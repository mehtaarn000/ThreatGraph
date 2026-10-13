"""Train an exploratory brand-pair baseline from the Zenodo public dataset."""

import json
import hashlib
import platform
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .brand_features import NEW_FEATURE_NAMES, extract_brand_features
from .metrics import precision_at_budget
from .zenodo_brand_data import download_dataset, load_brand_pairs


ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "data" / "raw" / "zenodo_brand"
ARTIFACT_DIR = ROOT / "artifacts"
REPORT_DIR = ROOT / "reports"
RANDOM_STATE = 42


def _score_metrics(y_true, scores):
    alert_count = max(1, int(np.ceil(len(scores) * 0.01)))
    return {
        "average_precision": float(average_precision_score(y_true, scores)),
        "precision_at_top_1_percent": precision_at_budget(y_true, scores, alert_count),
        "precision_at_0_5": float(precision_score(y_true, scores >= 0.5, zero_division=0)),
        "recall_at_0_5": float(recall_score(y_true, scores >= 0.5, zero_division=0)),
    }


def main():
    files = download_dataset(RAW_DIR)
    pairs = load_brand_pairs(files["phishing.csv"], files["not-phishing.csv"], files["brands.csv"])
    feature_rows = [
        extract_brand_features(row.candidate_url, row.brand_name, row.brand_domain)
        for row in pairs.itertuples(index=False)
    ]
    X = pd.DataFrame.from_records(feature_rows)
    y = pairs["target"].to_numpy(dtype=np.int32)
    groups = pairs["candidate_domain"].to_numpy()
    splitter = GroupShuffleSplit(n_splits=30, test_size=0.2, random_state=RANDOM_STATE)
    train_idx = test_idx = None
    for candidate_train, candidate_test in splitter.split(X, y, groups):
        if len(np.unique(y[candidate_train])) == 2 and len(np.unique(y[candidate_test])) == 2:
            train_idx, test_idx = candidate_train, candidate_test
            break
    if train_idx is None:
        raise RuntimeError("Could not find a domain-grouped split containing both classes.")

    # All variants use exactly the same records, holdout, and model settings.
    original = [name for name in X.columns if name not in NEW_FEATURE_NAMES]
    variants = {
        "original_20": original,
        "with_entropy": original + [NEW_FEATURE_NAMES[0]],
        "with_domain_similarity": original + list(NEW_FEATURE_NAMES[1:]),
        "combined_23": original + list(NEW_FEATURE_NAMES),
    }
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    comparisons = {}
    for name, columns in variants.items():
        model = make_pipeline(
            SimpleImputer(strategy="median"),
            StandardScaler(),
            LogisticRegression(class_weight="balanced", max_iter=2000, random_state=RANDOM_STATE),
        )
        model.fit(X.iloc[train_idx][columns], y[train_idx])
        scores = model.predict_proba(X.iloc[test_idx][columns])[:, 1]
        comparisons[name] = _score_metrics(y[test_idx], scores)
        joblib.dump(
            {"model": model, "feature_names": columns, "feature_schema_version": 2},
            ARTIFACT_DIR / f"zenodo_brand_pair_{name}.joblib",
        )
        if name == "original_20":
            # Preserve the existing training command and serving artifact contract.
            joblib.dump(
                {"model": model, "feature_names": columns},
                ARTIFACT_DIR / "zenodo_brand_pair_baseline.joblib",
            )
    metrics = dict(comparisons["original_20"])
    rule_scores = X.iloc[test_idx]["brand_token_present"].to_numpy(dtype=float)
    metrics["brand_token_rule_baseline"] = _score_metrics(y[test_idx], rule_scores)

    manifest = {
        "task": "exploratory_brand_impersonation_pair_classification",
        "dataset": "Zenodo Phishing Website Dataset, record 8041387",
        "dataset_url": "https://zenodo.org/records/8041387",
        "dataset_doi": "10.5281/zenodo.8041387",
        "dataset_license": "CC BY 4.0",
        "label_caveat": "Phishing rows use the source-declared target brand. Negative pairs are sampled from a non-phishing pool with no brand field; they are weak proxies, not reviewed domain-brand labels.",
        "split": "80/20 GroupShuffleSplit grouped by candidate domain; dataset is historical (2023), not a temporal holdout.",
        "n_pairs": int(len(pairs)),
        "n_positive": int(y.sum()),
        "n_weak_negative": int((y == 0).sum()),
        "n_train": int(len(train_idx)),
        "n_test": int(len(test_idx)),
        "n_train_domains": int(len(set(groups[train_idx]))),
        "n_test_domains": int(len(set(groups[test_idx]))),
        "random_state": RANDOM_STATE,
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "feature_comparison": comparisons,
        "feature_sets": variants,
        "evaluation_note": "Exploratory fixed holdout comparison, not an independent final test or evidence of calibrated production accuracy. No automatic model promotion.",
        "test_indices_sha256": hashlib.sha256(test_idx.astype("<i8").tobytes()).hexdigest(),
        "dataset_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()
        },
    }
    with (REPORT_DIR / "zenodo_brand_pair_metrics.json").open("w") as handle:
        json.dump(manifest, handle, indent=2)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
