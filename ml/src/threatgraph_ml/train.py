"""Train baseline URL-phishing models and write a reproducible report."""

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold

from .dataset import load_dataset
from .features import make_pipeline


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = ROOT / "artifacts"
REPORT_DIR = ROOT / "reports"
RANDOM_STATE = 42


def _domain_groups(frame: pd.DataFrame) -> np.ndarray:
    if "Domain" in frame:
        values = frame["Domain"].fillna("").astype(str).str.lower().str.rstrip(".")
    else:
        from urllib.parse import urlsplit
        values = frame["URL"].map(lambda value: urlsplit(
            str(value) if "://" in str(value) else "//" + str(value)
        ).hostname or "")
        values = values.astype(str).str.lower().str.rstrip(".")
    fallback = frame["URL"].astype(str).str.lower()
    return values.where(values.ne(""), fallback).to_numpy()


def _group_holdout(y: np.ndarray, groups: np.ndarray):
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    for train_idx, test_idx in splitter.split(np.zeros(len(y)), y, groups):
        if len(np.unique(y[train_idx])) == 2 and len(np.unique(y[test_idx])) == 2:
            return train_idx, test_idx
    raise RuntimeError("Could not produce a two-class domain-grouped holdout.")


def _metrics(y_true, scores):
    predicted = (scores >= 0.5).astype(int)
    top_count = max(1, int(np.ceil(len(scores) * 0.01)))
    top_indices = np.argsort(scores)[-top_count:]
    return {
        "average_precision": float(average_precision_score(y_true, scores)),
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "precision_at_0_5": float(precision_score(y_true, predicted, zero_division=0)),
        "recall_at_0_5": float(recall_score(y_true, predicted, zero_division=0)),
        "f1_at_0_5": float(f1_score(y_true, predicted, zero_division=0)),
        "precision_in_top_1_percent": float(np.mean(y_true[top_indices])),
        "test_positive_rate": float(np.mean(y_true)),
    }


def main():
    frame = load_dataset()
    y = frame["is_phishing"].to_numpy(dtype=np.int32)
    groups = _domain_groups(frame)
    train_idx, test_idx = _group_holdout(y, groups)

    # A one-dimensional string array is accepted by both the lexical
    # transformer and TfidfVectorizer branches of the FeatureUnion.
    X = frame["URL"].to_numpy()
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, include_char_ngrams in (
        ("lexical_logistic", False),
        ("lexical_plus_char_ngrams_logistic", True),
    ):
        model = make_pipeline(include_char_ngrams=include_char_ngrams)
        model.fit(X_train, y_train)
        scores = model.predict_proba(X_test)[:, 1]
        results[name] = _metrics(y_test, scores)
        results[name]["n_features"] = int(model.named_steps["nonconstant"].get_support().sum())
        print(f"{name}: {json.dumps(results[name], sort_keys=True)}")

        if name == "lexical_plus_char_ngrams_logistic":
            joblib.dump(model, ARTIFACT_DIR / "phiusiil_url_phishing.joblib")

    manifest = {
        "task": "generic_url_phishing_classification",
        "not_brand_impersonation": True,
        "dataset": "UCI PhiUSIIL Phishing URL (Website), repository id 967",
        "dataset_url": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
        "dataset_doi": "10.1016/j.cose.2023.103545",
        "dataset_license": "CC BY 4.0",
        "label_mapping": {"UCI 0": "phishing (internal 1)", "UCI 1": "legitimate (internal 0)"},
        "split": "StratifiedGroupKFold first valid fold; grouped on Domain where available",
        "split_note": "No temporal split: the source dataset does not provide suitable observation timestamps.",
        "n_rows": int(len(frame)),
        "n_train": int(len(train_idx)),
        "n_test": int(len(test_idx)),
        "n_train_groups": int(len(set(groups[train_idx]))),
        "n_test_groups": int(len(set(groups[test_idx]))),
        "train_positive_rate": float(np.mean(y_train)),
        "test_positive_rate": float(np.mean(y_test)),
        "random_state": RANDOM_STATE,
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "models": results,
    }
    with (REPORT_DIR / "phiusiil_metrics.json").open("w") as handle:
        json.dump(manifest, handle, indent=2)
    print(f"Saved model to {ARTIFACT_DIR / 'phiusiil_url_phishing.joblib'}")
    print(f"Saved report to {REPORT_DIR / 'phiusiil_metrics.json'}")


if __name__ == "__main__":
    main()
