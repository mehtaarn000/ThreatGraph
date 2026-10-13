"""Compare lexical, DNS, and combined phishing models on one audited holdout."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

import joblib
import lightgbm
import numpy as np
import pandas as pd
import sklearn
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_curve, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .dns_features import SCHEMA_VERSION, extract_dns_features, from_domainradar, normalize_domain, registrable_domain
from .metrics import precision_at_budget

ROOT = Path(__file__).resolve().parents[2]
SEED = 42


def date_value(value):
    if isinstance(value, dict):
        value = value.get("$date")
    if value is None:
        return pd.NaT
    return pd.to_datetime(value, utc=True, errors="coerce")


def training_table(sample_path):
    records, rejected = [], Counter()
    with Path(sample_path).open() as handle:
        for line in handle:
            row = json.loads(line)
            try:
                domain = normalize_domain(row["domain_name"])
                features = extract_dns_features(domain, from_domainradar(row))
                timestamp = date_value((row.get("remarks") or {}).get("dns_evaluated_on"))
                timestamp_kind = "dns_evaluated_on"
                if pd.isna(timestamp):
                    timestamp, timestamp_kind = date_value(row.get("evaluated_on")), "evaluated_on_fallback"
                if pd.isna(timestamp):
                    rejected["missing_timestamp"] += 1
                    continue
                if row["target"] not in (0, 1):
                    raise ValueError("Invalid target")
                records.append({
                    "domain": domain, "group": registrable_domain(domain),
                    "observed_at": timestamp, "timestamp_kind": timestamp_kind,
                    "source_file": row["source_file"], "source": row.get("source", ""),
                    "source_record_id": row["source_record_id"], "target": row["target"], **features,
                })
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                rejected[f"invalid_record:{type(exc).__name__}"] += 1
    if not records:
        raise ValueError("No valid training records")
    frame = pd.DataFrame(records)
    conflicts = frame.groupby("domain")["target"].nunique()
    conflicts = set(conflicts[conflicts > 1].index)
    rejected["conflicting_label_rows"] = int(frame["domain"].isin(conflicts).sum())
    frame = frame.loc[~frame["domain"].isin(conflicts)]
    before = len(frame)
    # One earliest observed example per host, independent of model outcome.
    frame = frame.sort_values(["observed_at", "source_file", "source_record_id"]).drop_duplicates("domain")
    rejected["duplicate_host_rows"] = before - len(frame)
    return frame.reset_index(drop=True), dict(rejected)


def make_split(frame, min_class_count=30):
    times = frame["observed_at"]
    train_cut, val_cut = times.quantile([.6, .8]).tolist()
    group_max = frame.groupby("group")["observed_at"].max()
    last = frame["group"].map(group_max)
    temporal = {
        "train": np.flatnonzero((last <= train_cut).to_numpy()),
        "validation": np.flatnonzero(((last > train_cut) & (last <= val_cut) & (times > train_cut)).to_numpy()),
        "test": np.flatnonzero(((last > val_cut) & (times > val_cut)).to_numpy()),
    }
    def usable(indices):
        return all((frame.iloc[index]["target"].value_counts().reindex([0, 1], fill_value=0) >= min_class_count).all()
                   for index in indices.values())
    temporal_counts = {name: frame.iloc[index]["target"].value_counts().to_dict()
                       for name, index in temporal.items()}
    if usable(temporal):
        split = temporal
        strategy = "chronological_60_20_20_with_registrable_domain_purge"
        reason = None
    else:
        # Predeclared fallback; no search across seeds to improve scores.
        splitter = GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED)
        development, test = next(splitter.split(frame, groups=frame["group"]))
        inner = GroupShuffleSplit(n_splits=1, test_size=.25, random_state=SEED)
        train, validation = next(inner.split(frame.iloc[development], groups=frame.iloc[development]["group"]))
        split = {"train": development[train], "validation": development[validation], "test": test}
        strategy = "registrable_domain_grouped_60_20_20"
        reason = f"Predeclared temporal split lacks at least {min_class_count} examples of each class in every partition."
        if not usable(split):
            raise ValueError("Insufficient classes for the fixed grouped split; increase the sample")
    groups = {name: set(frame.iloc[index]["group"]) for name, index in split.items()}
    if groups["train"] & groups["validation"] or groups["train"] & groups["test"] or groups["validation"] & groups["test"]:
        raise AssertionError("Group leakage")
    audit = {
        "strategy": strategy, "temporal_fallback_reason": reason,
        "attempted_temporal_counts": temporal_counts,
        "temporal_cutoffs": [train_cut.isoformat(), val_cut.isoformat()],
        "purged_rows": len(frame) - sum(len(index) for index in split.values()),
        "partitions": {},
    }
    for name, index in split.items():
        part = frame.iloc[index]
        audit["partitions"][name] = {
            "rows": len(part), "groups": len(groups[name]), "positive_rate": float(part.target.mean()),
            "class_counts": {str(k): int(v) for k, v in part.target.value_counts().items()},
            "source_file_counts": part.source_file.value_counts().to_dict(),
            "first_scan": part.observed_at.min().isoformat(), "last_scan": part.observed_at.max().isoformat(),
        }
    return split, audit


def evaluate(y, scores, threshold=.5):
    budget = max(1, int(np.ceil(len(y) * .01)))
    return {
        "average_precision": float(average_precision_score(y, scores)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "precision": float(precision_score(y, scores >= threshold, zero_division=0)),
        "recall": float(recall_score(y, scores >= threshold, zero_division=0)),
        "threshold": float(threshold), "alert_budget": budget,
        "precision_at_top_1_percent": precision_at_budget(y, scores, budget),
        "alert_count": int((scores >= threshold).sum()),
    }


def choose_threshold(y, scores, target_precision=.9):
    precision, recall, thresholds = precision_recall_curve(y, scores)
    eligible = [i for i in range(len(thresholds))
                if precision[i] >= target_precision and int((scores >= thresholds[i]).sum()) >= 20]
    if not eligible:
        return .5, "Validation could not support 90% precision with at least 20 alerts; retained 0.5."
    best = max(eligible, key=lambda index: recall[index])
    return float(thresholds[best]), "Threshold chosen on validation for maximum recall at >=90% precision and >=20 alerts."


def paired_ap_interval(y, original, augmented, groups, repetitions=200):
    _, group_index = np.unique(groups, return_inverse=True)
    count = int(group_index.max()) + 1
    rng, deltas = np.random.default_rng(SEED), []
    for _ in range(repetitions):
        weights = rng.multinomial(count, np.full(count, 1 / count))[group_index]
        if not all(weights[y == label].sum() > 0 for label in (0, 1)):
            continue
        deltas.append(average_precision_score(y, augmented, sample_weight=weights) -
                      average_precision_score(y, original, sample_weight=weights))
    return {
        "combined_minus_lexical": float(average_precision_score(y, augmented) - average_precision_score(y, original)),
        "group_bootstrap_95_percent_interval": np.quantile(deltas, [.025, .975]).tolist(),
        "repetitions": len(deltas),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-dir", type=Path, default=ROOT / "data/raw/domainradar")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/domainradar")
    parser.add_argument("--report-dir", type=Path, default=ROOT / "reports")
    args = parser.parse_args()
    manifest = json.loads((args.sample_dir / "manifest.json").read_text())
    sample_path = args.sample_dir / "sample.jsonl"
    if hashlib.sha256(sample_path.read_bytes()).hexdigest() != manifest["sample_sha256"]:
        raise ValueError("Sample checksum differs from its acquisition manifest")
    frame, rejected = training_table(sample_path)
    split, split_audit = make_split(frame)
    columns = [column for column in frame if column.startswith(("lex_", "dns_"))]
    variants = {"lexical": [c for c in columns if c.startswith("lex_")],
                "dns": [c for c in columns if c.startswith("dns_")], "combined": columns}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    train, validation, test = (split[name] for name in ("train", "validation", "test"))
    y = frame.target.to_numpy()
    reports, scores_by_model, candidates = {}, {}, {}
    for family in ("logistic", "lightgbm"):
        for variant, names in variants.items():
            if family == "logistic":
                model = make_pipeline(SimpleImputer(strategy="median", keep_empty_features=True),
                                      StandardScaler(),
                                      LogisticRegression(class_weight="balanced", max_iter=2000, random_state=SEED))
            else:
                model = lightgbm.LGBMClassifier(
                    n_estimators=200, num_leaves=15, learning_rate=.05, min_child_samples=30,
                    reg_lambda=1, class_weight="balanced", n_jobs=2, random_state=SEED,
                    deterministic=True, force_col_wise=True, verbosity=-1,
                )
            model.fit(frame.iloc[train][names], y[train])
            validation_scores = model.predict_proba(frame.iloc[validation][names])[:, 1]
            threshold, threshold_note = choose_threshold(y[validation], validation_scores)
            name = f"{family}_{variant}"
            candidates[name] = (model, names, threshold)
            reports[name] = {
                "feature_count": len(names), "features": names,
                "validation": evaluate(y[validation], validation_scores),
                "selected_threshold": threshold, "threshold_note": threshold_note,
            }
            print(f"Fitted {name}: validation AP={reports[name]['validation']['average_precision']:.4f}", flush=True)
    # Select once on validation, before inspecting test predictions.
    selected = max(reports, key=lambda name: reports[name]["validation"]["average_precision"])
    predictions = frame.iloc[test][["domain", "group", "target", "source_file", "observed_at"]].copy()
    for name, (model, names, threshold) in candidates.items():
        scores = model.predict_proba(frame.iloc[test][names])[:, 1]
        scores_by_model[name] = scores
        reports[name]["test_at_0_5"] = evaluate(y[test], scores)
        reports[name]["test_at_validation_threshold"] = evaluate(y[test], scores, threshold)
        reports[name]["test_by_source_file"] = {}
        for source, indices in frame.iloc[test].groupby("source_file").indices.items():
            labels, source_scores = y[test][indices], scores[indices]
            reports[name]["test_by_source_file"][source] = {
                "rows": len(indices), "positive_rate": float(labels.mean()),
                "flagged_fraction_at_validation_threshold": float((source_scores >= threshold).mean()),
            }
        bundle = {"model": model, "feature_names": names, "schema_version": SCHEMA_VERSION,
                  "task": "generic_domain_phishing", "threshold": threshold,
                  "sample_sha256": manifest["sample_sha256"], "model_name": name,
                  "score_semantics": "Uncalibrated historical research score; not a brand-impersonation probability."}
        joblib.dump(bundle, args.output_dir / f"{name}.joblib")
        if name == selected:
            joblib.dump(bundle, args.output_dir / "selected.joblib")
        predictions[name] = scores
    assignments = frame[["domain", "group", "target", "source_file", "observed_at"]].copy()
    assignments["partition"] = "purged"
    for name, index in split.items():
        assignments.loc[index, "partition"] = name
    assignments.to_csv(args.report_dir / "domainradar_splits.csv", index=False)
    predictions.to_csv(args.report_dir / "domainradar_predictions.csv", index=False)
    source_audit = {}
    for source, part in frame.groupby("source_file"):
        source_audit[source] = {"rows": len(part), "first_scan": part.observed_at.min().isoformat(),
                               "last_scan": part.observed_at.max().isoformat(),
                               "record_missing_rates": part[[c for c in columns if c.endswith("_missing")]].mean().to_dict()}
    report = {
        "dataset": manifest["dataset"], "license": manifest["license"],
        "sampling": manifest["sampling"], "sample_sha256": manifest["sample_sha256"],
        "downloaded_bytes": manifest["downloaded_bytes"], "raw_sample_counts": manifest["counts"],
        "usable_rows": len(frame), "rejected": rejected, "source_audit": source_audit,
        "timestamp_sources": frame.timestamp_kind.value_counts().to_dict(),
        "split": split_audit, "models": reports, "selected_on_validation": selected,
        "dns_added_value": {
            family: paired_ap_interval(y[test], scores_by_model[f"{family}_lexical"],
                                       scores_by_model[f"{family}_combined"], frame.iloc[test].group.to_numpy())
            for family in ("logistic", "lightgbm")
        },
        "limitations": [
            "Approximate byte-window sample, not a validated uniform sample of domains.",
            "Historical source-derived labels, not brand-impersonation or campaign labels.",
            "Publisher collection/null semantics differ from live recursive DNS resolution.",
            "Source and collection-time artifacts can inflate performance; this is not a production accuracy estimate.",
            "No calibration; thresholds optimized on validation only.",
            "Shared infrastructure or campaigns may cross registrable-domain groups.",
            "This evaluation does not measure the existing brand-pair model; its metrics are not directly comparable.",
            "Source composition differs across temporal partitions; inspect per-partition source counts. No independent held-out feed was evaluated.",
            "Validation has limited positive examples; threshold selection and model ranking can be unstable.",
            "Malformed domains or DNS values cause whole records to be quarantined, potentially biasing this sample.",
            "Unknown-DNS missingness indicators have no variation in this sample; live timeouts are out of training support.",
        ],
        "runtime": {"python": platform.python_version(), "sklearn": sklearn.__version__,
                    "lightgbm": lightgbm.__version__, "seed": SEED},
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (args.report_dir / "domainradar_metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"selected": selected, "split": split_audit["strategy"],
                      "test": reports[selected]["test_at_0_5"], "dns_added_value": report["dns_added_value"]}, indent=2))


if __name__ == "__main__":
    main()
