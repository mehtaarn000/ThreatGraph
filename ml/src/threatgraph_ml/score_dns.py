"""Offline scoring of the Go enrichment API's DNS snapshots.

Load only locally trained, trusted joblib artifacts: pickle can execute code.
This scorer is separate from the existing brand-pair classifier.
"""
import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from .dns_features import SCHEMA_VERSION, extract_dns_features, from_snapshot, normalize_domain

DEFAULT_MODEL = Path(__file__).resolve().parents[2] / "artifacts/domainradar/selected.joblib"


def load_model(path=DEFAULT_MODEL):
    bundle = joblib.load(path)
    if bundle.get("schema_version") != SCHEMA_VERSION or bundle.get("task") != "generic_domain_phishing":
        raise ValueError("Incompatible DNS model artifact")
    return bundle


def score_snapshot(bundle, response):
    snapshot = response.get("snapshot", response)
    domain = normalize_domain(snapshot["domain"])
    features = extract_dns_features(domain, from_snapshot(snapshot))
    names = bundle["feature_names"]
    if not names or len(set(names)) != len(names) or any(name not in features for name in names):
        raise ValueError("Artifact feature schema does not match the DNS extractor")
    frame = pd.DataFrame([[features[name] for name in names]], columns=names)
    score = float(bundle["model"].predict_proba(frame)[0, 1])
    return {
        "domain": domain, "observed_at": snapshot.get("observed_at"),
        "generic_phishing_score": score, "threshold": bundle["threshold"],
        "flagged": score >= bundle["threshold"], "model": bundle["model_name"],
        "score_semantics": bundle["score_semantics"],
        "unknown_record_types": [kind for kind in ("A", "AAAA", "NS", "MX")
                                 if features[f"dns_{kind.lower()}_missing"]],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path, help="Saved DNS API response or unwrapped snapshot JSON")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    args = parser.parse_args()
    print(json.dumps(score_snapshot(load_model(args.model), json.loads(args.snapshot.read_text())), indent=2))


if __name__ == "__main__":
    main()
