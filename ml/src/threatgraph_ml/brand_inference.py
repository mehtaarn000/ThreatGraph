"""Inference utilities for domain–brand impersonation models."""

from pathlib import Path

import joblib


BRAND_PAIR_MODEL_PATH = (
    Path(__file__).resolve().parents[2] / "artifacts" / "zenodo_brand_pair_baseline.joblib"
)


def load_brand_pair_model(path: Path = BRAND_PAIR_MODEL_PATH):
    """Load the exploratory domain–brand model artifact bundle."""
    if not path.exists():
        raise FileNotFoundError(
            f"No trained brand-pair model at {path}. "
            "Run `python -m ml.src.threatgraph_ml.train_brand_baseline` first."
        )
    bundle = joblib.load(path)
    if not isinstance(bundle, dict) or not {"model", "feature_names"}.issubset(bundle):
        raise ValueError(f"Brand-pair model artifact at {path} has an invalid format.")
    return bundle
