"""Inference utilities for domain–brand impersonation models."""

from pathlib import Path

import joblib
import pandas as pd

from .brand_features import extract_brand_features


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


def score_brand_pair(
    candidate_url,
    brand_name,
    brand_domain,
    model_bundle=None,
    model_path: Path = BRAND_PAIR_MODEL_PATH,
    explanation_limit=5,
):
    """Score one candidate–brand pair and return model-relative signals.

    The numeric score is an uncalibrated benchmark output. Contributions show
    how the logistic model combined its features; they are not proof that a
    domain is malicious.
    """
    if explanation_limit < 0:
        raise ValueError("explanation_limit must be zero or greater.")
    bundle = model_bundle if model_bundle is not None else load_brand_pair_model(model_path)
    model = bundle["model"]
    feature_names = bundle["feature_names"]
    values = extract_brand_features(candidate_url, brand_name, brand_domain)
    unknown_features = set(feature_names).difference(values)
    if unknown_features:
        raise ValueError(f"Scoring feature extractor is missing: {sorted(unknown_features)}")

    features = pd.DataFrame([[values[name] for name in feature_names]], columns=feature_names)
    score = float(model.predict_proba(features)[0, 1])
    explanations = []
    steps = getattr(model, "steps", [])
    estimator = steps[-1][1] if steps else None
    if estimator is not None and hasattr(estimator, "coef_") and len(estimator.coef_) == 1:
        transformed = model[:-1].transform(features)[0]
        contributions = transformed * estimator.coef_[0]
        ranked = sorted(
            zip(feature_names, (values[name] for name in feature_names), contributions),
            key=lambda item: abs(float(item[2])),
            reverse=True,
        )[:explanation_limit]
        explanations = [
            {
                "feature": name,
                "value": float(value),
                "log_odds_contribution": float(contribution),
                "direction": "raises score" if contribution > 0 else "lowers score",
            }
            for name, value, contribution in ranked
        ]

    return {
        "candidate_url": str(candidate_url),
        "brand_name": str(brand_name),
        "brand_domain": str(brand_domain),
        "impersonation_score": score,
        "score_semantics": "Uncalibrated exploratory model score; use for research and prioritization only.",
        "feature_contributions": explanations,
        "explanation_semantics": "Model feature contributions are not proof of malicious intent.",
    }
