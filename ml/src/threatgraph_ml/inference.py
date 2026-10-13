"""Load the saved generic phishing model for application integration."""

from pathlib import Path

import joblib
import numpy as np


MODEL_PATH = Path(__file__).resolve().parents[2] / "artifacts" / "phiusiil_url_phishing.joblib"


def load_model(path: Path = MODEL_PATH):
    if not path.exists():
        raise FileNotFoundError(
            f"No trained model at {path}. Run `python -m ml.src.threatgraph_ml.train` first."
        )
    return joblib.load(path)


def score_urls(urls, model=None):
    """Return generic phishing scores, not brand-impersonation probabilities."""
    if model is None:
        model = load_model()
    values = np.asarray(list(urls), dtype=object)
    scores = model.predict_proba(values)[:, 1]
    return [
        {"url": str(url), "generic_phishing_score": float(score)}
        for url, score in zip(values, scores)
    ]
