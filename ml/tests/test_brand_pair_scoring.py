import numpy as np
import pandas as pd
import pytest
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ml.src.threatgraph_ml.brand_features import extract_brand_features
from ml.src.threatgraph_ml.brand_inference import score_brand_pair


def _model_bundle():
    pairs = [
        ("https://acme-login.example/secure", 1),
        ("http://acme-support.example/signin", 1),
        ("https://acme-verification.example", 1),
        ("https://acme.example/", 0),
        ("https://unrelated.example/", 0),
        ("http://other-site.test/home", 0),
    ]
    features = pd.DataFrame([
        extract_brand_features(url, "Acme", "https://acme.example")
        for url, _ in pairs
    ])
    labels = np.array([label for _, label in pairs])
    model = make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=2000, random_state=7),
    ).fit(features, labels)
    return {"model": model, "feature_names": list(features.columns)}


def test_score_brand_pair_returns_score_and_ranked_model_contributions():
    result = score_brand_pair(
        "https://acme-login.example/secure",
        "Acme",
        "https://acme.example",
        model_bundle=_model_bundle(),
        explanation_limit=4,
    )

    assert 0 <= result["impersonation_score"] <= 1
    assert result["candidate_url"] == "https://acme-login.example/secure"
    assert result["brand_name"] == "Acme"
    assert len(result["feature_contributions"]) == 4
    assert all("log_odds_contribution" in item for item in result["feature_contributions"])
    assert "not proof" in result["explanation_semantics"]


def test_score_brand_pair_can_omit_explanations_and_validates_limit():
    bundle = _model_bundle()
    result = score_brand_pair(
        "acme-login.example", "Acme", "acme.example",
        model_bundle=bundle, explanation_limit=0,
    )
    assert result["feature_contributions"] == []

    with pytest.raises(ValueError, match="zero or greater"):
        score_brand_pair(
            "acme-login.example", "Acme", "acme.example",
            model_bundle=bundle, explanation_limit=-1,
        )


def test_score_brand_pair_rejects_unavailable_training_features():
    bundle = _model_bundle()
    bundle["feature_names"] = ["missing_feature"]
    with pytest.raises(ValueError, match="feature extractor is missing"):
        score_brand_pair("acme-login.example", "Acme", "acme.example", model_bundle=bundle)
