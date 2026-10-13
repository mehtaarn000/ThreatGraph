"""Functional coverage using a real, locally trained model and temporary artifact.

Synthetic labels test plumbing, not classifier accuracy. No feeds or sites are fetched.
"""

import joblib
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ml.src.threatgraph_ml.brand_dataset import build_training_table, load_reviewed_labels
from ml.src.threatgraph_ml.brand_inference import load_brand_pair_model, score_brand_pair
from ml.src.threatgraph_ml.scoring_api import create_app


@pytest.fixture
def trained_artifact(tmp_path):
    rows = []
    for index, (domain, label) in enumerate([
        ("acme-login.test", "confirmed_impersonation"),
        ("acme-verify.test", "confirmed_impersonation"),
        ("secure-acme.test", "confirmed_impersonation"),
        ("acme.example", "confirmed_not_impersonation"),
        ("weather.example", "confirmed_not_impersonation"),
        ("library.example", "confirmed_not_impersonation"),
        ("unknown.example", "unknown"),
    ]):
        rows.append({
            "example_id": str(index), "candidate_url": "https://" + domain,
            "candidate_domain": domain, "brand_id": "acme", "brand_name": "Acme",
            "brand_domain": "acme.example", "label": label, "source_name": "synthetic",
            "observed_at": "2026-01-01T00:00:00Z", "reviewed_at": "2026-01-02T00:00:00Z",
            "reviewer_id": "test-fixture", "evidence_refs": "synthetic-case",
        })
    labels_path = tmp_path / "labels.csv"
    pd.DataFrame(rows).to_csv(labels_path, index=False)
    table = build_training_table(load_reviewed_labels(labels_path))
    assert len(table) == 6  # Unknown judgments must not become negatives.
    metadata = ["example_id", "candidate_domain", "brand_id", "campaign_id", "observed_at", "target"]
    features = table.drop(columns=metadata)
    model = make_pipeline(
        SimpleImputer(strategy="median"), StandardScaler(),
        LogisticRegression(random_state=42, max_iter=1000),
    ).fit(features, table["target"])
    path = tmp_path / "model.joblib"
    joblib.dump({"model": model, "feature_names": list(features.columns)}, path)
    return path


def test_functional_labels_to_artifact_to_http_predictions(trained_artifact, monkeypatch):
    monkeypatch.setenv("THREATGRAPH_BRAND_MODEL_PATH", str(trained_artifact))
    bundle = load_brand_pair_model(trained_artifact)
    payload = {
        "candidate_url": "https://acme-review.test/login",
        "brand_name": "Acme", "brand_domain": "acme.example",
    }
    expected = score_brand_pair(**payload, model_bundle=bundle)
    with TestClient(create_app()) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        # Removing the file proves subsequent requests use the startup-loaded model.
        trained_artifact.unlink()
        for _ in range(2):
            response = client.post("/v1/score", json=payload)
            assert response.status_code == 200
            result = response.json()
            assert result == expected
            assert 0 <= result["impersonation_score"] <= 1
            assert len(result["feature_contributions"]) == 5
            assert "Uncalibrated" in result["score_semantics"]
        invalid = client.post("/v1/score", json={**payload, "brand_name": " "})
        assert invalid.status_code == 422
        assert client.post("/v1/score", json=payload).status_code == 200

