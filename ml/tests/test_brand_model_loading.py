import joblib
import pytest

from ml.src.threatgraph_ml.brand_inference import load_brand_pair_model


def test_load_brand_pair_model_reports_missing_artifact(tmp_path):
    with pytest.raises(FileNotFoundError, match="train_brand_baseline"):
        load_brand_pair_model(tmp_path / "missing.joblib")


def test_load_brand_pair_model_rejects_invalid_artifact_bundle(tmp_path):
    path = tmp_path / "bad.joblib"
    joblib.dump({"model": object()}, path)

    with pytest.raises(ValueError, match="invalid format"):
        load_brand_pair_model(path)
