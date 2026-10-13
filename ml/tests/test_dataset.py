import pandas as pd
import pytest

from ml.src.threatgraph_ml import dataset


@pytest.mark.parametrize("label", [0.5, 1.9, -0.5])
def test_rejects_fractional_labels_before_integer_conversion(tmp_path, monkeypatch, label):
    path = tmp_path / "cached.csv"
    pd.DataFrame({"URL": ["https://example.test"], "label": [label]}).to_csv(path, index=False)
    monkeypatch.setattr(dataset, "RAW_CSV", path)
    with pytest.raises(ValueError, match="Unexpected UCI labels"):
        dataset.load_dataset()
