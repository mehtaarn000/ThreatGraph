import json

import pandas as pd

from ml.src.threatgraph_ml.zenodo_brand_data import load_brand_pairs


def _write_csv(path, rows):
    pd.DataFrame(rows).to_csv(path, index=False)


def test_load_brand_pairs_preserves_target_brand_and_weak_negative_provenance(tmp_path):
    brands = tmp_path / "brands.csv"
    phishing = tmp_path / "phishing.csv"
    benign = tmp_path / "not-phishing.csv"
    _write_csv(brands, [{"identifier": "acme", "name": "Acme", "website": "https://acme.example"}])
    _write_csv(phishing, [{
        "_id": "p-1", "domain": "login-acme.test", "url": "https://login-acme.test/signin",
        "brands": json.dumps(["acme"]), "scan_date": "2023-03-01T00:00:00Z",
    }])
    _write_csv(benign, [{
        "_id": "n-1", "domain": "ordinary.example", "url": "https://ordinary.example/",
        "scan_date": "2023-03-02T00:00:00Z",
    }])

    pairs = load_brand_pairs(phishing, benign, brands)

    assert pairs["target"].tolist() == [1, 0]
    positive, negative = pairs.to_dict("records")
    assert positive["brand_id"] == negative["brand_id"] == "acme"
    assert positive["label_quality"] == "source_labeled_positive"
    assert negative["label_quality"] == "weak_benign_proxy"
    assert negative["label_source"].startswith("Zenodo non-phishing pool")


def test_load_brand_pairs_rejects_invalid_brand_json(tmp_path):
    brands = tmp_path / "brands.csv"
    phishing = tmp_path / "phishing.csv"
    benign = tmp_path / "not-phishing.csv"
    _write_csv(brands, [{"identifier": "acme", "name": "Acme", "website": "https://acme.example"}])
    _write_csv(phishing, [{
        "_id": "p-1", "domain": "login-acme.test", "url": "", "brands": "not-json", "scan_date": "",
    }])
    _write_csv(benign, [{"_id": "n-1", "domain": "ordinary.example", "url": "", "scan_date": ""}])

    try:
        load_brand_pairs(phishing, benign, brands)
    except ValueError as exc:
        assert "Invalid brand list" in str(exc)
    else:
        raise AssertionError("invalid JSON should fail with a useful data error")
