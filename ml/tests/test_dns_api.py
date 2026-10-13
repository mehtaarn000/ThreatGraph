import numpy as np
import pytest
from fastapi.testclient import TestClient

from ml.src.threatgraph_ml.scoring_api import create_app


class FixedModel:
    def predict_proba(self, frame):
        return np.array([[.2, .8]])


def snapshot():
    return {"id": "123e4567-e89b-12d3-a456-426614174000", "domain": "example.test",
            "observed_at": "2026-10-13T12:00:00.123456789Z", "queries": [
                {"type": kind, "status": "no_records", "records": []}
                for kind in ("A", "AAAA", "NS", "MX")]}


def app_with_loader(loader):
    return create_app(model_loader=lambda: {}, dns_model_loader=loader)


def bundle():
    return {"model": FixedModel(), "model_version": "a" * 64,
            "feature_names": ["dns_a_count"], "threshold": .5,
            "model_name": "test", "score_semantics": "Uncalibrated research score"}


def test_dns_endpoint_loads_once_preserves_timestamp_and_provenance(monkeypatch):
    monkeypatch.setenv("THREATGRAPH_DNS_MODEL_PATH", "fixture")
    calls = []
    def loader(path):
        calls.append(path)
        return bundle()
    with TestClient(app_with_loader(loader)) as client:
        assert client.get("/v1/dns/readyz").status_code == 200
        for _ in range(2):
            response = client.post("/v1/score/dns", json=snapshot())
            assert response.status_code == 200, response.text
            assert response.json()["observed_at"] == snapshot()["observed_at"]
            assert response.json()["snapshot_id"] == snapshot()["id"]
            assert response.json()["model_version"] == "a" * 64
            assert response.json()["experimental"] is True
            assert response.json()["generic_phishing_score"] == .8
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["duplicate", "ip", "mx", "status", "timestamp", "empty_ok"])
def test_invalid_dns_evidence_rejected(monkeypatch, mutation):
    monkeypatch.setenv("THREATGRAPH_DNS_MODEL_PATH", "fixture")
    payload = snapshot()
    if mutation == "duplicate": payload["queries"][1]["type"] = "A"
    if mutation == "ip": payload["queries"][0].update(status="ok", records=[{"value": "bad-ip"}])
    if mutation == "mx": payload["queries"][3].update(status="ok", records=[{"value": "mail.test"}])
    if mutation == "status": payload["queries"][0]["status"] = "surprise"
    if mutation == "timestamp": payload["observed_at"] = "2026-10-13T12:00:00"
    if mutation == "empty_ok": payload["queries"][0]["status"] = "ok"
    with TestClient(app_with_loader(lambda _: bundle())) as client:
        assert client.post("/v1/score/dns", json=payload).status_code == 422


def test_all_failed_queries_rejected_partial_failures_disclosed(monkeypatch):
    monkeypatch.setenv("THREATGRAPH_DNS_MODEL_PATH", "fixture")
    payload = snapshot()
    with TestClient(app_with_loader(lambda _: bundle())) as client:
        payload["queries"][3]["status"] = "timeout"
        assert client.post("/v1/score/dns", json=payload).json()["unknown_record_types"] == ["MX"]
        for query in payload["queries"]: query["status"] = "timeout"
        assert client.post("/v1/score/dns", json=payload).status_code == 422


def test_unconfigured_dns_model_returns_unavailable(monkeypatch):
    monkeypatch.delenv("THREATGRAPH_DNS_MODEL_PATH", raising=False)
    with TestClient(app_with_loader(lambda _: bundle())) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/v1/dns/readyz").status_code == 503
        assert client.post("/v1/score/dns", json=snapshot()).status_code == 503


def test_invalid_configured_artifact_fails_startup(monkeypatch):
    monkeypatch.setenv("THREATGRAPH_DNS_MODEL_PATH", "fixture")
    def broken(_): raise ValueError("bad artifact")
    with pytest.raises(RuntimeError, match="DNS model failed"):
        with TestClient(app_with_loader(broken)):
            pass


def test_broken_model_returns_500_not_invalid_input(monkeypatch):
    monkeypatch.setenv("THREATGRAPH_DNS_MODEL_PATH", "fixture")
    value = bundle()
    value["feature_names"] = ["nonexistent"]
    with TestClient(app_with_loader(lambda _: value)) as client:
        response = client.post("/v1/score/dns", json=snapshot())
        assert response.status_code == 500
        assert response.json()["detail"] == "DNS model scoring failed"
