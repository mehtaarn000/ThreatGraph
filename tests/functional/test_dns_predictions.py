"""DNS protocol -> Go -> Python inference -> PostgreSQL, using isolated services."""
import hashlib
from concurrent.futures import ThreadPoolExecutor

import httpx


def predict(stack, domain="acme-review.test"):
    return stack.client.post(stack.api_url + f"/v1/domains/{domain}/dns/predictions")


def test_dns_prediction_roundtrip_provenance_and_restart(stack):
    response = predict(stack)
    assert response.status_code == 200, response.text
    prediction = response.json()
    snapshot = stack.get("/v1/domains/acme-review.test/dns").json()
    direct = stack.client.post(stack.model_url + "/v1/score/dns", json=snapshot)
    assert direct.status_code == 200, direct.text
    for key, value in direct.json().items():
        assert prediction[key] == value
    assert prediction["snapshot_id"] == snapshot["id"]
    assert prediction["observed_at"] == snapshot["observed_at"]
    assert prediction["model_version"] == hashlib.sha256(stack.dns_model.read_bytes()).hexdigest()
    assert prediction["experimental"] is True
    assert 0 <= prediction["generic_phishing_score"] <= 1
    assert "impersonation_score" not in prediction
    for name in ("api", "model", "postgres"):
        stack.stop(name)
    stack.start_postgres()
    stack.start_model()
    stack.start_api()
    assert stack.get("/v1/domains/ACME-REVIEW.TEST./dns/predictions").json()["predictions"] == [prediction]
    assert predict(stack).json() == prediction
    assert stack.sql("SELECT count(*) FROM dns_predictions") == "1"
    assert stack.sql("SELECT count(*) FROM analyses") == "0"


def test_concurrent_cached_predictions_do_not_duplicate_rows(stack):
    first = predict(stack)
    assert first.status_code == 200, first.text
    def request(_):
        return httpx.post(stack.api_url + "/v1/domains/acme-review.test/dns/predictions", timeout=15, trust_env=False)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(request, range(4)))
    assert all(response.status_code == 200 and response.json() == first.json() for response in responses)
    assert stack.sql("SELECT count(*) FROM dns_predictions") == "1"


def test_model_outage_preserves_dns_and_retry_recovers(stack, dns_fixture):
    stack.stop("model")
    response = predict(stack)
    assert response.status_code == 502, response.text
    assert stack.sql("SELECT count(*) FROM dns_observations") == "1"
    assert stack.sql("SELECT count(*) FROM dns_predictions") == "0"
    calls = dns_fixture.count("acme-review.test")
    stack.start_model()
    assert predict(stack).status_code == 200
    assert dns_fixture.count("acme-review.test") == calls
    assert stack.sql("SELECT count(*) FROM dns_predictions") == "1"


def test_failed_dns_is_not_scored_and_partial_dns_is_disclosed(stack):
    response = predict(stack, "timeout.test")
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "insufficient_dns"
    assert stack.sql("SELECT count(*) FROM dns_observations") == "1"
    assert stack.sql("SELECT count(*) FROM dns_predictions") == "0"
    partial = predict(stack, "partial.test")
    assert partial.status_code == 200, partial.text
    assert partial.json()["unknown_record_types"] == ["MX"]
    assert partial.json()["experimental"] is True


def test_prediction_storage_failure_is_reported_without_losing_dns(stack):
    stack.sql("REVOKE INSERT ON dns_predictions FROM threatgraph_app")
    # The app owns the table: explicit revoke of its own privilege tests a real DB failure.
    response = predict(stack)
    assert response.status_code == 500, response.text
    assert response.json()["error"]["code"] == "prediction_storage_error"
    assert stack.sql("SELECT count(*) FROM dns_observations") == "1"
    stack.sql("GRANT INSERT ON dns_predictions TO threatgraph_app")
    assert predict(stack).status_code == 200


def test_new_model_artifact_creates_separate_prediction(stack):
    import joblib
    original = predict(stack).json()
    stack.stop("model")
    bundle = joblib.load(stack.dns_model)
    bundle["model_name"] = "synthetic_dns_v2"
    new_path = stack.directory / "updated-model.joblib"
    joblib.dump(bundle, new_path)
    stack.dns_model = new_path
    stack.start_model()
    updated = predict(stack)
    assert updated.status_code == 200, updated.text
    assert updated.json()["snapshot_id"] == original["snapshot_id"]
    assert updated.json()["model_version"] != original["model_version"]
    assert updated.json()["id"] != original["id"]
    assert len(stack.get("/v1/domains/acme-review.test/dns/predictions").json()["predictions"]) == 2
