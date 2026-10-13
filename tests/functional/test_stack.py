"""Real HTTP, model inference, and PostgreSQL; synthetic inputs only."""


def test_stack_starts_with_database_migration_and_ready_services(stack):
    assert stack.get("/healthz").json() == {"status": "ok"}
    assert stack.get("/readyz").json() == {"status": "ready"}
    assert stack.sql("SELECT count(*) FROM analyses") == "0"
    assert stack.sql("SELECT current_database()") == "threatgraph_stack"


def test_analysis_round_trip_matches_model_and_postgres(stack):
    import json
    from datetime import datetime
    from uuid import UUID

    ids = set()
    for brand in ("Acme", "Acme's Research"):
        response = stack.create(brand_name=brand)
        assert response.status_code == 201, response.text
        assert response.headers["cache-control"] == "no-store"
        created = response.json()
        identifier = str(UUID(created["id"]))
        assert identifier not in ids
        ids.add(identifier)
        assert datetime.fromisoformat(created["created_at"].replace("Z", "+00:00")).tzinfo is not None
        assert 0 <= created["result"]["impersonation_score"] <= 1
        assert len(created["result"]["feature_contributions"]) == 5
        payload = {key: created[key] for key in ("candidate_url", "brand_name", "brand_domain")}
        direct = stack.client.post(stack.model_url + "/v1/score", json=payload)
        assert direct.status_code == 200, direct.text
        assert created["result"] == direct.json()
        retrieved = stack.get("/v1/analyses/" + identifier)
        assert retrieved.status_code == 200, retrieved.text
        assert retrieved.json() == created
        stored = json.loads(stack.sql(
            f"SELECT json_build_object('candidate_url', candidate_url, 'brand_name', brand_name, "
            f"'brand_domain', brand_domain, 'result', result, 'score', impersonation_score) "
            f"FROM analyses WHERE id = '{identifier}'"
        ))
        assert {key: stored[key] for key in payload} == payload
        assert stored["result"] == created["result"]
        assert stored["score"] == created["result"]["impersonation_score"]
    assert stack.sql("SELECT count(*) FROM analyses") == "2"


def test_api_restart_preserves_records_and_reapplies_migration_safely(stack):
    response = stack.create()
    assert response.status_code == 201, response.text
    created = response.json()
    stack.stop("api")
    stack.start_api()
    retrieved = stack.get("/v1/analyses/" + created["id"])
    assert retrieved.status_code == 200, retrieved.text
    assert retrieved.json() == created
    assert stack.sql("SELECT count(*) FROM analyses") == "1"
    second = stack.create(candidate_url="https://second-acme.test")
    assert second.status_code == 201, second.text
    assert second.json()["id"] != created["id"]
    assert stack.sql("SELECT count(*) FROM analyses") == "2"


def test_all_services_restart_with_durable_data_and_loaded_model(stack):
    response = stack.create()
    assert response.status_code == 201, response.text
    created = response.json()
    for name in ("api", "model", "postgres"):
        stack.stop(name)
    stack.start_postgres()
    stack.start_model()
    stack.start_api()
    retrieved = stack.get("/v1/analyses/" + created["id"])
    assert retrieved.status_code == 200, retrieved.text
    assert retrieved.json() == created
    after_restart = stack.create()
    assert after_restart.status_code == 201, after_restart.text
    assert after_restart.json()["result"] == created["result"]
    assert after_restart.json()["id"] != created["id"]
    assert stack.sql("SELECT count(*) FROM analyses") == "2"


def test_model_outage_does_not_save_partial_analysis_and_recovers(stack):
    stack.stop("model")
    assert stack.get("/healthz").status_code == 200
    readiness = stack.get("/readyz")
    assert readiness.status_code == 503
    assert readiness.json()["error"]["code"] == "model_service_unavailable"
    response = stack.create()
    assert response.status_code == 502, response.text
    assert response.json()["error"]["code"] == "model_service_error"
    assert stack.sql("SELECT count(*) FROM analyses") == "0"
    stack.start_model()
    assert stack.get("/readyz").status_code == 200
    recovered = stack.create()
    assert recovered.status_code == 201, recovered.text
    assert stack.sql("SELECT count(*) FROM analyses") == "1"

