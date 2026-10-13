from fastapi.testclient import TestClient

from ml.src.threatgraph_ml.scoring_api import create_app


def _app():
    return create_app(
        model_loader=lambda: {"model": object(), "feature_names": []},
        scorer=lambda candidate_url, brand_name, brand_domain, model_bundle: {
            "candidate_url": candidate_url,
            "brand_name": brand_name,
            "brand_domain": brand_domain,
            "impersonation_score": 0.76,
            "score_semantics": "research only",
            "feature_contributions": [],
            "explanation_semantics": "not proof",
        },
    )


def test_health_and_score_endpoints_share_the_go_service_contract():
    with TestClient(_app()) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}

        response = client.post("/v1/score", json={
            "candidate_url": "https://acme-login.example/sign-in",
            "brand_name": "Acme",
            "brand_domain": "acme.example",
        })
        assert response.status_code == 200
        assert response.json()["impersonation_score"] == 0.76
        assert response.json()["brand_name"] == "Acme"


def test_scoring_api_rejects_invalid_urls_and_unknown_fields():
    with TestClient(_app()) as client:
        invalid_url = client.post("/v1/score", json={
            "candidate_url": "file:///tmp/example",
            "brand_name": "Acme",
            "brand_domain": "acme.example",
        })
        assert invalid_url.status_code == 422

        unknown_field = client.post("/v1/score", json={
            "candidate_url": "https://acme-login.example",
            "brand_name": "Acme",
            "brand_domain": "acme.example",
            "fetch": True,
        })
        assert unknown_field.status_code == 422
