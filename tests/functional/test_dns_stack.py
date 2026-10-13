"""Real DNS protocol -> Go -> PostgreSQL, with no external network dependency."""

from datetime import datetime
import re


def parse_timestamp(value):
    # Python 3.9 accepts only 3/6 fractional digits; Go emits RFC3339Nano.
    normalized = re.sub(r"\.(\d+)(?=[+-])",
                        lambda match: "." + match[1].ljust(6, "0")[:6],
                        value.replace("Z", "+00:00"))
    return datetime.fromisoformat(normalized)


def enrich(stack, domain):
    response = stack.client.post(stack.api_url + f"/v1/domains/{domain}/dns")
    assert response.status_code == 200, response.text
    return response.json()


def test_dns_records_cache_history_and_restart(stack, dns_fixture):
    result = enrich(stack, "ACME-REVIEW.TEST.")
    assert result["cached"] is False
    snapshot = result["snapshot"]
    assert snapshot["domain"] == "acme-review.test"
    assert snapshot["resolver"] == dns_fixture.address
    queries = {q["type"]: q for q in snapshot["queries"]}
    assert set(queries) == {"A", "AAAA", "NS", "MX"}
    assert all(q["status"] == "ok" for q in queries.values())
    assert queries["A"]["records"] == [{"value": "192.0.2.10"}]
    assert queries["AAAA"]["records"] == [{"value": "2001:db8::10"}]
    assert queries["NS"]["records"] == [{"value": "ns1.fixture.test"}]
    assert queries["MX"]["records"] == [{"value": "mail.fixture.test", "preference": 10}]
    for query in queries.values():
        assert parse_timestamp(query["observed_at"]).tzinfo
    assert len(snapshot["relationships"]) == 4
    assert {edge["kind"] for edge in snapshot["relationships"]} == {
        "RESOLVES_TO", "USES_NAMESERVER", "MAIL_HANDLED_BY",
    }
    for edge in snapshot["relationships"]:
        assert edge["observed_at"] == queries[edge["record_type"]]["observed_at"]
    calls = dns_fixture.count("acme-review.test")
    assert calls >= 4
    assert enrich(stack, "acme-review.test") == {"snapshot": snapshot, "cached": True}
    stack.stop("api")
    stack.start_api()
    assert enrich(stack, "acme-review.test") == {"snapshot": snapshot, "cached": True}
    assert dns_fixture.count("acme-review.test") == calls
    latest = stack.get("/v1/domains/acme-review.test/dns")
    assert latest.status_code == 200
    assert latest.json() == snapshot
    history = stack.get("/v1/domains/acme-review.test/dns/history?limit=1")
    assert history.json()["observations"] == [snapshot]
    assert stack.sql("SELECT count(*) FROM dns_observations") == "1"
    assert stack.sql("SELECT count(*) FROM schema_migrations") == "2"


def test_expired_cache_appends_an_observation(stack, dns_fixture):
    first = enrich(stack, "acme-review.test")["snapshot"]
    calls = dns_fixture.count("acme-review.test")
    # Move this test-owned cached snapshot to its expiry boundary without sleeping.
    stack.sql("""UPDATE dns_observations SET expires_at = observed_at,
        payload = jsonb_set(payload, '{expires_at}', payload->'observed_at')""")
    result = enrich(stack, "acme-review.test")
    assert result["cached"] is False
    assert result["snapshot"]["id"] != first["id"]
    assert dns_fixture.count("acme-review.test") > calls
    history = stack.get("/v1/domains/acme-review.test/dns/history").json()["observations"]
    assert len(history) == 2
    assert history[0]["id"] == result["snapshot"]["id"]
    assert history[1]["id"] == first["id"]


def test_partial_timeout_keeps_successful_records_and_is_retried(stack, dns_fixture):
    first = enrich(stack, "partial.test")
    snapshot = first["snapshot"]
    queries = {q["type"]: q for q in snapshot["queries"]}
    assert queries["MX"]["status"] == "timeout"
    assert queries["MX"]["records"] == []
    assert all(queries[k]["status"] == "ok" for k in ("A", "AAAA", "NS"))
    assert snapshot["expires_at"] == snapshot["observed_at"]
    assert len(snapshot["relationships"]) == 3
    calls = dns_fixture.count("partial.test")
    second = enrich(stack, "partial.test")
    assert second["cached"] is False
    assert second["snapshot"]["id"] != snapshot["id"]
    assert dns_fixture.count("partial.test") > calls


def test_negative_answers_are_cached_and_null_mx_has_no_mail_edge(stack, dns_fixture):
    missing = enrich(stack, "missing.test")
    snapshot = missing["snapshot"]
    assert all(q["status"] == "not_found" for q in snapshot["queries"])
    assert snapshot["relationships"] == []
    observed = parse_timestamp(snapshot["observed_at"])
    expires = parse_timestamp(snapshot["expires_at"])
    assert (expires - observed).total_seconds() == 30
    calls = dns_fixture.count("missing.test")
    assert enrich(stack, "missing.test")["cached"] is True
    assert dns_fixture.count("missing.test") == calls
    null_mail = enrich(stack, "null-mail.test")["snapshot"]
    mx = next(q for q in null_mail["queries"] if q["type"] == "MX")
    assert mx["records"] == [{"value": ".", "preference": 0}]
    assert all(edge["kind"] != "MAIL_HANDLED_BY" for edge in null_mail["relationships"])


def test_existing_analysis_can_be_enriched_and_invalid_domains_do_not_query(stack, dns_fixture):
    created = stack.create().json()
    response = stack.client.post(stack.api_url + f"/v1/analyses/{created['id']}/dns")
    assert response.status_code == 200, response.text
    assert response.json()["snapshot"]["domain"] == "acme-review.test"
    assert stack.get("/v1/analyses/" + created["id"]).json() == created
    for domain in ("127.0.0.1", "localhost", "bad..test"):
        response = stack.client.post(stack.api_url + f"/v1/domains/{domain}/dns")
        assert response.status_code == 422
        assert dns_fixture.count(domain) == 0
    assert stack.get("/v1/domains/unknown.test/dns").status_code == 404
    assert stack.get("/v1/domains/acme-review.test/dns/history?limit=101").status_code == 400
    assert stack.sql("SELECT count(*) FROM dns_observations") == "1"


def test_migration_upgrades_legacy_database_without_losing_analyses(stack):
    response = stack.create()
    assert response.status_code == 201
    original = response.json()
    stack.stop("api")
    stack.sql("DROP TABLE dns_observations; DROP TABLE schema_migrations")
    stack.start_api()
    assert stack.get("/v1/analyses/" + original["id"]).json() == original
    assert stack.sql("SELECT count(*) FROM schema_migrations") == "2"
    assert enrich(stack, "acme-review.test")["snapshot"]["id"]
