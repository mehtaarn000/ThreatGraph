"""Real HTTP, model inference, and PostgreSQL; synthetic inputs only."""


def test_stack_starts_with_database_migration_and_ready_services(stack):
    assert stack.get("/healthz").json() == {"status": "ok"}
    assert stack.get("/readyz").json() == {"status": "ready"}
    assert stack.sql("SELECT count(*) FROM analyses") == "0"
    assert stack.sql("SELECT current_database()") == "threatgraph_stack"
