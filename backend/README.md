# ThreatGraph Go API

The Go API owns the public REST contract and persists analyses in PostgreSQL.
It sends scoring requests to the internal Python model service, which loads the
scikit-learn model once at startup. Neither service fetches candidate websites.

## Local stack

First train the local model artifact (the model file is intentionally not
tracked by Git):

```bash
python -m ml.src.threatgraph_ml.train_brand_baseline
```

Then build and start the services:

```bash
docker compose up --build -d
```

PostgreSQL creates the `analyses` table on API startup. The model service must
be healthy before the API readiness endpoint succeeds. The API uses local
development credentials by default; set `POSTGRES_PASSWORD` before using the
compose stack outside a personal development machine.

## API

`GET /healthz` checks that the process is running. `GET /readyz` checks the
database and model-service dependencies.

`POST /v1/analyses` scores a domain–brand pair and persists the result:

```json
{
  "candidate_url": "https://acme-login.example/secure",
  "brand_name": "Acme",
  "brand_domain": "https://acme.example"
}
```

The response includes a generated analysis ID, the input pair, score, feature
contributions, and creation time. Retrieve it with `GET /v1/analyses/{id}`.

Example request:

```bash
curl -sS http://localhost:8080/v1/analyses \
  -H 'Content-Type: application/json' \
  -d '{"candidate_url":"https://acme-login.example/secure","brand_name":"Acme","brand_domain":"https://acme.example"}'
```

The returned score is uncalibrated and trained with weak negative pairs. Use it
for local research and prioritization only. This API is not ready for public
exposure: authentication, rate limiting, tenant isolation, and a reviewed
training set are still needed.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | Go API listen port |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `SCORER_URL` | `http://localhost:8000` | Base URL for the internal Python scorer |
| `THREATGRAPH_BRAND_MODEL_PATH` | `ml/artifacts/zenodo_brand_pair_baseline.joblib` | Python service model file |

The API currently performs scoring synchronously and saves completed analyses.
The next backend increment can move discovery and scoring into background jobs,
then add brand management and graph correlation endpoints.

The Compose stack binds published API and database ports to 127.0.0.1. Keep these local bindings until authentication and deployment access controls are configured.

### Functional tests

From the repository root:

```sh
(cd backend && go test -race ./...)
ml/.venv/bin/python -m pytest ml/tests -q
```

To run just the functional workflows:

```sh
(cd backend && go test -race ./internal/api -run Functional -v)
ml/.venv/bin/python -m pytest ml/tests/test_scoring_workflow.py -q
```

Go workflow tests send real HTTP requests through the API and model client,
using a controlled model HTTP server and a stateful in-memory repository. They
cover creating and retrieving distinct analyses, explanations, missing records,
and model/persistence failures without saving partial results.

Python workflow tests build a synthetic labeled dataset, train and save a real
classifier, start the model API with that artifact, and compare HTTP predictions
with direct inference. They also check model caching, invalid requests, and
startup failure for missing/corrupt artifacts.

These tests need no public datasets or trained production artifact. They do not
measure model quality or cover PostgreSQL SQL behavior, Docker startup, or the
Go-to-Python connection in a fully deployed stack.

### Real PostgreSQL and cross-service tests

The opt-in suite in `tests/functional` exercises the compiled Go API, the Python
scoring service with a freshly trained synthetic model, and a real PostgreSQL
database. It does not require Docker or a downloaded research dataset.

Install PostgreSQL 16 on macOS using Homebrew:

```sh
brew install postgresql@16
```

Use the existing Python environment with `ml/requirements-service.txt` installed.
Install Go 1.25 or newer. From the repository root, run:

```sh
PG_BINDIR="$(brew --prefix postgresql@16)/bin" \
THREATGRAPH_RUN_STACK_TESTS=1 \
ml/.venv/bin/python -m pytest tests/functional -v
```

If Go is not on PATH, set `GO_BIN` to its executable. On Linux, set `PG_BINDIR`
to the directory containing `initdb`, `postgres`, and `psql`. Run as a regular
user, since PostgreSQL refuses to initialize as root. The harness builds the API
with Go's race detector, so a supported C compiler/toolchain is needed.

Each test initializes a new temporary database cluster, creates a dedicated
non-superuser application role, and starts its own API and model processes.
PostgreSQL accepts only Unix-socket connections inside a private temporary
directory; database TCP connections are disabled. The harness never reads
`DATABASE_URL` or uses Homebrew's default database cluster, and it does not
register a login/background service. HTTP services use temporary ports; run this
local-only suite on a trusted development machine (the Go API binds all
interfaces and has no authentication).

Coverage includes:
- Startup readiness and automatic database migration.
- HTTP score/explanation equality with direct model-service output and stored SQL data.
- Distinct IDs, timestamps, quoted brand names, and retrieval of persisted records.
- API restart and repeat migration without losing rows.
- Restarting all three services while retaining database files.
- Model outage returning 502 without inserting rows, followed by recovery.
- Database outage, error responses, and connection-pool recovery without an API restart.
- Invalid requests and missing records without database writes.

Subprocesses are stopped in fixture teardown, including after assertion failures.
The short Unix-socket directory is removed. Logs and database files remain in
pytest's managed temporary directory for failure diagnosis; pytest normally
retains only recent runs. Without `THREATGRAPH_RUN_STACK_TESTS=1`, this suite is
skipped. Ordinary unit/functional tests can still run without PostgreSQL.

This validates a local process deployment with synthetic data. Docker image
builds, AWS deployment, production authentication, and model accuracy remain
separate checks.

### DNS enrichment

The Go API can now collect A, AAAA, NS, and MX records for a domain, save
timestamped observations, and reuse cached snapshots across restarts.

- `POST /v1/domains/{domain}/dns`: collect or reuse an observation.
- `GET /v1/domains/{domain}/dns`: retrieve the latest saved observation.
- `GET /v1/domains/{domain}/dns/history?limit=20`: retrieve recent observations.
- `POST /v1/analyses/{id}/dns`: enrich an existing analysis's candidate domain.

See [DNS enrichment](docs/dns-enrichment.md) for cache settings, response semantics,
relationship types, limitations, and tests.
