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
