# DNS model integration

The Go API now connects DNS enrichment to the Python generic-phishing model.
Brand-pair analyses remain a separate API and database record. DNS scores are
explicitly experimental, uncalibrated scores rather than probabilities of
brand impersonation.

## Setup

Install `ml/requirements-service.txt` (now includes the DNS model dependencies),
and acquire/train the artifact using `ml/docs/domainradar.md`. For a local Python
process, set `THREATGRAPH_DNS_MODEL_PATH` to
`ml/artifacts/domainradar/selected.joblib`. The existing brand artifact is also
required. Docker Compose sets both artifact paths and mounts `ml/artifacts`
read-only. Its Python image installs libgomp1 for LightGBM. On macOS, use libomp.

The service loads configured artifacts once during startup; replacing a model
file requires a model-service restart. Missing or invalid configured artifacts
fail startup. If no DNS path is configured, brand scoring still starts and DNS
scoring returns unavailable. The internal `GET /v1/dns/readyz` reports DNS model
availability; the existing `/healthz` remains a general process health check.
Only load trusted local joblib artifacts.

## Public endpoints

```sh
curl -X POST http://localhost:8080/v1/domains/example.com/dns/predictions
curl http://localhost:8080/v1/domains/example.com/dns/predictions
```

POST has no request body. It resolves the domain through the existing DNS
enrichment service or reuses an unexpired saved observation, sends that snapshot
to Python, validates the returned identity/provenance, and saves the prediction.
GET returns `{"predictions": [...]}`, newest creation first, with a maximum of
100 records; an unknown domain returns an empty array. This initial bounded
history endpoint has no pagination.

Prediction fields:

| Field | Meaning |
|---|---|
| `id`, `created_at` | Persisted prediction identity and creation time |
| `snapshot_id` | Foreign key to the exact DNS observation |
| `domain`, `observed_at` | Domain and DNS observation time, preserved across HTTP |
| `generic_phishing_score`, `threshold`, `flagged` | Uncalibrated model result and decision |
| `model` | Training model name |
| `model_version` | SHA-256 of the exact artifact bytes loaded by Python |
| `score_semantics`, `experimental` | Interpretation and experimental status |
| `unknown_record_types` | Lookup failures, distinguished from successful empty answers |

The internal `POST /v1/score/dns` accepts one unwrapped saved snapshot. It checks
the UUID, timezone-aware timestamp, four distinct query types, record structure,
MX preferences, and domain/IP values. Snapshot metadata such as resolver, expiry,
and graph relationships may be present but is not a model input. Go verifies the
response's snapshot ID, domain, precise observation time, score range, threshold
decision, unknown-record list, and artifact fingerprint before persistence.

## Persistence and retry behavior

Migration `003_dns_predictions.sql` creates `dns_predictions` with a foreign key
to `dns_observations` and a unique `(snapshot_id, model_version)` constraint.
Concurrent or repeated requests for the same pair return the first saved result
and the same prediction ID. Inference is still repeated; this is persistence
deduplication, not an inference cache. A new snapshot or changed artifact creates
a new prediction. The full response is stored as JSONB for auditability.

POST returns 200 for both a new prediction and an existing one. Scoring runs
synchronously with a 24-second overall deadline and an 8-second model-client
timeout. The server write deadline is 30 seconds. No queue or background worker
is introduced in this increment.

| Failure | Response / saved data |
|---|---|
| Invalid domain | 422; no DNS lookup |
| All four lookups fail | 422 `insufficient_dns`; snapshot retained, no prediction |
| Some lookups fail | Score may be produced; failed types listed explicitly |
| Model unavailable/invalid response | 502 `dns_model_error`; snapshot retained |
| Model deadline | 504 `dns_model_error`; snapshot retained |
| Prediction persistence fails | 500 `prediction_storage_error`; no success reported |

Existing DNS collection errors keep their original status codes. Retrying a model
failure normally reuses valid cached DNS evidence; failed/expired snapshots are
collected again according to the existing enrichment policy. Successful negative
answers (`not_found`, `no_records`) are usable empty evidence. A model flag is
never proof of phishing, especially for partial snapshots: unknown DNS failures
were not represented in the historical training sample.

## Validation

- Python endpoint tests: one-time loading, precise timestamps, malformed records,
  missing model, failed artifact, all/partial DNS failure, inference errors.
- Go client tests: missing/mismatched fields, provenance, decisions and deadlines.
- Isolated real-service tests: DNS protocol → Go → Python → PostgreSQL; direct
  inference equality, restart durability, concurrent deduplication, outages and
  retry recovery, storage permission failures, and artifact-version changes.

The integration fixtures train small synthetic models, avoiding any requirement
to download DomainRadar for tests. They validate wiring and persistence rather
than classification accuracy. The historical dataset evaluation remains separate.
This change does not supply authentication, public deployment, or a dashboard;
keep the internal scorer private and use the existing local deployment setup.
