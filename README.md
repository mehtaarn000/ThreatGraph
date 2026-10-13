# ThreatGraph

ThreatGraph is a defensive threat-intelligence research project. It enriches domains with DNS evidence, scores generic phishing risk, and stores auditable, time-stamped observations for investigation. Its experimental generic-phishing score is distinct from its brand-impersonation score; neither is a confirmed incident verdict.

## Project status

- Go REST API with PostgreSQL persistence for analyses, DNS observations, and DNS model predictions.
- Python FastAPI model service for brand-pair scoring and DNS-based generic phishing inference.
- Reproducible ML experiments, feature adapters, evaluation reports, and functional tests.
- DNS relationships are recorded as evidence for future graph correlation. A graph database and interactive dashboard are not implemented yet.

The DomainRadar model was trained on a bounded sample of public data. It is experimental and uncalibrated. Its benchmark has source and time-period bias; see [the evaluation report](outputs/domainradar-model-evaluation.md) before interpreting its metrics. Dataset processing and model scoring do not visit candidate websites or collect credentials.

## Run locally

Requirements: Docker Compose, Python 3.9+, and Git. From the repository root, create the local Python environment and train the artifacts used by the stack:

```bash
python3 -m venv ml/.venv
source ml/.venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r ml/requirements-dns.txt
python -m pip install -r ml/requirements-service.txt

# Train the brand-pair model required by the scoring service.
python -m ml.src.threatgraph_ml.train_brand_baseline

# Acquire a bounded DomainRadar sample and train the DNS model.
python -m ml.src.threatgraph_ml.domainradar_data
python -m ml.src.threatgraph_ml.train_dns

# Build and start PostgreSQL, the model service, and the Go API.
docker compose up --build
```

On macOS, install `libomp` for LightGBM (`brew install libomp`). The Linux container installs its LightGBM runtime dependency itself. The default DomainRadar download is about 284 MiB; acquisition, sampling limits, and license details are in [the DNS ML guide](ml/docs/domainradar.md).

The API binds to localhost on port 8080 and PostgreSQL on port 5432 by default. Compose uses a development-only database password; set `POSTGRES_PASSWORD` before using the stack outside local development. Do not expose the API publicly: authentication and rate limiting are not implemented.

## API overview

- `GET /healthz` and `GET /readyz`: process health and dependency readiness.
- `POST /v1/analyses`: score and save a domain/brand pair.
- `GET /v1/analyses/{id}`: retrieve a saved brand analysis.
- `POST /v1/domains/{domain}/dns`: collect or reuse a DNS observation.
- `GET /v1/domains/{domain}/dns`: retrieve the latest DNS observation.
- `GET /v1/domains/{domain}/dns/history`: retrieve DNS observation history.
- `POST /v1/domains/{domain}/dns/predictions`: enrich and score a domain, then save an experimental generic-phishing prediction.
- `GET /v1/domains/{domain}/dns/predictions`: retrieve saved predictions.

See [backend API and configuration](backend/README.md), [DNS enrichment details](backend/docs/dns-enrichment.md), and [DNS prediction behavior](backend/docs/dns-predictions.md).

## Tests

```bash
ml/.venv/bin/python -m pytest ml/tests -q
cd backend && go test -race ./... && cd ..
```

The full functional suite launches isolated local PostgreSQL, DNS, API, and model services. See [backend functional test instructions](backend/README.md) for the opt-in command and requirements. Synthetic test domains and records are used; the DNS fixture does not forward queries to the public internet.

## Repository layout

```text
backend/   Go API, PostgreSQL migrations, DNS enrichment, service docs
ml/        Python features, datasets, training, inference, and tests
tests/     End-to-end tests using local synthetic services
outputs/   Human-readable and machine-readable model evaluation results
```

Raw datasets, local model artifacts, virtual environments, and generated reports are excluded from Git. See the ML guides for data attribution and reproduction.
