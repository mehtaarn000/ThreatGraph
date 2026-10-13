# DNS phishing benchmark

This experiment trains a separate **generic domain-phishing classifier** using
[DomainRadar 2024, Zenodo record 14332167](https://zenodo.org/records/14332167),
by Radek Hranicky, Adam Horak, and Ondrej Ondryas (CC BY 4.0).
The [publisher schema](https://github.com/nesfit/domainradar-dib/blob/main/data_schema.json)
describes the original records. Our preprocessing changes those records into
domain-level features. Neither the dataset nor this classifier establishes
which brand a domain impersonates. The existing brand model is unchanged.

## Reproduce

Run from the repository root using a Python environment with a supported SSL
runtime. On macOS, LightGBM also needs `brew install libomp`.

```sh
ml/.venv/bin/python -m pip install -r ml/requirements-dns.txt
ml/.venv/bin/python -m ml.src.threatgraph_ml.domainradar_data
ml/.venv/bin/python -m ml.src.threatgraph_ml.train_dns
ml/.venv/bin/python -m pytest ml/tests/test_dns_pipeline.py -q
```

The local Python 3.9 / LibreSSL environment emits an urllib3 compatibility
warning. The extractor uses tldextract's bundled suffix list offline; acquisition
uses Python's urllib. Prefer a maintained Python build linked to OpenSSL for a
fresh environment. Exact package versions are pinned in the requirements files.

### Acquisition and provenance

The default downloads 71 seeded 4 MiB byte windows across the phishing,
benign CESNET, and benign Umbrella JSON files (284 MiB). This avoids downloading
roughly 14.8 GB. Each file is divided into equal byte strata and a window is
selected inside each stratum. Only complete objects within a window are kept.
This is **approximate sampling with boundary and record-length bias**, not a
uniform random sample of domains or a sample of real-world phishing prevalence.

`ml/data/raw/domainradar/manifest.json` records file identities, window offsets,
window SHA-256 digests, the sample digest, seed, counts, license and attribution.
The publisher's full-file sizes and MD5 identifiers are checked against API
metadata. Full-file MD5 contents are **not** verified because only ranges were
downloaded. Cached windows are verified by length and local digest on reuse.
Interrupted acquisition can resume using the same command. HTTP range responses
are validated; requests have deadlines and bounded retries. No listed domains
or websites are contacted. Raw data and model artifacts are ignored by Git.

## Feature contract

There are 29 features: 10 lexical and 19 DNS.

- Lexical: hostname length, label count, longest label, digit fraction, hyphens,
  character entropy, unique-character fraction, punycode indicator, suspicious
  keyword count, and subdomain depth.
- DNS: A/AAAA/NS/MX counts and unknown indicators; NS/MX mean hostname length,
  entropy and fraction sharing the queried domain's registrable domain;
  minimum/maximum MX preference; null-MX indicator; unique IPv4 /24 and IPv6 /48
  prefix counts.

Counts use deduplicated records. No raw IP identity, hostname identity, source
name, collection timestamp, reputation verdict, TLS, or RDAP field is a model
input. Timestamps only establish observation order. The private/public suffix
list bundled with pinned tldextract is used for grouping and feature extraction.

Historical records and Go API snapshots use separate adapters feeding the same
extractor. DomainRadar explicit null means no records according to its schema;
an absent field means unknown. Live `timeout`, `error`, or `canceled` stays
unknown (NaN plus an indicator), while `no_records` and `not_found` mean empty.
Null MX (`.` with preference zero) is preserved. The historical sample has no
unknown indicators set, so live lookup failures remain an unvalidated scenario.
Cache hits and timeout durations are operational behavior, not training targets.

## Training and evaluation

1. Normalize domains using IDNA; validate DNS values. Quarantine malformed rows,
   conflicting labels, and missing timestamps. Keep the earliest observation
   per hostname. Counts are reported rather than silently discarded.
2. Use DNS evaluation time, falling back to general evaluation time. Attempt
   60/20/20 chronological cutoffs, assign related registrable domains to their
   latest partition, and purge their earlier observations to preserve chronology.
3. If any temporal partition has fewer than 30 examples of either class, use
   one fixed-seed grouped split and report that fallback explicitly. The current
   run uses the temporal split. This minimum is a feasibility check, not evidence
   that the split has enough positives for robust threshold selection.
4. Train balanced logistic regression (training-only median imputation and
   scaling) and LightGBM, each with lexical, DNS, and combined features. LightGBM
   handles missing numeric inputs directly. Hyperparameters and seed are fixed.
5. Select the model using validation average precision, before test scoring.
   Attempt a validation threshold with at least 90% precision and 20 alerts;
   otherwise retain 0.5 and report failure. No current candidate met that target.
6. Report average precision (stepwise PR summary), ROC-AUC, precision, recall,
   and tie-aware precision at the top 1% alert budget. Compare combined against
   lexical models on identical holdout records using 200 paired, registrable-domain
   bootstrap replicates. Intervals capture holdout sampling uncertainty, not
   training uncertainty or source bias.

Artifacts: six model bundles and `selected.joblib` under
`ml/artifacts/domainradar/`; split assignments, held-out predictions and the
metrics JSON under `ml/reports/`. Models retain the feature order, schema version,
training-sample digest, task name, threshold and score semantics.

### Score a saved enrichment response

```sh
ml/.venv/bin/python -m ml.src.threatgraph_ml.score_dns saved-dns-response.json
```

Accepts the existing Go endpoint's wrapped response (`snapshot` plus `cached`)
or an unwrapped snapshot. It returns an **uncalibrated** phishing score, threshold,
model name, observation time and unknown record types. Load only trusted local
joblib files. The same adapter now powers the internal `/v1/score/dns` endpoint.
Set `THREATGRAPH_DNS_MODEL_PATH` to load a bundle once at startup. The Go API
persists separate generic-phishing predictions; it does not substitute this
model for the brand classifier. See
[backend integration](../../backend/docs/dns-predictions.md) for the full contract.

## Limits and next evaluation

The sampled sources have different collection schedules. Training phishing
prevalence is 8.7%, validation 1.0%, and test 49.2%. The validation set contains
only 38 phishing records; Umbrella has no validation/test rows. High test precision
therefore cannot be projected onto a low-prevalence stream. Source-derived labels
and later reputation vetting are not adjudicated ground truth at observation time.
Shared infrastructure and campaigns may cross registrable-domain groups.

The next meaningful experiment is a fresh, prospectively collected and manually
audited holdout with contemporaneous benign and phishing observations from
independent sources. It should include failed DNS lookups, assess precision at
a realistic alert budget, and support calibration before operational thresholds
are adopted. Keep the current test set frozen; improvements tuned after reviewing
its results need a new holdout. Brand impersonation needs separate brand-specific
labels and evaluation.
