# ThreatGraph: DNS model evaluation

[DomainRadar 2024](https://zenodo.org/records/14332167), Radek Hranicky, Adam Horak, Ondrej Ondryas. CC BY 4.0. This experiment adapts their records into domain-level lexical and DNS features.

## Completed

- Acquired 20,121 records using 71 reproducible byte windows (284 MiB), with checksummed local caches and provenance metadata.
- Retained 19,932 valid unique hosts: 184 malformed records rejected and 5 duplicate hosts removed. No conflicting labels found.
- Extracted 10 lexical and 19 DNS features covering A, AAAA, NS and MX records.
- Trained six models: logistic regression and LightGBM, each using lexical, DNS, and combined features.
- Saved model bundles, split assignments, predictions, metrics, and a scorer accepting the existing Go DNS endpoint response.
- Passed 70 Python tests, including 11 new DNS-pipeline tests. Successfully loaded the trained model and scored a synthetic API-format snapshot. One urllib3/LibreSSL environment warning remains; see the repository setup guide.

## Holdout results

The model was selected on validation average precision before test evaluation. All rows below use the same chronological, registrable-domain-disjoint holdout of 3,987 hosts. Precision and recall use threshold 0.5; no model achieved the validation target of 90% precision with at least 20 alerts. Scores are uncalibrated.

| Model | Average precision | Precision | Recall |
|---|---:|---:|---:|
| logistic lexical | 0.744 | 69.2% | 67.1% |
| logistic dns | 0.694 | 63.6% | 83.0% |
| logistic combined | 0.805 | 72.6% | 75.8% |
| lightgbm lexical | 0.779 | 73.3% | 58.2% |
| lightgbm dns | 0.755 | 68.3% | 81.9% |
| lightgbm combined | 0.855 | 81.0% | 68.9% |

**Selected model: LightGBM with combined features.** DNS increased its average precision by 0.076; a 200-replicate paired group-bootstrap interval was [0.059, 0.090]. This measures uncertainty within this holdout, not uncertainty about new feeds or future performance.

All 40 highest-scored holdout domains were labeled phishing. That small alert-budget result is descriptive and should not be presented as 100% real-world precision.

## Interpretation and limitations

- Training: 11,438 rows (8.7% phishing). Validation: 3,913 rows (1.0% phishing, only 38 positives). Test: 3,987 rows (49.2% phishing). Another 594 observations were purged to keep related domains separate without violating chronology.
- The sources were collected at different times. Umbrella contributes only training examples; test negatives are CESNET. This source/time imbalance makes the evaluation unsuitable as a production accuracy estimate.
- The sample uses byte windows and drops partial boundary records. It is not a proven uniform domain sample. Whole-file publisher hashes were checked as metadata identifiers, not verified over entire downloaded files.
- Labels are historical and source-derived, including retrospective vetting. The task is generic phishing detection, not confirmed brand impersonation.
- Every retained historical record has known DNS-field status. Live timeout/error cases are preserved as unknown by the adapter but have not been validated by this training distribution.
- Shared infrastructure/campaigns can cross registrable-domain groups. Bootstrap intervals do not remove that possible leakage.
- The existing brand classifier and API scoring behavior have not been replaced. This model is currently available through a separate offline scorer.

## Reproduce and next step

From the repository root:

```sh
ml/.venv/bin/python -m pip install -r ml/requirements-dns.txt
ml/.venv/bin/python -m ml.src.threatgraph_ml.domainradar_data
ml/.venv/bin/python -m ml.src.threatgraph_ml.train_dns
ml/.venv/bin/python -m ml.src.threatgraph_ml.score_dns saved-dns-response.json
```

On macOS, install libomp for LightGBM. The full method, setup details and feature contract are documented in `ml/docs/domainradar.md`. Models are under `ml/artifacts/domainradar/`; acquisition data under `ml/data/raw/domainradar/`; split assignments and predictions under `ml/reports/`. Large generated artifacts are excluded from Git.

Next: connect the snapshot scorer to the application as a separate generic-phishing result, then collect a fresh independently labeled holdout before calibration or production threshold selection.

Sample SHA-256: `5cd41fbc98390c4a1e00bf197c87fb06f117cb0edda7776aac63c39ac89b8494`
Report generated: 2026-10-13T19:29:08.004935+00:00
