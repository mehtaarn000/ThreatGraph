# ThreatGraph ML pipeline (initial slice)

For the separate DNS-enriched DomainRadar experiment, acquisition commands,
model comparisons, and scoring of Go DNS snapshots, see
[the DNS model guide](docs/domainradar.md). It uses 29 lexical/DNS features and
does not replace the existing brand classifier.

This is the first reproducible ML pipeline for ThreatGraph. It uses the UCI
PhiUSIIL Phishing URL (Website) dataset to train a **generic phishing URL
classifier**. Its labels do not identify which brand is being impersonated, so
this model is not a brand-impersonation classifier and its score must not be
presented as one.

UCI documents 235,795 URL/page records. Its `Label` field uses `0` for phishing
and `1` for legitimate. The dataset is CC BY 4.0. Cite Prasad & Chandra (2024),
UCI Machine Learning Repository, DOI: <https://doi.org/10.1016/j.cose.2023.103545>.

## What this pipeline does

1. Downloads the dataset from UCI into a local, ignored data directory.
2. Trains two logistic-regression models: handcrafted URL lexical features,
   then lexical features combined with character n-grams.
3. Splits by the dataset's `Domain` value where available, keeping a domain
   group out of both train and test. This is a group holdout, not a temporal
   test: the dataset does not provide the observation times needed for one.
4. Reports average precision, precision, recall, F1, ROC AUC, and precision in
   the highest-scored 1% of the test set.
5. Saves the best model, feature configuration, and a JSON report locally.

The first experiment is intended to validate data handling, feature extraction,
model persistence, and evaluation. It does not establish production performance
or prove that the model generalizes to a new feed, time period, or target brand.

## Setup

Requires Python 3.9 or newer. From the repository root:

```bash
python3 -m venv ml/.venv
source ml/.venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r ml/requirements.txt
```

## Download and train

```bash
python -m ml.src.threatgraph_ml.train
```

The command fetches the public UCI dataset, trains both models, prints metrics,
and writes artifacts under `ml/artifacts/` and a report under `ml/reports/`.
Raw data, fitted models, and generated reports are excluded from Git. Keep the
dataset citation and license information with any published results.

## Next ML milestone

Add a reviewed `domain-brand` dataset with labels `confirmed_impersonation`,
`confirmed_not_impersonation`, and `unknown`. Only the first two should enter a
binary training run. Preserve source provenance and timestamps, then use a
campaign-aware and time-based holdout before claiming brand-risk performance.

The domain–brand label contract and lexical feature extractor are in
`ml/docs/brand-labeling.md`, `ml/templates/domain_brand_labels.csv`, and
`ml/src/threatgraph_ml/brand_features.py`. `brand_dataset.py` validates reviewed
labels and builds a feature table.

## Exploratory brand-pair benchmark

The [Zenodo Phishing Website Dataset](https://zenodo.org/records/8041387)
provides phishing records with target-brand identifiers and a separate
non-phishing pool. Its metadata lists CC BY 4.0 and DOI
`10.5281/zenodo.8041387`; cite the dataset and retain attribution if reusing its
data. The downloader fetches only `brands.csv`, `phishing.csv`, and
`not-phishing.csv`. It does not download the much larger archived page files or
visit any URLs.

Run the first pair-model experiment with:

```bash
python -m ml.src.threatgraph_ml.train_brand_baseline
```

The source phishing records include a target brand, so they are used as
source-labeled positive pairs. The non-phishing records do not name a brand;
the experiment samples those domains and assigns brands according to the
positive brand distribution. These are weak negative proxies, not manually
reviewed domain–brand judgments. The report preserves that limitation, uses a
candidate-domain grouped split, and compares the logistic model with a simple
brand-token rule. Because the source is historical and the negative pairs are
weak, its metrics are only a pipeline benchmark. Do not use them to claim
production brand-impersonation performance.

The fitted model is written to `ml/artifacts/zenodo_brand_pair_baseline.joblib`
and the run manifest to `ml/reports/zenodo_brand_pair_metrics.json`; both are
ignored by Git. The earlier PhiUSIIL model remains the generic phishing URL
baseline and has a separate report.

### Score one candidate–brand pair

After training, score a candidate against a specific brand:

```python
from ml.src.threatgraph_ml.brand_inference import score_brand_pair

result = score_brand_pair(
    "https://acme-login.example/secure",
    brand_name="Acme",
    brand_domain="https://acme.example",
)
```

The returned `impersonation_score` is an **uncalibrated model score**, not a
reliable probability or a verdict. `feature_contributions` lists the strongest
log-odds contributions from the logistic model. These explain the model's
behavior; they do not establish malicious intent. This function only examines
the supplied URL string and brand details; it does not fetch the site.

The application should load the model once at process startup, then call this
function from its inference service. Before treating scores as alert thresholds,
replace weak negatives with reviewed domain–brand labels, calibrate on a
separate validation set, and choose thresholds against an analyst alert budget.


### Entropy and official-domain feature comparison

Run `python -m ml.src.threatgraph_ml.train_brand_baseline` to compare four
logistic models on the same domain-grouped holdout: the original 20 features,
entropy alone added, official-domain similarity alone added, and all 23 features.
All models use identical preprocessing and classifier settings. The report records
feature lists, dataset hashes, the holdout index hash, and each variant's metrics.

New features:
- `host_shannon_entropy`: empirical Shannon character entropy in bits, excluding
  dots and a leading www. Retains digits and hyphens. Character order does not
  affect this value; high entropy alone does not imply malicious intent.
- `official_domain_edit_similarity`: normalized Levenshtein similarity of the
  complete candidate and official hostnames.
- `official_domain_bigram_dice`: overlap between sets of adjacent character pairs
  in those hostnames.

These new comparisons normalize case, trailing dots, IDNA Unicode spelling and
leading www. They retain other subdomains and suffixes, ignore URL paths/queries,
and do not infer registrable domains or visual confusables. Missing hosts yield
zero similarity.

Artifacts are saved separately as `zenodo_brand_pair_<variant>.joblib`.
The existing `zenodo_brand_pair_baseline.joblib` remains the original 20-feature
model. To serve the expanded model locally, set
`THREATGRAPH_BRAND_MODEL_PATH=ml/artifacts/zenodo_brand_pair_combined_23.joblib`
when starting the Python service from the repository root. In Compose, change
the model service's artifact path to
`/app/ml/artifacts/zenodo_brand_pair_combined_23.joblib`, then recreate that service.

The initial comparison used 8,204 training pairs and 2,048 held-out pairs.
Average precision rose from 0.870135 to 0.871246 with all three new features.
At threshold 0.5, precision changed from 0.824601 to 0.814732 and recall from
0.706341 to 0.712195. All four models achieved precision 1.0 in the top 21
alerts on this particular holdout. These small, mixed differences do not establish
a reliable improvement. Labels include weak negative proxies; the holdout is
historical, non-temporal, and already used for exploratory comparison. Use a fresh
evaluation set before making performance claims or choosing deployment thresholds.
