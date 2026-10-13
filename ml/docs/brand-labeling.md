# Domain–brand training labels

The generic PhiUSIIL model predicts phishing versus legitimate URLs. ThreatGraph
needs a separate task: **does this candidate domain impersonate this specific
brand?** Each labeled example is therefore a domain–brand pair, with the
evidence and review decision preserved.

## CSV contract

Use `ml/templates/domain_brand_labels.csv` as the header template. One row is
one reviewed candidate–brand assessment. Required fields:

| Field | Meaning |
| --- | --- |
| `example_id` | Stable ID for this labeled assessment. |
| `candidate_url` | Observed URL, if available; may include path and query. |
| `candidate_domain` | Normalized hostname being assessed. |
| `brand_id`, `brand_name`, `brand_domain` | Brand context for this pair. |
| `label` | `confirmed_impersonation`, `confirmed_not_impersonation`, or `unknown`. |
| `source_name`, `source_record_id` | Where the underlying observation came from. |
| `observed_at` | When the domain/evidence was observed. |
| `reviewed_at`, `reviewer_id` | When and by whom the label was reviewed. |
| `evidence_refs` | References or concise evidence summary supporting the decision. |
| `campaign_id` | Optional reviewed campaign/family identifier for grouped evaluation. |

Only `confirmed_impersonation` and `confirmed_not_impersonation` are eligible
for binary model training. `unknown` is retained for review and excluded from
the training target. A phishing-feed record is a lead; it is not a positive
domain–brand label unless the target brand is known and the relationship was
reviewed. A popular or highly ranked domain is not automatically a negative.

## Review guidance

- Positive: evidence supports deliberate impersonation of the named brand.
- Negative: evidence supports that this domain is legitimate or unrelated to
  the named brand.
- Unknown: evidence is missing, ambiguous, stale, or points to another target.
- Keep the source observation and the reviewer decision separate. Preserve
  corrections as new review events rather than silently replacing history.
- Do not put secrets, credentials, or personal mailbox/call content in the
  evidence field. Prefer source record IDs and safe, minimal summaries.

## Evaluation groups

Do not randomly split repeated observations of the same candidate domain. Keep
campaign members together when `campaign_id` is known. For the production claim,
reserve a later observation period as a final holdout. Report coverage and class
counts along with precision, recall, average precision, and precision at the
analyst's alert budget. The current public dataset has no suitable observation
times and cannot provide this evaluation for brand impersonation.
