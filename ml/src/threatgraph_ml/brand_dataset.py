"""Validate reviewed domain–brand labels and build feature rows."""

from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from .brand_features import extract_brand_features


REQUIRED_COLUMNS = {
    "example_id", "candidate_url", "candidate_domain", "brand_id",
    "brand_name", "brand_domain", "label", "source_name", "observed_at",
    "reviewed_at", "reviewer_id", "evidence_refs",
}
TRAINABLE_LABELS = {"confirmed_impersonation", "confirmed_not_impersonation"}
ALL_LABELS = TRAINABLE_LABELS | {"unknown"}


def _normalize_domain(value):
    text = str(value or "").strip()
    parsed = urlsplit(text if "://" in text else "//" + text)
    host = (parsed.hostname or "").rstrip(".").casefold()
    if not host:
        raise ValueError(f"Invalid candidate_domain: {value!r}")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid candidate_domain: {value!r}") from exc


def load_reviewed_labels(path):
    """Load the label CSV, enforce its contract, and mark trainable rows.

    Unknown cases remain in the returned frame but are excluded from `target`
    and the training feature table.
    """
    frame = pd.read_csv(Path(path), dtype=str, keep_default_na=False)
    missing = REQUIRED_COLUMNS.difference(frame.columns)
    if missing:
        raise ValueError(f"Label file is missing required columns: {sorted(missing)}")
    if frame.empty:
        raise ValueError("Label file contains no examples.")

    frame["label"] = frame["label"].str.strip().str.lower()
    invalid = set(frame["label"]).difference(ALL_LABELS)
    if invalid:
        raise ValueError(f"Unsupported labels: {sorted(invalid)}")
    for column in REQUIRED_COLUMNS - {"candidate_url"}:
        if frame[column].str.strip().eq("").any():
            raise ValueError(f"Required field '{column}' contains an empty value.")

    frame["candidate_domain"] = frame["candidate_domain"].map(_normalize_domain)
    frame["candidate_url"] = frame["candidate_url"].str.strip()
    for row in frame.itertuples(index=False):
        if row.candidate_url and _normalize_domain(row.candidate_url) != row.candidate_domain:
            raise ValueError("candidate_url hostname must match candidate_domain.")
    frame["brand_id"] = frame["brand_id"].str.strip()
    if frame.duplicated(["example_id"]).any():
        raise ValueError("example_id must be unique.")

    pair_key = ["candidate_domain", "brand_id", "observed_at"]
    conflicts = frame.groupby(pair_key)["label"].nunique()
    if (conflicts > 1).any():
        raise ValueError("Conflicting labels exist for a domain–brand observation.")

    frame["is_trainable"] = frame["label"].isin(TRAINABLE_LABELS)
    return frame


def build_training_table(frame):
    """Create pair features and binary target from validated reviewed labels."""
    trainable = frame.loc[frame["is_trainable"]].copy()
    if trainable.empty:
        raise ValueError("No confirmed domain–brand labels are available for training.")

    records = []
    for row in trainable.itertuples(index=False):
        features = extract_brand_features(
            candidate_url=row.candidate_url or row.candidate_domain,
            brand_name=row.brand_name,
            brand_domain=row.brand_domain,
        )
        records.append({
            "example_id": row.example_id,
            "candidate_domain": row.candidate_domain,
            "brand_id": row.brand_id,
            "campaign_id": getattr(row, "campaign_id", ""),
            "observed_at": row.observed_at,
            "target": int(row.label == "confirmed_impersonation"),
            **features,
        })
    return pd.DataFrame.from_records(records)
