"""Load the public Zenodo dataset as an explicitly weakly labeled benchmark.

Phishing rows carry a target brand. Benign rows do not, so this module samples
benign domains and assigns brands using the positive brand distribution. Those
negative pairs are useful for an initial experiment, but are not reviewed
domain-brand judgments and must not be described as production labels.
"""

import hashlib
import json
from pathlib import Path
import time
from urllib.request import urlopen

import numpy as np
import pandas as pd


RECORD_URL = "https://zenodo.org/records/8041387"
LICENSE = "CC BY 4.0"
FILES = {
    "brands.csv": (16_951, "4194175e26f89582dd0a641b34f897de"),
    "phishing.csv": (61_519_197, "513962464c413fc30b2030547a12868a"),
    "not-phishing.csv": (107_438_400, "f5d218eb67f5d7bd0571e8089a8fc392"),
}


def _md5(path):
    digest = hashlib.md5()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_dataset(output_dir):
    """Download only the structured CSV files, never the archived site pages."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, (expected_size, expected_md5) in FILES.items():
        destination = output_dir / filename
        if destination.exists() and destination.stat().st_size == expected_size and _md5(destination) == expected_md5:
            continue
        partial = destination.with_suffix(destination.suffix + ".part")
        for attempt in range(3):
            try:
                with urlopen(f"{RECORD_URL}/files/{filename}?download=1", timeout=60) as response:
                    with partial.open("wb") as output:
                        while True:
                            chunk = response.read(1024 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)
                if partial.stat().st_size != expected_size or _md5(partial) != expected_md5:
                    raise ValueError(f"Downloaded {filename} failed its size or MD5 check.")
                partial.replace(destination)
                break
            except Exception:
                partial.unlink(missing_ok=True)
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)
    return {name: output_dir / name for name in FILES}


def _as_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def load_brand_pairs(phishing_path, benign_path, brands_path, negative_ratio=1.0, random_state=42):
    """Return target-brand phishing positives and sampled benign proxy pairs.

    Positive brand associations come from the dataset's ``brands`` field.
    Since benign records have no brand association, sampled benign domains are
    paired with brands according to the observed positive brand distribution.
    ``label_source`` and ``label_quality`` preserve this important distinction.
    """
    if negative_ratio <= 0:
        raise ValueError("negative_ratio must be positive.")

    brands = pd.read_csv(brands_path, dtype=str, keep_default_na=False)
    required_brands = {"identifier", "name", "website"}
    if not required_brands.issubset(brands.columns):
        raise ValueError(f"Brand catalog must include {sorted(required_brands)}.")
    catalog = {
        row.identifier: {"brand_name": row.name, "brand_domain": row.website}
        for row in brands.itertuples(index=False)
    }

    positive_frame = pd.read_csv(
        phishing_path,
        usecols=["_id", "domain", "url", "brands", "scan_date"],
        dtype=str,
        keep_default_na=False,
    )
    positives = []
    for row in positive_frame.rename(columns={"_id": "source_id"}).itertuples(index=False):
        domain = _as_text(row.domain).casefold().rstrip(".")
        if not domain:
            continue
        try:
            brand_ids = json.loads(row.brands or "[]")
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid brand list for source record {row.source_id}.") from exc
        for brand_id in sorted(set(brand_ids)):
            brand = catalog.get(brand_id)
            if not brand:
                continue
            positives.append({
                "candidate_domain": domain,
                "candidate_url": _as_text(row.url) or domain,
                "brand_id": brand_id,
                **brand,
                "target": 1,
                "label_source": "Zenodo phishing record with declared target brand",
                "label_quality": "source_labeled_positive",
                "source_record_id": _as_text(row.source_id),
                "observed_at": _as_text(row.scan_date),
            })
    if not positives:
        raise ValueError("No phishing records with a known target brand were found.")

    positive_frame = pd.DataFrame.from_records(positives).drop_duplicates(
        ["candidate_domain", "brand_id", "observed_at"]
    )
    brand_counts = positive_frame["brand_id"].value_counts().sort_index()
    benign_frame = pd.read_csv(
        benign_path,
        usecols=["_id", "domain", "url", "scan_date"],
        dtype=str,
        keep_default_na=False,
    )
    benign_frame["domain"] = benign_frame["domain"].str.strip().str.casefold().str.rstrip(".")
    benign_frame = benign_frame.loc[benign_frame["domain"].ne("")].drop_duplicates("domain")
    requested = min(len(benign_frame), int(round(len(positive_frame) * negative_ratio)))
    if requested == 0:
        raise ValueError("No benign domains are available for weak-negative sampling.")

    rng = np.random.default_rng(random_state)
    selected = rng.choice(len(benign_frame), size=requested, replace=False)
    sampled = benign_frame.iloc[selected].reset_index(drop=True)
    brand_ids = brand_counts.index.to_numpy()
    probabilities = (brand_counts / brand_counts.sum()).to_numpy()
    assigned_brands = rng.choice(brand_ids, size=requested, p=probabilities)
    negatives = []
    for row, brand_id in zip(sampled.rename(columns={"_id": "source_id"}).itertuples(index=False), assigned_brands):
        negatives.append({
            "candidate_domain": row.domain,
            "candidate_url": _as_text(row.url) or row.domain,
            "brand_id": brand_id,
            **catalog[brand_id],
            "target": 0,
            "label_source": "Zenodo non-phishing pool; brand paired by seeded sampling",
            "label_quality": "weak_benign_proxy",
            "source_record_id": _as_text(row.source_id),
            "observed_at": _as_text(row.scan_date),
        })
    return pd.concat([positive_frame, pd.DataFrame.from_records(negatives)], ignore_index=True)
