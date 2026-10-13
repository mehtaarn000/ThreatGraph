"""Fetch and validate the public UCI PhiUSIIL dataset."""

from pathlib import Path

import pandas as pd
from ucimlrepo import fetch_ucirepo


UCI_DATASET_ID = 967
RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"
RAW_CSV = RAW_DIR / "phiusiil.csv"


def load_dataset(refresh: bool = False) -> pd.DataFrame:
    """Load a cached CSV or fetch PhiUSIIL from UCI and cache it locally."""
    if RAW_CSV.exists() and not refresh:
        frame = pd.read_csv(RAW_CSV)
    else:
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        dataset = fetch_ucirepo(id=UCI_DATASET_ID)
        features = dataset.data.features.copy()
        targets = dataset.data.targets.copy()
        frame = pd.concat([features, targets], axis=1)
        frame.to_csv(RAW_CSV, index=False)

    # The UCI metadata renders this column as "Label", while the downloaded
    # CSV currently uses lowercase "label". Normalize both forms.
    label_column = next((column for column in frame.columns if column.lower() == "label"), None)
    if "URL" not in frame.columns or label_column is None:
        raise ValueError("UCI dataset must contain URL and label columns.")
    if label_column != "Label":
        frame = frame.rename(columns={label_column: "Label"})

    frame = frame.dropna(subset=["URL", "Label"]).copy()
    frame["URL"] = frame["URL"].astype(str)
    frame["Label"] = pd.to_numeric(frame["Label"], errors="raise")
    unexpected = set(frame["Label"].unique()).difference({0, 1})
    if unexpected:
        raise ValueError(f"Unexpected UCI labels: {sorted(unexpected)}")

    frame["Label"] = frame["Label"].astype(int)

    # UCI's encoding is 0=phishing, 1=legitimate. ThreatGraph's internal
    # convention is positive class 1=phishing.
    frame["is_phishing"] = (frame["Label"] == 0).astype(int)
    return frame.reset_index(drop=True)
