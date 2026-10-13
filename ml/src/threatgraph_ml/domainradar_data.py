"""Reproducible bounded sampling of the pinned DomainRadar research release.

Random byte windows span each file. Partial boundary records are excluded, so
this is an approximate record sample, not a proven uniform sample. Full-file
publisher checksums identify the release; window SHA256s verify cached windows,
not the entire remote file. No domains in the data are visited.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import re
import time
from urllib.request import Request, urlopen

RECORD_ID = 14332167
BASE = f"https://zenodo.org/api/records/{RECORD_ID}"
ROOT = Path(__file__).resolve().parents[2]
FILES = {
    "phishing.json": (2247046745, "md5:77a4be494ae696371190a1f7724dc3d9", 1),
    "benign_cesnet.json": (6437047412, "md5:cea8cbe33ec308f76c5ecf3ef6a6219e", 0),
    "benign_umbrella.json": (6075400719, "md5:41e340c0714d7455494c0f893193cb5e", 0),
}
START = re.compile(r'\{\s*"_id"\s*:\s*\{\s*"\$oid"')


def window_plan(size, fraction, window_bytes, seed):
    if not 0 < fraction <= .1 or window_bytes < 65536:
        raise ValueError("fraction must be in (0, .1] and windows at least 64 KiB")
    count = max(1, math.ceil(size * fraction / window_bytes))
    rng = random.Random(seed)
    for index in range(count):
        low, high = size * index // count, size * (index + 1) // count
        width = min(window_bytes, high - low)
        start = rng.randint(low, high - width)
        yield start, start + width - 1


def records_in_window(data):
    # Replacement affects only a cut UTF-8 character at a window boundary.
    text = data.decode("utf-8", errors="replace")
    decoder = json.JSONDecoder()
    for match in START.finditer(text):
        try:
            record, _ = decoder.raw_decode(text, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("domain_name"), str):
            yield record


def fetch_window(job):
    directory, filename, start, end = job
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{start}-{end}.bin"
    digest_path = path.with_suffix(".sha256")
    expected_length = end - start + 1
    data = None
    if path.exists() and digest_path.exists():
        cached = path.read_bytes()
        if len(cached) == expected_length and hashlib.sha256(cached).hexdigest() == digest_path.read_text().strip():
            data = cached
    if data is None:
        url = f"{BASE}/files/{filename}/content?start={start}&end={end}"
        for attempt in range(4):
            try:
                request = Request(url, headers={"Range": f"bytes={start}-{end}", "Accept-Encoding": "identity"})
                with urlopen(request, timeout=45) as response:
                    wanted = f"bytes {start}-{end}/{FILES[filename][0]}"
                    if response.status != 206 or response.headers.get("Content-Range") != wanted:
                        raise ValueError(f"Server did not honor bounded range: {response.status}, {response.headers.get('Content-Range')}")
                    data = response.read(expected_length + 1)
                if len(data) != expected_length:
                    raise ValueError("Downloaded window length mismatch")
                temporary = path.with_suffix(".part")
                temporary.write_bytes(data)
                temporary.replace(path)
                digest_path.write_text(hashlib.sha256(data).hexdigest() + "\n")
                break
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)
    records = list(records_in_window(data))
    return {
        "file": filename, "start": start, "end": end,
        "sha256": hashlib.sha256(data).hexdigest(), "complete_records": len(records),
    }, records


def prepare_sample(output_dir, fraction=.02, window_bytes=4 * 1024 * 1024, seed=42):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with urlopen(BASE, timeout=30) as response:
        metadata = json.load(response)
    if metadata["metadata"]["license"]["id"] != "cc-by-4.0":
        raise ValueError("Publisher license differs from the expected CC BY 4.0")
    published = {item["key"]: item for item in metadata["files"]}
    for name, (size, checksum, _) in FILES.items():
        if published[name]["size"] != size or published[name]["checksum"] != checksum:
            raise ValueError(f"Publisher file identity changed: {name}")
    (output_dir / "publisher.json").write_text(json.dumps(metadata, indent=2))
    jobs = []
    for name, (size, _, _) in FILES.items():
        file_seed = seed + int(hashlib.sha256(name.encode()).hexdigest()[:8], 16)
        jobs += [(output_dir / "windows" / name, name, start, end)
                 for start, end in window_plan(size, fraction, window_bytes, file_seed)]
    seen, windows, counts = set(), [], {name: 0 for name in FILES}
    sample_path = output_dir / "sample.jsonl"
    partial_path = sample_path.with_suffix(".part")
    with partial_path.open("w") as output, ThreadPoolExecutor(max_workers=3) as pool:
        for index, (window, records) in enumerate(pool.map(fetch_window, jobs), 1):
            name = window["file"]
            windows.append(window)
            for row in records:
                source_id = row.get("_id", {}).get("$oid")
                key = (name, source_id)
                if source_id is None or key in seen:
                    continue
                seen.add(key)
                # Keep only DNS/model-audit fields, excluding WHOIS personal data.
                selected = {key: row.get(key) for key in
                            ("domain_name", "dns", "remarks", "evaluated_on", "sourced_on", "source")}
                selected.update(source_record_id=source_id, source_file=name, target=FILES[name][2])
                output.write(json.dumps(selected, ensure_ascii=True) + "\n")
                counts[name] += 1
            print(f"Window {index}/{len(jobs)}: {name}, {len(records)} complete records", flush=True)
    partial_path.replace(sample_path)
    manifest = {
        "dataset": f"https://zenodo.org/records/{RECORD_ID}",
        "license": "CC BY 4.0", "authors": "Radek Hranicky, Adam Horak, Ondrej Ondryas",
        "seed": seed, "requested_byte_fraction": fraction, "window_bytes": window_bytes,
        "sampling": "Seeded byte window in each equal-size file stratum; incomplete boundary records excluded. Approximate record sampling with boundary/record-length bias.",
        "counts": counts, "downloaded_bytes": sum(w["end"] - w["start"] + 1 for w in windows),
        "publisher_files": {name: {"bytes": size, "checksum": checksum} for name, (size, checksum, _) in FILES.items()},
        "windows": windows, "sample_sha256": hashlib.sha256(sample_path.read_bytes()).hexdigest(),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return sample_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data/raw/domainradar")
    parser.add_argument("--fraction", type=float, default=.02)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(prepare_sample(args.output_dir, args.fraction, seed=args.seed))


if __name__ == "__main__":
    main()
