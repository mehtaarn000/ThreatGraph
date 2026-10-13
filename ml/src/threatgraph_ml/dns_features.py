"""Shared DNS features for historical DomainRadar records and live Go snapshots."""
from collections import Counter
import ipaddress
import math

import idna
import numpy as np
import tldextract

# Use the package's bundled suffix list. No network or runtime PSL refresh.
SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                               include_psl_private_domains=True)
SCHEMA_VERSION = 1
RECORD_TYPES = ("A", "AAAA", "NS", "MX")
TERMS = ("login", "verify", "account", "secure", "support", "update", "signin")


def normalize_domain(value):
    value = str(value or "").strip().rstrip(".")
    ascii_host = idna.encode(value, uts46=True).decode("ascii").lower()
    if len(ascii_host) > 253 or "." not in ascii_host:
        raise ValueError("Expected a fully qualified domain")
    try:
        ipaddress.ip_address(ascii_host)
    except ValueError:
        return ascii_host
    raise ValueError("Expected a domain, not an IP address")


def registrable_domain(domain):
    result = SUFFIXES(domain)
    return result.registered_domain or domain


def entropy(text):
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in Counter(text).values()) if text else 0.0


def from_domainradar(row):
    raw = row.get("dns")
    if not isinstance(raw, dict):
        return {kind: None for kind in RECORD_TYPES}
    result = {}
    for kind in RECORD_TYPES:
        if kind not in raw:
            result[kind] = None
            continue
        value = raw[kind]
        # The publisher documents null as no records found, not a timed-out lookup.
        if value is None:
            result[kind] = []
        elif kind in ("A", "AAAA") and isinstance(value, list):
            result[kind] = value
        elif kind == "NS" and isinstance(value, dict):
            result[kind] = list(value)
        elif kind == "MX" and isinstance(value, dict):
            result[kind] = [{"value": host, "preference": metadata["priority"]}
                            for host, metadata in value.items()]
        else:
            raise ValueError(f"Unexpected DomainRadar {kind} record structure")
    return result


def from_snapshot(snapshot):
    result = {kind: None for kind in RECORD_TYPES}
    seen = set()
    for query in snapshot["queries"]:
        kind = query["type"]
        if kind not in result:
            continue
        if kind in seen:
            raise ValueError(f"Duplicate DNS query type: {kind}")
        seen.add(kind)
        if query["status"] in ("not_found", "no_records"):
            result[kind] = []
        elif query["status"] == "ok":
            records = query["records"]
            result[kind] = records if kind == "MX" else [record["value"] for record in records]
        # Timeouts/errors remain unknown, never false evidence of zero records.
    return result


def extract_dns_features(domain, dns):
    domain = normalize_domain(domain)
    base = registrable_domain(domain)
    labels = domain.split(".")
    chars = domain.replace(".", "")
    features = {
        "lex_host_length": len(domain), "lex_label_count": len(labels),
        "lex_longest_label": max(map(len, labels)),
        "lex_digit_ratio": sum(c.isdigit() for c in domain) / len(domain),
        "lex_hyphen_count": domain.count("-"), "lex_entropy": entropy(chars),
        "lex_unique_ratio": len(set(chars)) / len(chars),
        "lex_punycode": int(any(label.startswith("xn--") for label in labels)),
        "lex_keyword_count": sum(term in domain for term in TERMS),
        "lex_subdomain_labels": max(0, len(labels) - len(base.split("."))),
    }
    normalized = {}
    for kind in RECORD_TYPES:
        records = dns.get(kind)
        if records is None:
            normalized[kind] = None
        elif kind in ("A", "AAAA"):
            ips = {ipaddress.ip_address(value) for value in records}
            expected = 4 if kind == "A" else 6
            if any(ip.version != expected for ip in ips):
                raise ValueError(f"Wrong IP family in {kind}")
            normalized[kind] = sorted(str(ip) for ip in ips)
        elif kind == "NS":
            normalized[kind] = sorted({normalize_domain(value) for value in records})
        else:
            values = set()
            for record in records:
                preference = record["preference"]
                if isinstance(preference, bool) or not isinstance(preference, int) or not 0 <= preference <= 65535:
                    raise ValueError("Invalid MX preference")
                host = "." if record["value"] == "." else normalize_domain(record["value"])
                values.add((host, preference))
            normalized[kind] = sorted(values)
        values = normalized[kind]
        features[f"dns_{kind.lower()}_missing"] = int(values is None)
        features[f"dns_{kind.lower()}_count"] = float("nan") if values is None else len(values)
    for kind in ("NS", "MX"):
        values = normalized[kind]
        hosts = None if values is None else [value if kind == "NS" else value[0] for value in values]
        hosts = None if hosts is None else [host for host in hosts if host != "."]
        prefix = f"dns_{kind.lower()}"
        for name, function in (
            ("mean_length", lambda host: len(host)),
            ("mean_entropy", entropy),
            ("same_domain_ratio", lambda host: registrable_domain(host) == base),
        ):
            features[f"{prefix}_{name}"] = (
                float("nan") if hosts is None else float(np.mean([function(host) for host in hosts])) if hosts else 0.0
            )
    mx = normalized["MX"]
    for name, function in (("min", min), ("max", max)):
        features[f"dns_mx_preference_{name}"] = (
            float("nan") if mx is None else function((pref for _, pref in mx), default=0)
        )
    features["dns_null_mx"] = float("nan") if mx is None else int((".", 0) in mx)
    for kind, prefix_length in (("A", 24), ("AAAA", 48)):
        values = normalized[kind]
        features[f"dns_{kind.lower()}_prefix_count"] = (
            float("nan") if values is None else len({str(ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)) for ip in values})
        )
    return features
