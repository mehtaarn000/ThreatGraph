"""Brand-relative lexical features for a candidate domain–brand pair."""

from collections import Counter
import math
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit


TOKEN_RE = re.compile(r"[^\W_]+", flags=re.UNICODE)
WWW_LABELS = {"www", "www2", "www3"}
NEW_FEATURE_NAMES = (
    "host_shannon_entropy",
    "official_domain_edit_similarity",
    "official_domain_bigram_dice",
)


def _comparison_host(value):
    # Decode IDNA and strip only a leading www; retain all other labels.
    host = unicodedata.normalize("NFC", _idna_unicode(_hostname(value))).casefold()
    return host[4:] if host.startswith("www.") else host


def _shannon_entropy(text):
    """Empirical character entropy in bits; repeated/empty strings have zero."""
    if not text:
        return 0.0
    return -sum((count / len(text)) * math.log2(count / len(text))
                for count in Counter(text).values())



def _hostname(value: str) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text if "://" in text else "//" + text)
    host = (parsed.hostname or "").rstrip(".").casefold()
    return host


def _idna_unicode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def _tokens(value: str):
    normalized = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return [token for token in TOKEN_RE.findall(normalized) if token]


def _edit_similarity(left: str, right: str) -> float:
    """Normalized Levenshtein similarity, using O(min(n,m)) memory."""
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[j] + 1,
                previous[j - 1] + (left_char != right_char),
            ))
        previous = current
    return 1.0 - previous[-1] / max(len(left), len(right))


def _bigram_dice(left: str, right: str) -> float:
    left_grams = {left[index:index + 2] for index in range(max(0, len(left) - 1))}
    right_grams = {right[index:index + 2] for index in range(max(0, len(right) - 1))}
    if not left_grams or not right_grams:
        return float(left == right)
    return 2.0 * len(left_grams & right_grams) / (len(left_grams) + len(right_grams))


def _is_ip(host: str) -> int:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return 1
    except ValueError:
        return 0


def extract_brand_features(candidate_url: str, brand_name: str, brand_domain: str):
    """Return deterministic lexical features; this does not fetch the URL.

    These signals help prioritize pairs for review. They are not proof that a
    domain is malicious. The official-domain match is an exact host/suffix
    check, while `brand_in_subdomain` is explicitly a rough label heuristic
    because it does not use a public-suffix database.
    """
    raw_url = str(candidate_url or "").strip()
    parsed = urlsplit(raw_url if "://" in raw_url else "//" + raw_url)
    host = (parsed.hostname or "").rstrip(".").casefold()
    unicode_host = unicodedata.normalize("NFKC", _idna_unicode(host)).casefold()
    host_labels = [label for label in unicode_host.split(".") if label]
    matching_labels = [label for label in host_labels if label not in WWW_LABELS]

    brand_tokens = [token for token in _tokens(brand_name) if len(token) >= 3]
    official_host = _hostname(brand_domain)
    if official_host.startswith("www."):
        official_host = official_host[4:]
    is_official_host = int(bool(official_host) and (
        host == official_host or host.endswith("." + official_host)
    ))

    pair_similarities = [
        _edit_similarity(brand_token, label)
        for brand_token in brand_tokens
        for label in matching_labels
    ]
    pair_dice = [
        _bigram_dice(brand_token, label)
        for brand_token in brand_tokens
        for label in matching_labels
    ]
    host_compact = "".join(matching_labels)
    brand_compact = "".join(brand_tokens)
    matched_tokens = {
        token for token in brand_tokens
        if any(token in label or label in token for label in matching_labels)
    }
    # Approximation only: without a public suffix list, the final two labels
    # are treated as a likely registrable suffix for this review feature.
    subdomain_labels = matching_labels[:-2] if len(matching_labels) > 2 else []
    path_tokens = set(_tokens(parsed.path or ""))
    non_ascii_count = sum(ord(char) > 127 for char in unicode_host)

    candidate_comparison = _comparison_host(candidate_url)
    official_comparison = _comparison_host(brand_domain)
    comparable = bool(candidate_comparison and official_comparison)
    return {
        # Entropy excludes dots, but retains hyphens and digits. It describes
        # character frequencies, not character order or malicious intent.
        "host_shannon_entropy": _shannon_entropy(candidate_comparison.replace(".", "")),
        "official_domain_edit_similarity": (
            _edit_similarity(candidate_comparison, official_comparison) if comparable else 0.0
        ),
        "official_domain_bigram_dice": (
            _bigram_dice(candidate_comparison, official_comparison) if comparable else 0.0
        ),
        "brand_token_count": len(brand_tokens),
        "host_label_count": len(host_labels),
        "host_length": len(host),
        "brand_tokens_matched": len(matched_tokens),
        "brand_token_present": int(bool(matched_tokens)),
        "brand_in_subdomain": int(any(
            token in label or label in token
            for token in brand_tokens for label in subdomain_labels
        )),
        "brand_token_in_path": int(bool(set(brand_tokens) & path_tokens)),
        "brand_host_edit_similarity": max(pair_similarities, default=0.0),
        "brand_host_bigram_dice": max(pair_dice, default=0.0),
        "brand_host_compact_similarity": _edit_similarity(brand_compact, host_compact),
        "brand_in_host_substring": int(any(token in host_compact for token in brand_tokens)),
        "official_brand_domain_or_subdomain": is_official_host,
        "uses_https": int(parsed.scheme.casefold() == "https"),
        "uses_http": int(parsed.scheme.casefold() == "http"),
        "host_is_ip": _is_ip(host),
        "has_punycode_label": int(any(label.startswith("xn--") for label in host.split("."))),
        "host_non_ascii_ratio": non_ascii_count / max(1, len(unicode_host)),
        "host_digit_count": sum(char.isdigit() for char in host),
        "host_hyphen_count": host.count("-"),
        "path_length": len(parsed.path or ""),
    }
