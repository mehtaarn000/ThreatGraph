"""Deterministic URL-only lexical features and model pipelines."""

import ipaddress
import re
from urllib.parse import urlsplit

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import VarianceThreshold
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler


SUSPICIOUS_TERMS = (
    "account", "auth", "bank", "confirm", "login", "password", "secure",
    "signin", "update", "verify", "wallet", "webscr",
)
OBFUSCATION_CHARS = re.compile(r"[%@]|\\x[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;|xn--")
LEXICAL_FEATURE_NAMES = (
    "url_length", "host_length", "path_length", "query_length", "dot_count",
    "hyphen_count", "underscore_count", "at_count", "percent_count",
    "slash_count", "question_count", "equals_count", "ampersand_count",
    "host_label_count", "subdomain_depth_estimate", "digit_count", "letter_count",
    "special_count", "digit_ratio", "special_ratio", "character_diversity",
    "uses_https", "uses_http", "has_userinfo", "port_present", "host_is_ip",
    "has_punycode", "obfuscation_marker_count", "suspicious_term_count",
)


def _split_url(value: str):
    text = str(value).strip()
    parsed = urlsplit(text if "://" in text else "//" + text)
    return text, parsed


def _is_ip(host: str) -> int:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return 1
    except ValueError:
        return 0


def lexical_vector(urls):
    """Return stable numeric URL features without fetching the target URL."""
    columns = []
    for raw in urls:
        text, parsed = _split_url(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        host_labels = [part for part in host.split(".") if part]
        digits = sum(char.isdigit() for char in text)
        letters = sum(char.isalpha() for char in text)
        special = sum(not char.isalnum() for char in text)
        lower_text = text.lower()
        term_count = sum(term in lower_text for term in SUSPICIOUS_TERMS)
        try:
            port_present = int(parsed.port is not None)
        except ValueError:
            port_present = 1

        columns.append([
            len(text), len(host), len(parsed.path or ""), len(parsed.query),
            text.count("."), text.count("-"), text.count("_"), text.count("@"),
            text.count("%"), text.count("/"), text.count("?"), text.count("="),
            text.count("&"), len(host_labels), max(0, len(host_labels) - 2),
            digits, letters, special, digits / max(1, len(text)),
            special / max(1, len(text)), len(set(text)) / max(1, len(text)),
            int(parsed.scheme.lower() == "https"), int(parsed.scheme.lower() == "http"),
            int(bool(parsed.username or parsed.password)), port_present,
            _is_ip(host), int("xn--" in host), len(OBFUSCATION_CHARS.findall(text)),
            term_count,
        ])
    return np.asarray(columns, dtype=np.float32).reshape((-1, len(LEXICAL_FEATURE_NAMES)))


class LexicalFeatures(BaseEstimator, TransformerMixin):
    """scikit-learn transformer for URL lexical features."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        values = X.iloc[:, 0].tolist() if hasattr(X, "iloc") else list(X)
        return sparse.csr_matrix(lexical_vector(values))


def make_pipeline(include_char_ngrams: bool = True) -> Pipeline:
    branches = [("lexical", Pipeline([
        ("extract", LexicalFeatures()),
        ("scale", StandardScaler(with_mean=False)),
    ]))]
    if include_char_ngrams:
        branches.append(("char_ngrams", TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            min_df=2,
            max_features=50000,
            sublinear_tf=True,
            dtype=np.float32,
            lowercase=True,
        )))
    transformer_weights = {name: 1.0 for name, _ in branches}

    return Pipeline([
        ("features", FeatureUnion(branches, transformer_weights=transformer_weights)),
        ("nonconstant", VarianceThreshold(threshold=0.0)),
        ("classifier", LogisticRegression(
            class_weight="balanced",
            max_iter=300,
            solver="liblinear",
            random_state=42,
        )),
    ])
