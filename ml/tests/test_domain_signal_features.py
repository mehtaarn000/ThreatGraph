"""Regression tests for the added domain signals, using synthetic inputs."""
import math

import pytest

from ml.src.threatgraph_ml.brand_features import NEW_FEATURE_NAMES, extract_brand_features


@pytest.mark.parametrize("host, expected", [
    ("", 0.0), ("aaaa", 0.0), ("abab", 1.0), ("abcd", 2.0),
    ("aaab", -(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25))),
])
def test_entropy_matches_known_distributions(host, expected):
    features = extract_brand_features(host, "Acme", "acme.test")
    assert features["host_shannon_entropy"] == pytest.approx(expected)


@pytest.mark.parametrize("candidate, expected_host", [
    ("https://WWW.AB.AB./login?token=zzzz", "abab"),
    ("https://bbaa", "abab"),
    ("https://a-1a", "a-1a"),
])
def test_entropy_uses_only_normalized_hostname_characters(candidate, expected_host):
    result = extract_brand_features(candidate, "Acme", "acme.test")
    probabilities = [expected_host.count(c) / len(expected_host) for c in set(expected_host)]
    expected = -sum(p * math.log2(p) for p in probabilities)
    assert result["host_shannon_entropy"] == pytest.approx(expected)


@pytest.mark.parametrize("candidate, edit, dice", [
    ("https://acme.test", 1.0, 1.0),
    ("https://acmf.test", 8 / 9, 0.75),
    ("https://zzzz.zzzz", 1 / 9, 0.0),
])
def test_direct_domain_similarity_has_known_values(candidate, edit, dice):
    # Deliberately unrelated display name: these compare to the official domain.
    result = extract_brand_features(candidate, "Unrelated display name", "acme.test")
    assert result["official_domain_edit_similarity"] == pytest.approx(edit)
    assert result["official_domain_bigram_dice"] == pytest.approx(dice)
