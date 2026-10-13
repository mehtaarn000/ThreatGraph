from ml.src.threatgraph_ml.brand_features import extract_brand_features


def test_brand_features_detect_name_similarity_without_calling_it_official():
    features = extract_brand_features(
        "https://northstar-login.example/sign-in",
        brand_name="Northstar Bank",
        brand_domain="northstar.example",
    )

    assert features["brand_token_present"] == 1
    assert features["brand_in_host_substring"] == 1
    assert features["brand_host_edit_similarity"] > 0.5
    assert features["official_brand_domain_or_subdomain"] == 0
    assert features["uses_https"] == 1


def test_official_domain_match_includes_subdomains_but_not_lookalikes():
    official = extract_brand_features(
        "https://accounts.northstar.example/",
        "Northstar Bank",
        "www.northstar.example",
    )
    lookalike = extract_brand_features(
        "https://northstar.example.attacker.test/",
        "Northstar Bank",
        "northstar.example",
    )

    assert official["official_brand_domain_or_subdomain"] == 1
    assert lookalike["official_brand_domain_or_subdomain"] == 0


def test_brand_token_in_path_is_separate_from_host_match():
    features = extract_brand_features(
        "https://unrelated.example/northstar/login",
        "Northstar Bank",
        "northstar.example",
    )

    assert features["brand_token_in_path"] == 1
    assert features["brand_token_present"] == 0


def test_punycode_host_is_flagged():
    features = extract_brand_features(
        "https://xn--e1afmkfd.example/",
        "Northstar Bank",
        "northstar.example",
    )

    assert features["has_punycode_label"] == 1
