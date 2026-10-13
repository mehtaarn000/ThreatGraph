import numpy as np

from ml.src.threatgraph_ml.features import LEXICAL_FEATURE_NAMES, lexical_vector


def test_lexical_vector_extracts_ip_and_url_structure():
    vector = lexical_vector(["http://192.0.2.10/login?account=1"])

    assert vector.shape == (1, len(LEXICAL_FEATURE_NAMES))
    assert np.isfinite(vector).all()
    assert vector[0, LEXICAL_FEATURE_NAMES.index("host_is_ip")] == 1
    assert vector[0, LEXICAL_FEATURE_NAMES.index("uses_http")] == 1
    assert vector[0, LEXICAL_FEATURE_NAMES.index("suspicious_term_count")] >= 1


def test_lexical_vector_handles_urls_without_scheme():
    vector = lexical_vector(["example.test/path"])

    assert vector.shape == (1, len(LEXICAL_FEATURE_NAMES))
    assert vector[0, LEXICAL_FEATURE_NAMES.index("host_length")] == len("example.test")
    assert vector[0, LEXICAL_FEATURE_NAMES.index("uses_https")] == 0


def test_lexical_vector_empty_input_has_two_dimensional_shape():
    assert lexical_vector([]).shape == (0, len(LEXICAL_FEATURE_NAMES))
