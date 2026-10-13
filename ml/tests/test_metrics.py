import numpy as np
import pytest

from ml.src.threatgraph_ml.metrics import precision_at_budget


def test_cutoff_ties_do_not_depend_on_source_row_order():
    labels = np.array([1, 1, 0, 0])
    scores = np.ones(4)
    assert precision_at_budget(labels, scores, 1) == 0.5
    assert precision_at_budget(labels[::-1], scores, 1) == 0.5


def test_only_cutoff_tie_is_averaged():
    assert precision_at_budget([1, 1, 0, 0], [1, .5, .5, 0], 2) == pytest.approx(.75)
