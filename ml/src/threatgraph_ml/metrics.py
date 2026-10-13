"""Ranking metrics with an explicit policy for tied alert scores."""

import numpy as np


def precision_at_budget(y_true, scores, budget):
    """Expected precision when the cutoff tie is selected uniformly at random."""
    y_true = np.asarray(y_true)
    scores = np.asarray(scores)
    if len(scores) != len(y_true) or not 1 <= budget <= len(scores):
        raise ValueError("Budget must be within the nonempty paired score array.")
    cutoff = np.partition(scores, len(scores) - budget)[len(scores) - budget]
    above = scores > cutoff
    tied = scores == cutoff
    remaining = budget - int(above.sum())
    return float((y_true[above].sum() + remaining * y_true[tied].mean()) / budget)
