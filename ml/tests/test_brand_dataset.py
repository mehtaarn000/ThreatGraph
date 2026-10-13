import pandas as pd
import pytest

from ml.src.threatgraph_ml.brand_dataset import build_training_table, load_reviewed_labels


def _row(example_id, candidate_domain, label, **overrides):
    row = {
        "example_id": example_id,
        "candidate_url": "",
        "candidate_domain": candidate_domain,
        "brand_id": "northstar",
        "brand_name": "Northstar Bank",
        "brand_domain": "northstar.example",
        "label": label,
        "source_name": "analyst_review",
        "source_record_id": "",
        "observed_at": "2026-10-01T12:00:00Z",
        "reviewed_at": "2026-10-02T12:00:00Z",
        "reviewer_id": "reviewer-1",
        "evidence_refs": "case-123",
        "campaign_id": "",
    }
    row.update(overrides)
    return row


def _write_labels(path, rows):
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_load_reviewed_labels_normalizes_domains_and_keeps_unknown(tmp_path):
    path = _write_labels(tmp_path / "labels.csv", [
        _row("a", "HTTPS://NORTHSTAR-LOGIN.EXAMPLE./path", "CONFIRMED_IMPERSONATION"),
        _row("b", "community.example", "unknown"),
    ])

    frame = load_reviewed_labels(path)

    assert frame["candidate_domain"].tolist() == ["northstar-login.example", "community.example"]
    assert frame["is_trainable"].tolist() == [True, False]


def test_load_reviewed_labels_rejects_unknown_label_value(tmp_path):
    path = _write_labels(tmp_path / "labels.csv", [_row("a", "bad.example", "phishing")])

    with pytest.raises(ValueError, match="Unsupported labels"):
        load_reviewed_labels(path)


def test_load_reviewed_labels_rejects_conflicting_pair_decisions(tmp_path):
    path = _write_labels(tmp_path / "labels.csv", [
        _row("a", "northstar-login.example", "confirmed_impersonation"),
        _row("b", "NORTHSTAR-LOGIN.EXAMPLE.", "confirmed_not_impersonation"),
    ])

    with pytest.raises(ValueError, match="Conflicting labels"):
        load_reviewed_labels(path)


def test_build_training_table_excludes_unknown_and_maps_binary_target(tmp_path):
    path = _write_labels(tmp_path / "labels.csv", [
        _row("a", "northstar-login.example", "confirmed_impersonation"),
        _row("b", "community.example", "confirmed_not_impersonation"),
        _row("c", "northstar-portal.example", "unknown"),
    ])
    frame = load_reviewed_labels(path)

    training = build_training_table(frame)

    assert training["example_id"].tolist() == ["a", "b"]
    assert training["target"].tolist() == [1, 0]
    assert "brand_host_edit_similarity" in training.columns


def test_build_training_table_requires_confirmed_examples(tmp_path):
    path = _write_labels(tmp_path / "labels.csv", [_row("a", "maybe.example", "unknown")])

    with pytest.raises(ValueError, match="No confirmed domain–brand labels"):
        build_training_table(load_reviewed_labels(path))
