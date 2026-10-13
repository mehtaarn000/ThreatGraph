import json

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.dummy import DummyClassifier

from ml.src.threatgraph_ml.domainradar_data import records_in_window, window_plan
from ml.src.threatgraph_ml.dns_features import extract_dns_features, from_domainradar, from_snapshot
from ml.src.threatgraph_ml.score_dns import load_model, score_snapshot
from ml.src.threatgraph_ml.train_dns import make_split, training_table


def snapshot():
    return {"domain": "example.com", "queries": [
        {"type": "A", "status": "ok", "records": [{"value": "192.0.2.1"}]},
        {"type": "AAAA", "status": "no_records", "records": []},
        {"type": "NS", "status": "ok", "records": [{"value": "ns.example.com."}]},
        {"type": "MX", "status": "ok", "records": [{"value": "mail.example.com", "preference": 10}]},
    ]}


def test_historical_and_live_features_match():
    historical = {"dns": {"A": ["192.0.2.1"], "AAAA": None,
                          "NS": {"ns.example.com": {}}, "MX": {"mail.example.com": {"priority": 10}}}}
    assert extract_dns_features("example.com", from_domainradar(historical)) == extract_dns_features("example.com", from_snapshot(snapshot()))


def test_timeout_is_unknown_not_zero_records():
    value = snapshot()
    value["queries"][0]["status"] = "timeout"
    features = extract_dns_features("example.com", from_snapshot(value))
    assert features["dns_a_missing"] == 1
    assert np.isnan(features["dns_a_count"])
    assert features["dns_aaaa_missing"] == 0
    assert features["dns_aaaa_count"] == 0


def test_null_mx_and_duplicate_addresses():
    dns = {"A": ["192.0.2.1", "192.0.2.1", "192.0.2.2"], "MX": [{"value": ".", "preference": 0}]}
    features = extract_dns_features("example.com", dns)
    assert features["dns_a_count"] == 2
    assert features["dns_a_prefix_count"] == 1
    assert features["dns_null_mx"] == 1
    assert features["dns_mx_mean_length"] == 0


def test_invalid_ip_family_rejected():
    with pytest.raises(ValueError, match="IP family"):
        extract_dns_features("example.com", {"A": ["2001:db8::1"]})


def test_duplicate_query_rejected():
    value = snapshot()
    value["queries"].append(value["queries"][0])
    with pytest.raises(ValueError, match="Duplicate"):
        from_snapshot(value)


def test_windows_deterministic_disjoint_and_bounded():
    plan = list(window_plan(10000000, .1, 65536, 42))
    assert plan == list(window_plan(10000000, .1, 65536, 42))
    assert all(0 <= start <= end < 10000000 for start, end in plan)
    assert all(left[1] < right[0] for left, right in zip(plan, plan[1:]))


def test_partial_boundary_records_are_not_parsed():
    complete = {"_id": {"$oid": "abc"}, "domain_name": "example.com"}
    data = b'partial tail }, ' + json.dumps(complete).encode() + b', {"_id":{"$oid":"cut"},"domain_name":'
    assert list(records_in_window(data)) == [complete]


def split_frame():
    return pd.DataFrame({"group": [f"g{i}" for i in range(100)], "target": [i % 2 for i in range(100)],
                         "observed_at": pd.date_range("2024-01-01", periods=100, tz="UTC"),
                         "source_file": "fixture"})


def test_temporal_split_preserves_order_and_purges_related_hosts():
    frame = split_frame()
    frame.loc[0, "group"] = frame.loc[99, "group"]
    split, audit = make_split(frame, min_class_count=2)
    assert audit["strategy"].startswith("chronological")
    assert 0 not in np.concatenate(list(split.values()))
    assert frame.iloc[split["train"]].observed_at.max() < frame.iloc[split["validation"]].observed_at.min()
    assert frame.iloc[split["validation"]].observed_at.max() < frame.iloc[split["test"]].observed_at.min()
    groups = [set(frame.iloc[split[name]].group) for name in ("train", "validation", "test")]
    assert not groups[0] & groups[1] and not groups[0] & groups[2] and not groups[1] & groups[2]


def test_single_class_time_periods_trigger_explicit_grouped_fallback():
    frame = split_frame()
    frame["target"] = [0] * 50 + [1] * 50
    _, audit = make_split(frame, min_class_count=2)
    assert audit["strategy"] == "registrable_domain_grouped_60_20_20"
    assert audit["temporal_fallback_reason"]


def test_conflicting_labels_quarantined(tmp_path):
    rows = [{"domain_name": domain, "target": label, "source_file": "fixture", "source_record_id": str(i),
             "evaluated_on": {"$date": "2024-01-01T00:00:00Z"}}
            for i, (domain, label) in enumerate([("a.example.com", 0), ("a.example.com", 1), ("other.example.com", 0)])]
    path = tmp_path / "sample.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows))
    frame, audit = training_table(path)
    assert list(frame.domain) == ["other.example.com"]
    assert audit["conflicting_label_rows"] == 2


def test_serialized_model_scores_api_response(tmp_path):
    model = DummyClassifier(strategy="prior").fit(pd.DataFrame({"dns_a_count": [1, 2]}), [0, 1])
    bundle = {"schema_version": 1, "task": "generic_domain_phishing", "feature_names": ["dns_a_count"],
              "model": model, "threshold": .6, "model_name": "fixture", "score_semantics": "uncalibrated"}
    path = tmp_path / "model.joblib"
    joblib.dump(bundle, path)
    prediction = score_snapshot(load_model(path), {"snapshot": snapshot(), "cached": True})
    assert prediction["generic_phishing_score"] == .5
    assert not prediction["flagged"]
    assert prediction["unknown_record_types"] == []
    bundle["schema_version"] = 999
    joblib.dump(bundle, path)
    with pytest.raises(ValueError, match="Incompatible"):
        load_model(path)
