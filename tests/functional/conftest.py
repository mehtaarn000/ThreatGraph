"""Opt-in real-service fixtures; never connect to a user-provided database."""

import os
from pathlib import Path
import shutil

import joblib
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ml.src.threatgraph_ml.brand_features import extract_brand_features
from ml.src.threatgraph_ml.dns_features import extract_dns_features
from .stack import ROOT, Stack, command
from .dns_fixture import DNSFixture


def pytest_collection_modifyitems(items):
    if os.environ.get("THREATGRAPH_RUN_STACK_TESTS") != "1":
        for item in items:
            if Path(__file__).parent in Path(str(item.fspath)).parents:
                item.add_marker(pytest.mark.skip(reason="Set THREATGRAPH_RUN_STACK_TESTS=1 to launch local services"))


@pytest.fixture(scope="session")
def stack_artifacts(tmp_path_factory):
    directory = tmp_path_factory.mktemp("stack-build")
    go = os.environ.get("GO_BIN") or shutil.which("go")
    if not go:
        pytest.fail("Install Go or set GO_BIN to the Go executable")
    binary = directory / "threatgraph-api"
    command([go, "build", "-race", "-o", binary, "./cmd/api"], cwd=ROOT / "backend")
    urls = ["https://acme-login.test", "https://acme-verify.test",
            "https://acme.example", "https://weather.example"]
    features = pd.DataFrame([extract_brand_features(url, "Acme", "acme.example") for url in urls])
    model = make_pipeline(StandardScaler(), LogisticRegression(random_state=42)).fit(features, [1, 1, 0, 0])
    model_path = directory / "synthetic-model.joblib"
    joblib.dump({"model": model, "feature_names": list(features.columns)}, model_path)
    dns_features = pd.DataFrame([extract_dns_features(domain, {
        "A": ["192.0.2.10"], "AAAA": [], "NS": ["ns.fixture.test"],
        "MX": [{"value": "mail.fixture.test", "preference": i * 10}],
    }) for i, domain in enumerate(("login-verify.test", "account-update.test", "weather.test", "example.test"))])
    dns_model = make_pipeline(SimpleImputer(keep_empty_features=True), StandardScaler(),
                              LogisticRegression(random_state=42)).fit(dns_features, [1, 1, 0, 0])
    dns_path = directory / "synthetic-dns-model.joblib"
    joblib.dump({"model": dns_model, "feature_names": list(dns_features.columns),
                 "schema_version": 1, "task": "generic_domain_phishing", "threshold": .5,
                 "model_name": "synthetic_dns", "score_semantics": "Uncalibrated experimental score"}, dns_path)
    return binary, model_path, dns_path


@pytest.fixture
def dns_fixture():
    server = DNSFixture()
    server.start()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def stack(tmp_path, stack_artifacts, dns_fixture):
    binary, model, dns_model = stack_artifacts
    services = Stack(tmp_path, binary, model)
    services.dns_model = dns_model
    services.dns_server = dns_fixture.address
    try:
        services.start()
        yield services
    finally:
        services.close()
