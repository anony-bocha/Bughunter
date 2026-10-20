from __future__ import annotations

import json

from bughunter.analyze.hypotheses import (
    HypothesisEngine,
    archive_param_signal,
    endpoint_signal,
    subdomain_signal,
)
from bughunter.analyze.secrets import extract_intel, interesting_path, scan_text
from bughunter.models import Confidence, Severity, Signal
from bughunter.store import Store


def test_secret_detection_and_redaction():
    text = (
        'aws = "AKIA1234567890ABCDEF"\n'
        'const key = "-----BEGIN RSA PRIVATE KEY-----";\n'
        'api_key = "aB3dE5fG7hJ9kL2mN4pQ6rS8";\n'
        'placeholder = "AKIAIOSFODNN7EXAMPLE";\n'
        'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABC123";\n'
    )
    hits = scan_text(text, "https://example.com/app.js")
    kinds = {hit.kind for hit in hits}
    assert "aws_access_key" in kinds
    assert "private_key" in kinds
    assert "generic_secret" in kinds
    assert "jwt" in kinds
    assert all("AKIA1234567890ABCDEF" not in hit.redacted for hit in hits)
    assert all("AKIA1234567890ABCDEF" not in hit.context for hit in hits)
    assert all("aB3dE5fG7hJ9kL2mN4pQ6rS8" not in hit.context for hit in hits)


def test_placeholder_secret_ignored():
    hits = scan_text('const key = "AKIAIOSFODNN7EXAMPLE";', "https://example.com/app.js")
    assert not any(hit.kind == "aws_access_key" for hit in hits)


def test_js_intel_extraction():
    text = """
    const a = fetch("/api/v1/users");
    const b = "https://my-bucket.s3.amazonaws.com/data.json";
    const c = "https://example.com/graphql";
    //# sourceMappingURL=app.abc.js.map
    const token = "AKIA1234567890ABCDEF";
    """
    intel = extract_intel(text, "https://example.com/static/app.js")
    joined = " ".join(intel.endpoints)
    assert "/api/v1/users" in joined
    assert "https://example.com/graphql" in intel.graphql_endpoints
    assert any(ref.identifier == "my-bucket" for ref in intel.cloud_references)
    assert any("app.abc.js.map" in url for url in intel.source_maps)
    assert any(hit.kind == "aws_access_key" for hit in intel.secret_hits)
    assert interesting_path("/api/v1/users")
    assert not interesting_path("/static/app.js")


def test_hypothesis_signals():
    subdomain = subdomain_signal("admin.example.com", ("example.com",))
    assert subdomain is not None
    assert "admin" in subdomain.title.lower() or "administrative" in subdomain.rationale.lower()
    assert subdomain_signal("www.example.com", ("example.com",)) is None

    archive = archive_param_signal(
        "example.com",
        ["https://example.com/page?token=SECRETVALUE&redirect=https://evil.test"],
    )
    assert archive is not None
    assert "token" in archive.evidence["parameters"]
    assert "SECRETVALUE" not in json.dumps(archive.evidence)
    assert "[REDACTED]" in json.dumps(archive.evidence)

    endpoint = endpoint_signal("https://example.com/api/v1/users", "example.com")
    assert endpoint.bug_class == "sensitive_endpoint"


def test_engine_dedupes_and_upgrades(tmp_path):
    store = Store(tmp_path)
    store.create_run(
        "run-1",
        program="Test",
        policy_path="policy.yaml",
        policy_sha256="x",
        policy_json={"program": {"name": "Test"}},
        mode="passive",
    )
    engine = HypothesisEngine(store, "run-1")
    lead = Signal(
        title="Lead",
        bug_class="test",
        asset="example.com",
        severity=Severity.MEDIUM,
        confidence=Confidence.POSSIBLE,
        rationale="r",
        next_step="n",
        dedupe_key="same",
        evidence={"a": 1},
    )
    assert engine.emit(lead) is not None
    assert engine.emit(lead) is None
    confirmed = Signal(
        title="Confirmed",
        bug_class="test",
        asset="example.com",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        rationale="r",
        next_step="n",
        dedupe_key="same",
        evidence={"b": 2},
    )
    assert engine.emit(confirmed) is not None
    hypotheses = store.hypotheses("run-1")
    assert len(hypotheses) == 1
    assert hypotheses[0]["status"] == "confirmed"
    assert hypotheses[0]["evidence"] == {"a": 1, "b": 2}
    store.close()
