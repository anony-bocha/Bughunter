from __future__ import annotations

import json

from bughunter.models import Confidence, Observation, Severity, Signal
from bughunter.policy import load_policy
from bughunter.report import build_report, render_markdown, write_reports
from bughunter.store import Store


def _seed_run(tmp_path, passive_policy_path):
    policy = load_policy(passive_policy_path)
    store = Store(tmp_path)
    store.create_run(
        "run-test",
        program=policy.program_name,
        policy_path=str(policy.path),
        policy_sha256=policy.sha256,
        policy_json=policy.to_dict(),
        mode=policy.mode,
        options={"passive_only": True},
    )
    store.upsert_asset(
        "run-test",
        {
            "host": "api.example.com",
            "source": "crt.sh",
            "ips": ["93.184.216.34"],
            "cname": "",
            "url": "https://api.example.com/?token=SECRETQUERY",
            "http_status": 200,
            "title": "API",
            "server": "nginx",
            "tech": ["nginx"],
        },
    )
    store.add_observation(
        "run-test",
        Observation(kind="dns", asset="api.example.com", key="resolve", value={"ips": ["93.184.216.34"]}),
    )
    confirmed = Signal(
        title="Exposed Git metadata on api.example.com",
        bug_class="exposed_file",
        asset="api.example.com",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        rationale="Git metadata was returned.",
        next_step="Verify manually.",
        evidence={"url": "https://api.example.com/.git/HEAD", "status": 200},
        source="exposed-file",
    )
    lead = Signal(
        title="Interesting subdomain naming: api.example.com",
        bug_class="interesting_subdomain",
        asset="api.example.com",
        severity=Severity.INFO,
        confidence=Confidence.POSSIBLE,
        rationale="API surface.",
        next_step="Review authorization.",
        evidence={"host": "api.example.com"},
    )
    store.upsert_hypothesis("run-test", confirmed.to_hypothesis())
    store.upsert_hypothesis("run-test", lead.to_hypothesis())
    store.add_request(
        "run-test",
        method="GET",
        url="https://api.example.com/",
        host="api.example.com",
        purpose="root",
        decision="allowed",
        status_code=200,
        elapsed_ms=10,
        bytes_read=100,
    )
    store.add_request(
        "run-test",
        method="GET",
        url="https://evil.test/",
        host="evil.test",
        purpose="root",
        decision="denied",
        reason="out of scope",
    )
    store.finish_run(
        "run-test",
        "completed",
        {"coverage": {"audit_path": "audit.jsonl", "database_path": "db.sqlite"}},
    )
    return store, policy


def test_report_building_and_markdown(tmp_path, passive_policy_path):
    store, _ = _seed_run(tmp_path, passive_policy_path)
    data = build_report(store, "run-test")
    assert data["summary"]["confirmed"] == 1
    assert data["summary"]["leads"] == 1
    assert data["summary"]["requests"] == 2
    assert data["summary"]["requests_denied"] == 1
    assert data["findings"][0]["bug_class"] == "exposed_file"
    assert data["assets"][0]["url"] == "https://api.example.com/"
    markdown = render_markdown(data)
    assert "Bughunter report" in markdown
    assert "Exposed Git metadata" in markdown
    assert "Leads requiring manual review" in markdown
    assert "Not tested" in markdown
    assert "SECRETQUERY" not in json.dumps(data)
    assert "SECRETQUERY" not in markdown
    paths = write_reports(data, tmp_path / "reports")
    assert (tmp_path / "reports" / "run-test.md").exists()
    assert "Exposed Git metadata" in (tmp_path / "reports" / "run-test.md").read_text(encoding="utf-8")
    assert paths["paths"]["json"].endswith("run-test.json")
    store.close()


def test_store_dedupe_and_stats(tmp_path, passive_policy_path):
    store, _ = _seed_run(tmp_path, passive_policy_path)
    hypotheses = store.hypotheses("run-test")
    assert len(hypotheses) == 2
    stats = store.hypothesis_stats("run-test")
    assert stats["confirmed"] == 1
    assert stats["lead"] == 1
    assert store.request_stats("run-test")["total"] == 2
    summary = store.summary("run-test")
    assert summary["assets"] == 1
    store.close()
