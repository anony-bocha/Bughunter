from __future__ import annotations

import json

from bughunter.audit import AuditLog


def test_audit_chain_verifies(tmp_path):
    path = tmp_path / "run.jsonl"
    log = AuditLog(path, "run-1", {"program": "Test"})
    log.record({"event": "phase", "phase": "one"})
    log.record({"event": "request_denied", "reason": "out of scope"})
    log.close()
    ok, message = AuditLog.verify(path)
    assert ok
    assert "3 record" in message


def test_audit_chain_detects_edit(tmp_path):
    path = tmp_path / "run.jsonl"
    log = AuditLog(path, "run-1")
    log.record({"event": "one", "value": 1})
    log.record({"event": "two", "value": 2})
    log.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["value"] = 999
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, message = AuditLog.verify(path)
    assert not ok
    assert "hash mismatch" in message


def test_audit_chain_detects_missing_record(tmp_path):
    path = tmp_path / "run.jsonl"
    log = AuditLog(path, "run-1")
    log.record({"event": "one"})
    log.record({"event": "two"})
    log.record({"event": "three"})
    log.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")

    ok, message = AuditLog.verify(path)
    assert not ok
    assert "prev" in message or "sequence" in message
