from __future__ import annotations

import httpx
import pytest
import yaml

from bughunter.audit import AuditLog
from bughunter.dnsutil import DnsInfo
from bughunter.errors import PolicyDenied
from bughunter.net import Capture, GatedSession
from bughunter.policy import load_policy
from bughunter.store import Store


class FakeResolver:
    def __init__(self, ips=("93.184.216.34",)):
        self.ips = ips
        self.calls = 0

    def resolve(self, host, *, use_cache=True):
        self.calls += 1
        return DnsInfo(host=host, a=tuple(self.ips))


def _make_session(tmp_path, policy_path, handler, *, resolver=None, max_total=None):
    policy = load_policy(policy_path)
    store = Store(tmp_path / "state")
    store.create_run(
        "run-net",
        program=policy.program_name,
        policy_path=str(policy.path),
        policy_sha256=policy.sha256,
        policy_json=policy.to_dict(),
        mode=policy.mode,
    )
    audit = AuditLog(tmp_path / "audit.jsonl", "run-net")
    session = GatedSession(
        policy,
        store,
        audit,
        "run-net",
        resolver=resolver or FakeResolver(),
        transport=httpx.MockTransport(handler),
        sleeper=lambda _: None,
        max_total_requests=max_total,
    )
    return session, store, audit


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/redirect":
        return httpx.Response(302, headers={"location": "https://evil.test/"})
    if request.url.path == "/":
        return httpx.Response(
            200,
            text="<html><title>Home</title></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax",
                "server": "nginx/1.25.1",
            },
        )
    return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})


def test_allowed_request_and_audit(tmp_path, active_policy_path):
    session, store, audit = _make_session(tmp_path, active_policy_path, _handler)
    result = session.request("GET", "https://target.test/", purpose="root", capture=Capture.TEXT)
    assert result.status == 200
    assert "Home" in (result.text or "")
    assert result.set_cookies()
    stats = store.request_stats("run-net")
    assert stats["total"] == 1
    assert stats["by_decision"]["allowed"] == 1
    assert session.stats["requests_allowed"] == 1
    session.close()
    audit.close()
    store.close()


def test_out_of_scope_request_is_never_sent(tmp_path, active_policy_path):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return _handler(request)

    session, store, audit = _make_session(tmp_path, active_policy_path, handler)
    with pytest.raises(PolicyDenied):
        session.request("GET", "https://evil.test/", purpose="root")
    assert calls == []
    assert store.request_stats("run-net")["by_decision"]["denied"] == 1
    session.close()
    audit.close()
    store.close()


def test_redirect_is_rechecked_and_blocked(tmp_path, active_policy_path):
    session, store, audit = _make_session(tmp_path, active_policy_path, _handler)
    result = session.request("GET", "https://target.test/redirect", purpose="root")
    assert result.blocked
    assert "out of scope" in result.block_reason or "matches no scope" in result.block_reason
    stats = store.request_stats("run-net")
    assert stats["total"] == 2
    assert stats["by_decision"].get("denied") == 1
    session.close()
    audit.close()
    store.close()


def test_forbidden_path_and_private_dns(tmp_path, active_policy_path):
    session, store, audit = _make_session(tmp_path, active_policy_path, _handler)
    with pytest.raises(PolicyDenied):
        session.request("GET", "https://target.test/logout", purpose="root")
    session.close()
    audit.close()
    store.close()

    private_session, private_store, private_audit = _make_session(
        tmp_path / "private",
        active_policy_path,
        _handler,
        resolver=FakeResolver(("127.0.0.1",)),
    )
    with pytest.raises(PolicyDenied) as exc:
        private_session.request("GET", "https://target.test/", purpose="root")
    assert "non-public" in str(exc.value)
    private_session.close()
    private_audit.close()
    private_store.close()


def test_request_budget(tmp_path, active_policy_path):
    session, store, audit = _make_session(tmp_path, active_policy_path, _handler, max_total=1)
    first = session.request("GET", "https://target.test/", purpose="root")
    assert first.status == 200
    with pytest.raises(PolicyDenied) as exc:
        session.request("GET", "https://target.test/other", purpose="crawl")
    assert "budget" in str(exc.value)
    assert session.budget_exhausted
    session.close()
    audit.close()
    store.close()


def test_method_allowlist(tmp_path, active_policy_path):
    session, store, audit = _make_session(tmp_path, active_policy_path, _handler)
    with pytest.raises(PolicyDenied) as exc:
        session.request("DELETE", "https://target.test/", purpose="root")
    assert "not allowed" in str(exc.value)
    session.close()
    audit.close()
    store.close()


def test_robots_txt_is_respected(tmp_path, active_policy_path):
    data = yaml.safe_load(active_policy_path.read_text(encoding="utf-8"))
    data["rules"]["respect_robots_txt"] = True
    policy_path = tmp_path / "robots-policy.yaml"
    policy_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    def handler(request):
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /secret\n")
        return httpx.Response(200, text="ok")

    session, store, audit = _make_session(tmp_path, policy_path, handler)
    assert session.request("GET", "https://target.test/", purpose="root").status == 200
    with pytest.raises(PolicyDenied) as exc:
        session.request("GET", "https://target.test/secret", purpose="crawl")
    assert "robots.txt" in str(exc.value)
    session.close()
    audit.close()
    store.close()
