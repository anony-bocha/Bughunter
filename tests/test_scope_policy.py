from __future__ import annotations

import copy
import textwrap

import pytest
import yaml

from bughunter.errors import AuthorizationError, PolicyError
from bughunter.policy import load_policy
from bughunter.scope import check_host, check_target, check_url, match_host_pattern


def test_scope_matching_semantics(passive_policy_path):
    policy = load_policy(passive_policy_path)
    assert match_host_pattern("example.com", "example.com")
    assert match_host_pattern("example.com", "api.example.com")
    assert not match_host_pattern("example.com", "notexample.com")
    assert match_host_pattern("*.example.org", "api.example.org")
    assert not match_host_pattern("*.example.org", "example.org")


def test_url_scope_checks(passive_policy_path):
    policy = load_policy(passive_policy_path)
    assert check_url(policy, "https://example.com/").allowed
    assert check_url(policy, "https://deep.api.example.com/").allowed
    assert check_url(policy, "https://api.example.org/").allowed
    assert not check_url(policy, "https://example.org/").allowed  # wildcard excludes apex
    assert not check_url(policy, "https://old.example.com/").allowed
    assert not check_url(policy, "https://admin.internal.example.org/").allowed
    assert not check_url(policy, "https://notexample.com/").allowed
    assert not check_url(policy, "http://example.com:8080/").allowed
    assert not check_url(policy, "ftp://example.com/").allowed
    assert not check_url(policy, "https://user:pass@example.com/").allowed
    assert not check_url(policy, "https://example.com/", method="POST").allowed
    assert not check_url(policy, "https://example.com/logout").allowed
    assert not check_url(policy, "https://example.com/%6Cogout").allowed
    assert not check_url(policy, "https://example.com/../delete").allowed
    assert not check_url(policy, "http://127.0.0.1/").allowed


def test_host_checks(passive_policy_path):
    policy = load_policy(passive_policy_path)
    assert check_host(policy, "example.com").allowed
    assert check_host(policy, "deep.example.com").allowed
    assert not check_host(policy, "old.example.com").allowed
    assert not check_host(policy, "example.net").allowed
    assert not check_host(policy, "127.0.0.1").allowed
    assert not check_host(policy, "example.com", port=8443).allowed


def test_scope_command_targets(passive_policy_path):
    policy = load_policy(passive_policy_path)
    assert check_target(policy, "https://api.example.com").allowed
    assert check_target(policy, "api.example.com").allowed
    assert not check_target(policy, "https://api.example.com:8080").allowed


def _policy_data(confirmed: bool = True, **rule_overrides):
    data = {
        "program": {
            "name": "Unit Test",
            "contact": "security@unit.test",
            "authorization": {
                "confirmed": confirmed,
                "authorized_by": "Unit Test" if confirmed else "",
                "date": "2026-10-20",
            },
        },
        "scope": {"domains": ["unit.test"], "exclusions": [], "ip_ranges": []},
        "rules": {
            "mode": "passive",
            "allowed_methods": ["GET", "HEAD"],
            "allowed_ports": [80, 443],
            "max_requests_per_host_per_minute": 20,
            "max_total_requests": 100,
            "max_runtime_seconds": 300,
            "request_timeout_seconds": 5,
            "max_hosts": 20,
            "respect_robots_txt": True,
            "forbidden_paths": ["/logout*"],
        },
    }
    data["rules"].update(rule_overrides)
    return data


def _write(tmp_path, data):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_policy_authorization_gate(tmp_path):
    data = _policy_data(confirmed=False)
    policy = load_policy(_write(tmp_path, data))
    assert not policy.authorization.confirmed
    with pytest.raises(AuthorizationError):
        policy.assert_authorized()


def test_policy_validation_errors(tmp_path):
    data = _policy_data()
    data["scope"]["domains"] = ["https://unit.test"]
    with pytest.raises(PolicyError):
        load_policy(_write(tmp_path, data))

    data = _policy_data()
    data["rules"]["mode"] = "aggressive"
    with pytest.raises(PolicyError):
        load_policy(_write(tmp_path, data))

    data = _policy_data()
    data["rules"]["allowed_ports"] = [0]
    with pytest.raises(PolicyError):
        load_policy(_write(tmp_path, data))


def test_policy_warnings_and_unknown_keys(tmp_path):
    data = _policy_data()
    data["rules"]["allow_out_of_scope_redirects"] = True
    data["rules"]["unknown_option"] = 1
    policy = load_policy(_write(tmp_path, data))
    joined = " ".join(policy.warnings)
    assert "not honored" in joined
    assert "unknown key" in joined


def test_exclusion_does_not_leak(passive_policy_path):
    policy = load_policy(passive_policy_path)
    decision = check_url(policy, "https://old.example.com/")
    assert not decision.allowed
    assert decision.excluded_rule == "old.example.com"
