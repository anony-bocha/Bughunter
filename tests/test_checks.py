from __future__ import annotations

import json

from bughunter.checks import cors as cors_check
from bughunter.checks import exposed as exposed_check
from bughunter.checks import graphql as graphql_check
from bughunter.checks import headers as header_check
from bughunter.checks import takeover as takeover_check
from bughunter.checks import tls as tls_check
from bughunter.models import Confidence, Signal
from bughunter.net import FetchResult, TLSInfo


class FakeSession:
    def __init__(self, handler):
        self.handler = handler

    def request(self, method, url, **kwargs):
        return self.handler(method, url, **kwargs)


def test_header_and_cookie_signals():
    signals = header_check.evaluate(
        "https://example.com/",
        {"server": "nginx/1.25.1", "x-powered-by": "PHP/8.2"},
        [
            {"name": "JSESSIONID", "secure": False, "httponly": False, "samesite": "", "prefix": "", "path": "/"},
        ],
    )
    classes = {signal.bug_class for signal in signals}
    assert "missing_security_headers" in classes
    assert "cookie_flags" in classes
    assert "version_disclosure" in classes


def test_http_cookie_flags_skip_secure():
    signals = header_check.evaluate(
        "http://example.com/",
        {},
        [{"name": "sid", "secure": False, "httponly": False, "samesite": "", "prefix": "", "path": "/"}],
    )
    cookie = [signal for signal in signals if signal.bug_class == "cookie_flags"]
    assert cookie
    assert "Secure" not in cookie[0].evidence["issue"]
    assert "HttpOnly" in cookie[0].evidence["issue"]


def test_cors_reflection_high():
    def handler(method, url, **kwargs):
        return FetchResult(
            url=url,
            final_url=url,
            method=method,
            status=200,
            headers={
                "access-control-allow-origin": "https://bughunter.invalid",
                "access-control-allow-credentials": "true",
                "vary": "Origin",
            },
        )

    signals = cors_check.probe(FakeSession(handler), ["https://example.com/api/v1/users"])
    assert len(signals) == 1
    assert signals[0].severity.value == "high"
    assert signals[0].confidence.value == "confirmed"
    assert signals[0].bug_class == "cors_misconfiguration"


def test_cors_wildcard_without_credentials_is_ignored():
    def handler(method, url, **kwargs):
        return FetchResult(
            url=url,
            final_url=url,
            method=method,
            status=200,
            headers={"access-control-allow-origin": "*"},
        )

    assert cors_check.probe(FakeSession(handler), ["https://example.com/api"]) == []


def test_exposed_file_signatures_and_spa_fallback():
    def handler(method, url, **kwargs):
        path = url.split("example.com", 1)[1] or "/"
        if path == "/.git/HEAD":
            return FetchResult(url, url, method, status=200, content_type="text/plain", body=b"ref: refs/heads/main\n")
        if path == "/.env":
            return FetchResult(url, url, method, status=200, content_type="text/plain", body=None)
        if path == "/.env.local":
            return FetchResult(url, url, method, status=200, content_type="text/html", body=None)
        if path == "/backup.zip":
            return FetchResult(url, url, method, status=200, content_type="application/zip", body=b"PK\x03\x04rest")
        return FetchResult(url, url, method, status=404, content_type="text/html", body=b"not found")

    signals = exposed_check.check_exposed(FakeSession(handler), "https://example.com/", limit=16)
    classes = {signal.bug_class for signal in signals}
    paths = {signal.evidence["url"].split("example.com", 1)[1] for signal in signals}
    assert "exposed_file" in classes
    assert "/.git/HEAD" in paths
    assert "/.env" in paths
    assert "/backup.zip" in paths
    assert "/.env.local" not in paths


def test_takeover_fingerprint():
    signal = takeover_check.evaluate(
        "old.example.com",
        ("old.example.com", "someone.github.io"),
        "There isn't a GitHub Pages site here.",
        status=404,
        content_type="text/html",
    )
    assert signal is not None
    assert signal.bug_class == "subdomain_takeover"
    assert signal.severity.value == "high"
    assert signal.confidence.value == "likely"


def test_tls_signals():
    info = TLSInfo(
        host="example.com",
        port=443,
        protocol="TLSv1.1",
        cipher="DES-CBC3-SHA",
        not_after="2020-01-01T00:00:00Z",
        days_left=-2,
        trusted=True,
    )
    classes = {signal.bug_class for signal in tls_check.evaluate("example.com", info)}
    assert {"tls_weak_protocol", "tls_expired", "tls_weak_cipher"} <= classes
    error_info = TLSInfo(host="example.com", port=443, error="certificate verification failed")
    assert tls_check.evaluate("example.com", error_info)[0].bug_class == "tls_error"


def test_graphql_introspection():
    payload = {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None}}}

    def handler(method, url, **kwargs):
        return FetchResult(
            url,
            url,
            method,
            status=200,
            content_type="application/json",
            body=json.dumps(payload).encode(),
        )

    signals = graphql_check.probe(FakeSession(handler), ["https://example.com/graphql"])
    assert len(signals) == 1
    assert signals[0].bug_class == "graphql_introspection"
    assert signals[0].confidence == Confidence.CONFIRMED
