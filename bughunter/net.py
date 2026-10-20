from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from . import __version__
from .audit import AuditLog
from .dnsutil import DnsInfo, Resolver
from .errors import PolicyDenied
from .policy import Policy
from .scope import ScopeDecision, check_url
from .store import Store
from .util import (
    decode_body,
    ensure_dir,
    host_of,
    is_public_ip,
    looks_textual,
    normalize_host,
    parse_ip,
    sha256_bytes,
    sha256_text,
    utc_now_iso,
)

PASSIVE_ALLOWLIST = {"crt.sh", "www.crt.sh", "web.archive.org"}
_REDIRECTS = {301, 302, 303, 307, 308}
_BLOCKED_REQUEST_HEADERS = {"authorization", "cookie", "host", "proxy-authorization"}


class Capture(str, Enum):
    NONE = "none"
    SMALL = "small"
    TEXT = "text"


@dataclass
class FetchResult:
    url: str
    final_url: str
    method: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes | None = None
    text: str | None = None
    elapsed_ms: int = 0
    error: str | None = None
    blocked: bool = False
    block_reason: str = ""
    redirects: list[str] = field(default_factory=list)
    content_type: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and not self.blocked and self.status is not None and 200 <= self.status < 400

    @property
    def host(self) -> str:
        return host_of(self.final_url or self.url)

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def set_cookies(self) -> list[str]:
        return [value for key, value in self.raw_headers if key == "set-cookie"]


@dataclass
class PassiveResult:
    url: str
    status: int | None = None
    body: bytes = b""
    error: str | None = None
    from_cache: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300


@dataclass
class TLSInfo:
    host: str
    port: int
    protocol: str = ""
    cipher: str = ""
    issuer: str = ""
    subject: str = ""
    sans: tuple[str, ...] = ()
    not_after: str = ""
    days_left: float | None = None
    trusted: bool = False
    hostname_match: bool = False
    error: str | None = None


class PassiveClient:
    """Polite client for public passive sources (CT logs, web archive).

    Redirects are not followed and only explicitly allowlisted hosts are
    reachable. Results are cached on disk to avoid hammering third parties.
    """

    def __init__(
        self,
        *,
        audit: AuditLog | None = None,
        cache_dir: str | Path | None = None,
        timeout: float = 30.0,
        cache_ttl: int = 21600,
        user_agent: str = f"Bughunter/{__version__}",
    ):
        self.audit = audit
        self.cache_dir = ensure_dir(cache_dir) if cache_dir else None
        self.cache_ttl = cache_ttl
        self.user_agent = user_agent
        self._lock = threading.Lock()
        self._last = 0.0
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": user_agent, "Accept": "application/json,text/plain,*/*"},
        )

    def _cache_path(self, url: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / f"{sha256_text(url)}.bin"

    def get(self, url: str, *, purpose: str, max_bytes: int = 8_000_000) -> PassiveResult:
        host = normalize_host(urlsplit(url).hostname or "")
        if host not in PASSIVE_ALLOWLIST:
            raise PolicyDenied(f"passive source host {host!r} is not allowlisted", url=url)
        cache_path = self._cache_path(url)
        if cache_path and cache_path.exists() and time.time() - cache_path.stat().st_mtime < self.cache_ttl:
            return PassiveResult(url=url, status=200, body=cache_path.read_bytes(), from_cache=True)

        error: str | None = None
        for attempt in range(3):
            with self._lock:
                wait = max(0.0, 1.0 - (time.monotonic() - self._last))
                if wait:
                    time.sleep(wait)
                self._last = time.monotonic()
            try:
                with self._client.stream("GET", url) as response:
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) >= max_bytes:
                            body = body[:max_bytes]
                            break
                    status = response.status_code
                    location = response.headers.get("location", "")
                if status in _REDIRECTS:
                    error = f"passive source redirected to {location!r}; refusing to follow"
                    break
                if status >= 500 or status == 429:
                    error = f"passive source returned HTTP {status}"
                    if attempt < 2:
                        time.sleep(2 * (attempt + 1))
                        continue
                    break
                payload = bytes(body)
                if status == 200 and cache_path:
                    cache_path.write_bytes(payload)
                if self.audit:
                    self.audit.record(
                        {
                            "event": "passive_fetch",
                            "source": host,
                            "url": url,
                            "purpose": purpose,
                            "status": status,
                            "bytes": len(payload),
                        }
                    )
                return PassiveResult(url=url, status=status, body=payload)
            except (httpx.HTTPError, OSError, ssl.SSLError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                    continue
        if self.audit:
            self.audit.record({"event": "passive_fetch_error", "source": host, "url": url, "error": error})
        return PassiveResult(url=url, error=error)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "PassiveClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class GatedSession:
    """Every target request passes through scope, method, DNS, robots, budget,
    rate-limit, and redirect checks before it is sent."""

    def __init__(
        self,
        policy: Policy,
        store: Store,
        audit: AuditLog,
        run_id: str,
        *,
        resolver: Any | None = None,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        stop_file: str | Path | None = None,
        max_total_requests: int | None = None,
    ):
        self.policy = policy
        self.store = store
        self.audit = audit
        self.run_id = run_id
        self.resolver = resolver or Resolver(timeout=policy.rules.request_timeout_seconds / 2)
        self.clock = clock
        self.sleeper = sleeper
        self.stop_file = Path(stop_file) if stop_file else None
        self.max_total_requests = min(
            policy.rules.max_total_requests,
            max_total_requests if max_total_requests is not None else policy.rules.max_total_requests,
        )
        self.user_agent = (
            f"Bughunter/{__version__} (+authorized bug bounty testing; "
            f"contact: {policy.contact})"
        )
        self._client = httpx.Client(
            timeout=policy.rules.request_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers={"User-Agent": self.user_agent},
        )
        self._lock = threading.RLock()
        self._rate_lock = threading.RLock()
        self._host_times: dict[str, deque[float]] = {}
        self._robots: dict[str, RobotFileParser | None] = {}
        self._total = 0
        self._denied = 0
        self._started = self.clock()
        self.budget_exhausted = False
        self.last_dns: dict[str, DnsInfo] = {}

    # ------------------------------------------------------------- policy
    def _stop_requested(self) -> bool:
        return bool(self.stop_file and self.stop_file.exists())

    def _record_denied(self, method: str, url: str, purpose: str, reason: str) -> None:
        with self._lock:
            self._denied += 1
        host = host_of(url)
        self.store.add_request(
            self.run_id,
            method=method,
            url=url,
            host=host,
            purpose=purpose,
            decision="denied",
            reason=reason,
        )
        self.audit.record(
            {"event": "request_denied", "method": method, "url": url, "purpose": purpose, "reason": reason}
        )

    def _deny(self, method: str, url: str, purpose: str, reason: str) -> None:
        self._record_denied(method, url, purpose, reason)
        raise PolicyDenied(reason, url=url, host=host_of(url))

    def _check_private(self, host: str) -> DnsInfo:
        ip = parse_ip(host)
        if ip is not None:
            info = DnsInfo(host=host, a=(host,) if ip.version == 4 else (), aaaa=(host,) if ip.version == 6 else ())
        else:
            info = self.resolver.resolve(host)
        self.last_dns[host] = info
        if self.policy.rules.allow_private_addresses:
            return info
        if not info.ips:
            raise PolicyDenied(
                f"DNS for {host!r} returned no addresses; refusing to connect (SSRF guard)",
                host=host,
            )
        bad = [address for address in info.ips if not is_public_ip(address)]
        if bad:
            raise PolicyDenied(
                f"DNS for {host!r} resolves to non-public address(es): {', '.join(bad)}; blocked (SSRF guard)",
                host=host,
            )
        return info

    def _authorize(self, method: str, url: str, purpose: str, *, check_robots: bool = True) -> ScopeDecision:
        if self._stop_requested():
            self._deny(method, url, purpose, "kill switch active: STOP file exists")
        if self.policy.rules.mode != "safe-active":
            self._deny(method, url, purpose, "policy mode is passive; target requests are disabled")
        decision = check_url(self.policy, url, method=method)
        if not decision.allowed:
            self._deny(method, url, purpose, decision.reason)
        elapsed = self.clock() - self._started
        if elapsed > self.policy.rules.max_runtime_seconds:
            self.budget_exhausted = True
            self._deny(method, url, purpose, "maximum runtime exceeded")
        with self._lock:
            if self._total >= self.max_total_requests:
                self.budget_exhausted = True
                self._deny(method, url, purpose, "maximum total request budget exhausted")
        try:
            self._check_private(decision.host)
        except PolicyDenied as exc:
            self._deny(method, url, purpose, exc.reason)
        if check_robots and self.policy.rules.respect_robots_txt and decision.path != "/robots.txt":
            if not self._robots_allowed(url, decision):
                self._deny(method, url, purpose, f"path disallowed by robots.txt: {decision.path}")
        return decision

    def _rate_gate(self, host: str, url: str, purpose: str) -> None:
        limit = self.policy.rules.max_requests_per_host_per_minute
        with self._rate_lock:
            now = self.clock()
            elapsed = now - self._started
            if elapsed > self.policy.rules.max_runtime_seconds:
                self.budget_exhausted = True
                self._deny("GET", url, purpose, "maximum runtime exceeded")
            with self._lock:
                if self._total >= self.max_total_requests:
                    self.budget_exhausted = True
                    self._deny("GET", url, purpose, "maximum total request budget exhausted")
            queue = self._host_times.setdefault(host, deque())
            while queue and now - queue[0] >= 60:
                queue.popleft()
            wait = 0.0
            if queue:
                wait = max(wait, (60.0 / limit) - (now - queue[-1]))
            if len(queue) >= limit:
                wait = max(wait, 60.0 - (now - queue[0]) + 0.01)
            if wait and elapsed + wait > self.policy.rules.max_runtime_seconds:
                self.budget_exhausted = True
                self._deny("GET", url, purpose, "waiting for rate limit would exceed maximum runtime")
            if wait > 0:
                self.sleeper(wait)
            now = self.clock()
            queue.append(now)
            with self._lock:
                self._total += 1

    def _robots_allowed(self, url: str, decision: ScopeDecision) -> bool:
        parts = urlsplit(url)
        key = f"{decision.scheme}://{parts.netloc}"
        if key not in self._robots:
            robots_url = f"{key}/robots.txt"
            parser: RobotFileParser | None = None
            try:
                result = self.request(
                    "GET",
                    robots_url,
                    purpose="robots",
                    capture=Capture.TEXT,
                    max_bytes=256_000,
                    follow_redirects=False,
                    check_robots=False,
                )
                if result.status == 200 and result.text:
                    parser = RobotFileParser()
                    parser.parse(result.text.splitlines())
            except PolicyDenied:
                parser = None
            self._robots[key] = parser
        parser = self._robots[key]
        if parser is None:
            return True
        path = decision.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return parser.can_fetch("Bughunter", path)

    # ------------------------------------------------------------ requests
    def request(
        self,
        method: str,
        url: str,
        *,
        purpose: str,
        headers: dict[str, str] | None = None,
        capture: Capture = Capture.NONE,
        max_bytes: int | None = None,
        follow_redirects: bool = True,
        check_robots: bool = True,
        content: bytes | None = None,
    ) -> FetchResult:
        method = method.upper()
        current = url
        redirects: list[str] = []
        tried = 0
        max_hops = self.policy.rules.max_redirects if follow_redirects else 0
        while True:
            try:
                decision = self._authorize(method, current, purpose, check_robots=check_robots)
                self._rate_gate(decision.host, current, purpose)
            except PolicyDenied as exc:
                if tried == 0:
                    raise
                return FetchResult(
                    url=url,
                    final_url=current,
                    method=method,
                    status=self._last_status,
                    error=None,
                    blocked=True,
                    block_reason=exc.reason,
                    redirects=redirects,
                )

            request_headers = {
                key: value
                for key, value in (headers or {}).items()
                if key.lower() not in _BLOCKED_REQUEST_HEADERS
            }
            request_headers.setdefault("User-Agent", self.user_agent)
            request_headers.setdefault("Accept", "text/html,application/json,text/plain,*/*")

            started = self.clock()
            try:
                with self._client.stream(
                    method,
                    current,
                    headers=request_headers,
                    content=content,
                    follow_redirects=False,
                ) as response:
                    status = response.status_code
                    self._last_status = status
                    ctype = response.headers.get("content-type", "")
                    raw_headers = [(key.lower(), value) for key, value in response.headers.multi_items()]
                    items: dict[str, str] = {}
                    for key, value in raw_headers:
                        items[key] = value
                    body: bytes | None = None
                    if capture != Capture.NONE and method != "HEAD":
                        limit = max_bytes or (8192 if capture == Capture.SMALL else self.policy.rules.max_body_bytes)
                        chunks = bytearray()
                        for chunk in response.iter_bytes():
                            chunks.extend(chunk)
                            if len(chunks) >= limit:
                                del chunks[limit:]
                                break
                        body = bytes(chunks)
                    location = response.headers.get("location", "")
                elapsed_ms = int((self.clock() - started) * 1000)
                self._client.cookies.clear()
                text = None
                if body is not None and looks_textual(ctype, body):
                    text = decode_body(body, ctype)
                result = FetchResult(
                    url=url,
                    final_url=current,
                    method=method,
                    status=status,
                    headers=items,
                    raw_headers=raw_headers,
                    body=body,
                    text=text,
                    elapsed_ms=elapsed_ms,
                    redirects=redirects,
                    content_type=ctype,
                )
                self._record_request(
                    method=method,
                    url=current,
                    host=decision.host,
                    purpose=purpose,
                    decision="allowed",
                    status=status,
                    elapsed_ms=elapsed_ms,
                    bytes_read=len(body or b""),
                )
            except (httpx.HTTPError, OSError, ssl.SSLError, ValueError) as exc:
                elapsed_ms = int((self.clock() - started) * 1000)
                error = f"{type(exc).__name__}: {exc}"
                self._record_request(
                    method=method,
                    url=current,
                    host=decision.host,
                    purpose=purpose,
                    decision="error",
                    reason=error,
                    elapsed_ms=elapsed_ms,
                )
                self._client.cookies.clear()
                return FetchResult(
                    url=url,
                    final_url=current,
                    method=method,
                    error=error,
                    elapsed_ms=elapsed_ms,
                    redirects=redirects,
                )

            if (
                follow_redirects
                and status in _REDIRECTS
                and location
                and method in {"GET", "HEAD"}
            ):
                next_url = urljoin(current, location)
                if next_url == current:
                    return result
                if tried >= max_hops:
                    result.error = f"too many redirects (max {max_hops})"
                    return result
                redirects.append(next_url)
                tried += 1
                current = next_url
                method = "GET" if status == 303 else method
                continue
            return result

    def _record_request(
        self,
        *,
        method: str,
        url: str,
        host: str,
        purpose: str,
        decision: str,
        reason: str = "",
        status: int | None = None,
        elapsed_ms: int = 0,
        bytes_read: int = 0,
    ) -> None:
        self.store.add_request(
            self.run_id,
            method=method,
            url=url,
            host=host,
            purpose=purpose,
            decision=decision,
            reason=reason,
            status_code=status,
            elapsed_ms=elapsed_ms,
            bytes_read=bytes_read,
        )
        self.audit.record(
            {
                "event": "http_request",
                "method": method,
                "url": url,
                "purpose": purpose,
                "decision": decision,
                "status": status,
                "elapsed_ms": elapsed_ms,
                "bytes": bytes_read,
                "reason": reason,
            }
        )

    # ----------------------------------------------------------------- TLS
    def probe_tls(self, host: str, port: int = 443) -> TLSInfo:
        host = normalize_host(host)
        url = f"https://{host}:{port}/"
        if self._stop_requested():
            self._deny("TLS", url, "tls", "kill switch active: STOP file exists")
        if self.policy.rules.mode != "safe-active":
            self._deny("TLS", url, "tls", "policy mode is passive; target connections are disabled")
        if port not in self.policy.rules.allowed_ports:
            self._deny("TLS", url, "tls", f"port {port} is not allowed")
        try:
            self._check_private(host)
        except PolicyDenied as exc:
            self._deny("TLS", url, "tls", exc.reason)
        try:
            self._rate_gate(host, url, "tls")
        except PolicyDenied:
            raise
        started = self.clock()
        info = TLSInfo(host=host, port=port)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.policy.rules.request_timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    info.protocol = tls.version() or ""
                    cipher = tls.cipher()
                    info.cipher = cipher[0] if cipher else ""
                    cert = tls.getpeercert() or {}
            info.trusted = True
            info.hostname_match = True
            info.subject = _name_to_text(cert.get("subject", ()))
            info.issuer = _name_to_text(cert.get("issuer", ()))
            info.sans = tuple(value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS")
            not_after = cert.get("notAfter")
            if not_after:
                epoch = ssl.cert_time_to_seconds(not_after)
                info.not_after = (
                    datetime.fromtimestamp(epoch, timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                info.days_left = round((epoch - time.time()) / 86400, 1)
            decision = "allowed"
            reason = ""
        except ssl.SSLCertVerificationError as exc:
            info.error = f"certificate verification failed: {getattr(exc, 'verify_message', None) or exc}"
            decision = "error"
            reason = info.error
        except (ssl.SSLError, socket.timeout, OSError) as exc:
            info.error = f"{type(exc).__name__}: {exc}"
            decision = "error"
            reason = info.error
        elapsed_ms = int((self.clock() - started) * 1000)
        self._record_request(
            method="TLS",
            url=url,
            host=host,
            purpose="tls",
            decision=decision,
            reason=reason,
            elapsed_ms=elapsed_ms,
        )
        return info

    @property
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "requests_allowed": self._total,
                "requests_denied": self._denied,
                "request_cap": self.max_total_requests,
                "runtime_seconds": round(self.clock() - self._started, 1),
                "budget_exhausted": self.budget_exhausted,
            }

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GatedSession":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def _name_to_text(names: Any) -> str:
    parts = []
    for group in names or ():
        for key, value in group:
            parts.append(f"{key}={value}")
    return ", ".join(parts)
