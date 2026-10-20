from __future__ import annotations

import secrets
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any

from .util import is_public_ip, normalize_host, parse_ip

try:  # pragma: no cover - exercised only when dnspython is missing
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None  # type: ignore[assignment]


@dataclass(frozen=True)
class DnsInfo:
    host: str
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    cname_chain: tuple[str, ...] = ()
    error: str | None = None
    target_error: str | None = None
    wildcard: bool = False

    @property
    def ips(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.a, *self.aaaa)))

    @property
    def public(self) -> bool:
        return bool(self.ips) and all(is_public_ip(ip) for ip in self.ips)

    @property
    def cname(self) -> str:
        return self.cname_chain[-1] if self.cname_chain else ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ips": list(self.ips),
            "cname_chain": list(self.cname_chain),
            "error": self.error,
            "target_error": self.target_error,
            "wildcard": self.wildcard,
        }


class Resolver:
    """Small cached DNS resolver with CNAME chain support.

    It uses dnspython when installed and falls back to the system resolver.
    The class intentionally exposes only `resolve(host)`, so tests can inject a
    stub.
    """

    def __init__(self, timeout: float = 4.0, cache_ttl: int = 600):
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._lock = threading.RLock()
        self._cache: dict[str, tuple[float, DnsInfo]] = {}
        self._resolver = None
        if dns is not None:
            self._resolver = dns.resolver.Resolver()
            self._resolver.lifetime = timeout
            self._resolver.timeout = timeout

    def resolve(self, host: str, *, use_cache: bool = True) -> DnsInfo:
        host = normalize_host(host)
        if not host:
            return DnsInfo(host="", error="empty hostname")
        ip = parse_ip(host)
        if ip is not None:
            return DnsInfo(host=host, a=(host,) if ip.version == 4 else (), aaaa=(host,) if ip.version == 6 else ())

        now = time.monotonic()
        if use_cache:
            with self._lock:
                cached = self._cache.get(host)
                if cached and cached[0] > now:
                    return cached[1]

        if self._resolver is not None:
            info = self._resolve_dnspython(host)
        else:  # pragma: no cover
            info = self._resolve_socket(host)
        if not info.ips:
            # dnspython can fail when the host only exposes system resolvers or
            # when the configured resolver is unreachable. Fall back to the OS
            # resolver so DNS checks and CNAME follow-ups keep working.
            fallback = self._resolve_socket(host)
            if fallback.ips:
                info = DnsInfo(
                    host=host,
                    a=fallback.a,
                    aaaa=fallback.aaaa,
                    cname_chain=info.cname_chain or fallback.cname_chain,
                    error=None,
                    target_error=None if info.cname_chain else info.target_error,
                )
        if use_cache:
            with self._lock:
                self._cache[host] = (now + self.cache_ttl, info)
        return info

    def _resolve_dnspython(self, host: str) -> DnsInfo:
        assert self._resolver is not None
        cname_chain: list[str] = []
        current = host
        for _ in range(6):
            try:
                answer = self._resolver.resolve(current, "CNAME", raise_on_no_answer=False)
            except dns.exception.Timeout:
                break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                break
            if getattr(answer, "rrset", None) is None or not answer:
                break
            try:
                target = str(answer[0].target).rstrip(".").lower()
            except Exception:
                break
            if not target or target == current:
                break
            cname_chain.append(target)
            current = target

        a: list[str] = []
        aaaa: list[str] = []
        error: str | None = None
        target_error: str | None = None
        for query_host in dict.fromkeys((current, host)):
            if query_host != current and cname_chain:
                continue
            for record, bucket in (("A", a), ("AAAA", aaaa)):
                try:
                    answer = self._resolver.resolve(query_host, record, raise_on_no_answer=False)
                except dns.resolver.NXDOMAIN as exc:
                    error = error or f"NXDOMAIN: {exc}"
                    continue
                except dns.exception.Timeout:
                    error = error or f"DNS timeout while resolving {record} for {query_host}"
                    continue
                except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException) as exc:
                    error = error or f"{type(exc).__name__}: {exc}"
                    continue
                if getattr(answer, "rrset", None) is None:
                    continue
                canonical = str(getattr(answer, "canonical_name", "") or "").rstrip(".").lower()
                if canonical and canonical != host and canonical not in cname_chain:
                    cname_chain.append(canonical)
                for item in answer:
                    value = str(item).strip()
                    if value and value not in bucket:
                        bucket.append(value)

        if cname_chain and not a and not aaaa:
            target_error = error or "CNAME target did not resolve to an address"
        if not a and not aaaa and not cname_chain and not error:
            error = "no A/AAAA/CNAME records returned"
        return DnsInfo(
            host=host,
            a=tuple(a),
            aaaa=tuple(aaaa),
            cname_chain=tuple(cname_chain),
            error=error,
            target_error=target_error,
        )

    def _resolve_socket(self, host: str) -> DnsInfo:  # pragma: no cover
        a: list[str] = []
        aaaa: list[str] = []
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            return DnsInfo(host=host, error=f"DNS resolution failed: {exc}")
        for family, _, _, _, sockaddr in infos:
            address = sockaddr[0]
            bucket = a if family == socket.AF_INET else aaaa
            if address not in bucket:
                bucket.append(address)
        if not a and not aaaa:
            return DnsInfo(host=host, error="no addresses returned")
        return DnsInfo(host=host, a=tuple(a), aaaa=tuple(aaaa))

    def wildcard_probe(self, base_domain: str) -> DnsInfo | None:
        base_domain = normalize_host(base_domain)
        label = f"bh-{secrets.token_hex(6)}.{base_domain}"
        info = self.resolve(label, use_cache=False)
        if info.ips or info.cname_chain:
            return DnsInfo(
                host=label,
                a=info.a,
                aaaa=info.aaaa,
                cname_chain=info.cname_chain,
                error=info.error,
                target_error=info.target_error,
                wildcard=True,
            )
        return None
