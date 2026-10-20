from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .policy import Policy, validate_domain_pattern
from .util import normalize_host, parse_ip

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    host: str = ""
    port: int = 443
    scheme: str = "https"
    path: str = "/"
    method: str = "GET"
    matched_rule: str | None = None
    excluded_rule: str | None = None
    url: str | None = None


def match_host_pattern(pattern: str, host: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    host = normalize_host(host)
    if pattern.startswith("*."):
        base = pattern[2:]
        return host != base and host.endswith("." + base)
    return host == pattern or host.endswith("." + pattern)


def _best_match(patterns: tuple[str, ...], host: str) -> str | None:
    matches = [pattern for pattern in patterns if match_host_pattern(pattern, host)]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item.lstrip("*.")))


def _forbidden_path(policy: Policy, path: str) -> str | None:
    decoded = unquote(path or "/")
    candidates = {path or "/", decoded}
    for candidate in list(candidates):
        if ".." in candidate.split("/"):
            return "path traversal segment is not allowed"
    for pattern in policy.rules.forbidden_paths:
        for candidate in candidates:
            if fnmatch.fnmatchcase(candidate, pattern):
                return pattern
    return None


def check_host(
    policy: Policy,
    host: str,
    *,
    port: int = 443,
    scheme: str = "https",
    check_port: bool = True,
) -> ScopeDecision:
    host = normalize_host(host)
    if not host:
        return ScopeDecision(False, "empty hostname", host=host, port=port, scheme=scheme)
    if _CONTROL_RE.search(host) or any(char in host for char in "/\\@?# "):
        return ScopeDecision(False, f"invalid hostname {host!r}", host=host, port=port, scheme=scheme)
    if check_port and port not in policy.rules.allowed_ports:
        return ScopeDecision(
            False,
            f"port {port} is not allowed (allowed: {', '.join(map(str, policy.rules.allowed_ports))})",
            host=host,
            port=port,
            scheme=scheme,
        )

    exclusion = _best_match(policy.scope.exclusions, host)
    if exclusion:
        return ScopeDecision(
            False,
            f"host is excluded by scope rule {exclusion!r}",
            host=host,
            port=port,
            scheme=scheme,
            excluded_rule=exclusion,
        )

    ip = parse_ip(host)
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            if not policy.rules.allow_private_addresses:
                return ScopeDecision(
                    False,
                    "private, loopback, link-local, or reserved IP addresses are blocked",
                    host=host,
                    port=port,
                    scheme=scheme,
                )
        in_range = None
        for entry in policy.scope.ip_ranges:
            network = ipaddress.ip_network(entry, strict=False)
            if ip in network:
                in_range = entry
                break
        if not in_range:
            return ScopeDecision(
                False,
                "IP address is out of scope (add it to scope.ip_ranges only if the program permits it)",
                host=host,
                port=port,
                scheme=scheme,
            )
        return ScopeDecision(
            True,
            f"IP matches scope range {in_range}",
            host=host,
            port=port,
            scheme=scheme,
            matched_rule=in_range,
        )

    matched = _best_match(policy.scope.domains, host)
    if not matched:
        return ScopeDecision(
            False,
            f"host {host!r} matches no scope.domains rule",
            host=host,
            port=port,
            scheme=scheme,
        )
    return ScopeDecision(
        True,
        f"host matches scope rule {matched!r}",
        host=host,
        port=port,
        scheme=scheme,
        matched_rule=matched,
    )


def check_url(
    policy: Policy,
    url: str,
    *,
    method: str = "GET",
    allow_any_port: bool = False,
) -> ScopeDecision:
    method = (method or "GET").upper()
    if method not in policy.rules.allowed_methods:
        return ScopeDecision(
            False,
            f"method {method} is not allowed (allowed: {', '.join(policy.rules.allowed_methods)})",
            method=method,
            url=url,
        )
    if not isinstance(url, str) or not url.strip():
        return ScopeDecision(False, "empty URL", method=method, url=url)
    if _CONTROL_RE.search(url) or any(char in url for char in ("\r", "\n", "\\")):
        return ScopeDecision(False, "URL contains control characters or backslashes", method=method, url=url)
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return ScopeDecision(False, f"invalid URL: {exc}", method=method, url=url)

    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return ScopeDecision(False, "only http and https schemes are allowed", scheme=scheme, method=method, url=url)
    if parts.username or parts.password:
        return ScopeDecision(False, "URLs with embedded credentials are not allowed", scheme=scheme, method=method, url=url)
    host = normalize_host(parts.hostname or "")
    if not host:
        return ScopeDecision(False, "URL has no hostname", scheme=scheme, method=method, url=url)
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return ScopeDecision(False, "URL has an invalid port", host=host, scheme=scheme, method=method, url=url)
    if not allow_any_port and port not in policy.rules.allowed_ports:
        return ScopeDecision(
            False,
            f"port {port} is not allowed (allowed: {', '.join(map(str, policy.rules.allowed_ports))})",
            host=host,
            port=port,
            scheme=scheme,
            method=method,
            url=url,
        )

    decision = check_host(policy, host, port=port, scheme=scheme)
    path = parts.path or "/"
    forbidden = _forbidden_path(policy, path)
    if forbidden:
        return ScopeDecision(
            False,
            f"path is forbidden by rule {forbidden!r}",
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            method=method,
            url=url,
        )
    return ScopeDecision(
        decision.allowed,
        decision.reason,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        method=method,
        matched_rule=decision.matched_rule,
        excluded_rule=decision.excluded_rule,
        url=url,
    )


def check_target(policy: Policy, target: str) -> ScopeDecision:
    target = (target or "").strip()
    if "://" in target:
        return check_url(policy, target)
    return check_host(policy, target, check_port=False)


def describe(policy: Policy) -> str:
    lines = [f"Scope rules: {', '.join(policy.scope.domains)}"]
    if policy.scope.exclusions:
        lines.append(f"Exclusions: {', '.join(policy.scope.exclusions)}")
    if policy.scope.ip_ranges:
        lines.append(f"IP ranges: {', '.join(policy.scope.ip_ranges)}")
    return "\n".join(lines)


__all__ = [
    "ScopeDecision",
    "check_host",
    "check_target",
    "check_url",
    "describe",
    "match_host_pattern",
    "validate_domain_pattern",
]
