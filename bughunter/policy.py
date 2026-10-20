from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import AuthorizationError, PolicyError
from .util import dedupe, normalize_host, sha256_text

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_MODES = {"passive", "safe-active"}

DEFAULT_FORBIDDEN_PATHS = (
    "/logout*",
    "/signout*",
    "/delete*",
    "/remove*",
    "/admin/delete*",
    "/api/*/delete*",
    "/checkout*",
    "/purchase*",
    "/unsubscribe*",
)


def validate_domain_pattern(pattern: str) -> str:
    if not isinstance(pattern, str) or not pattern.strip():
        raise PolicyError("scope domain entries must be non-empty strings")
    raw = pattern.strip().lower().rstrip(".")
    if "://" in raw or "/" in raw or ":" in raw or "@" in raw or " " in raw:
        raise PolicyError(f"scope entry {pattern!r} must be a hostname, not a URL, URL with port, or email")
    if raw == "*" or raw.startswith("*.") and raw.count("*") != 1:
        raise PolicyError(f"invalid wildcard scope entry {pattern!r}; only a leading '*.' is supported")
    if "*" in raw and not raw.startswith("*."):
        raise PolicyError(f"invalid wildcard scope entry {pattern!r}; only a leading '*.' is supported")
    base = raw[2:] if raw.startswith("*.") else raw
    if not base or base != normalize_host(base):
        raise PolicyError(f"invalid scope entry {pattern!r}")
    if base.startswith(".") or base.endswith(".") or ".." in base:
        raise PolicyError(f"invalid scope entry {pattern!r}")
    try:
        ascii_base = base.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PolicyError(f"scope entry {pattern!r} is not a valid IDNA hostname: {exc}") from exc
    if not _DOMAIN_RE.match(ascii_base):
        raise PolicyError(
            f"scope entry {pattern!r} is not a valid registrable domain (use ip_ranges for IP addresses)"
        )
    return f"*.{ascii_base}" if raw.startswith("*.") else ascii_base


@dataclass(frozen=True)
class Authorization:
    confirmed: bool
    authorized_by: str
    date: str
    policy_url: str


@dataclass(frozen=True)
class ScopeConfig:
    domains: tuple[str, ...]
    exclusions: tuple[str, ...]
    ip_ranges: tuple[str, ...]


@dataclass(frozen=True)
class PassiveSources:
    crtsh: bool
    wayback: bool
    max_crtsh_results: int
    max_wayback_urls: int


@dataclass(frozen=True)
class ActiveChecks:
    enabled: bool
    security_headers: bool
    cookies: bool
    cors: bool
    exposed_files: bool
    graphql_introspection: bool
    takeover_fingerprints: bool
    tls: bool


@dataclass(frozen=True)
class Rules:
    mode: str
    allowed_methods: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    max_requests_per_host_per_minute: int
    max_total_requests: int
    max_runtime_seconds: int
    request_timeout_seconds: int
    max_hosts: int
    max_pages_per_host: int
    max_js_files_per_host: int
    max_paths_per_host: int
    max_hosts_for_exposed_checks: int
    max_hosts_for_deep_checks: int
    max_body_bytes: int
    max_redirects: int
    respect_robots_txt: bool
    allow_private_addresses: bool
    allow_out_of_scope_redirects: bool
    forbidden_paths: tuple[str, ...]
    passive_sources: PassiveSources
    active_checks: ActiveChecks


@dataclass(frozen=True)
class Policy:
    path: Path
    sha256: str
    program_name: str
    platform: str
    policy_url: str
    contact: str
    authorization: Authorization
    scope: ScopeConfig
    rules: Rules
    raw: dict[str, Any]
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def mode(self) -> str:
        return self.rules.mode

    @property
    def discovery_domains(self) -> tuple[str, ...]:
        return tuple(dedupe(entry[2:] if entry.startswith("*.") else entry for entry in self.scope.domains))

    def assert_authorized(self) -> None:
        if not self.authorization.confirmed:
            raise AuthorizationError(
                "authorization.confirmed is false. Edit the policy and set it to true only after "
                "you have verified that you are permitted to test this program."
            )
        if not self.authorization.authorized_by.strip():
            raise AuthorizationError(
                "authorization.authorized_by is empty. Record who authorized the testing "
                "(yourself, your company, or the program owner)."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "program": {
                "name": self.program_name,
                "platform": self.platform,
                "policy_url": self.policy_url,
                "contact": self.contact,
                "authorization": {
                    "confirmed": self.authorization.confirmed,
                    "authorized_by": self.authorization.authorized_by,
                    "date": self.authorization.date,
                    "policy_url": self.authorization.policy_url,
                },
            },
            "scope": {
                "domains": list(self.scope.domains),
                "exclusions": list(self.scope.exclusions),
                "ip_ranges": list(self.scope.ip_ranges),
            },
            "rules": {
                "mode": self.rules.mode,
                "allowed_methods": list(self.rules.allowed_methods),
                "allowed_ports": list(self.rules.allowed_ports),
                "max_requests_per_host_per_minute": self.rules.max_requests_per_host_per_minute,
                "max_total_requests": self.rules.max_total_requests,
                "max_runtime_seconds": self.rules.max_runtime_seconds,
                "request_timeout_seconds": self.rules.request_timeout_seconds,
                "max_hosts": self.rules.max_hosts,
                "max_pages_per_host": self.rules.max_pages_per_host,
                "max_js_files_per_host": self.rules.max_js_files_per_host,
                "max_paths_per_host": self.rules.max_paths_per_host,
                "max_hosts_for_exposed_checks": self.rules.max_hosts_for_exposed_checks,
                "max_hosts_for_deep_checks": self.rules.max_hosts_for_deep_checks,
                "max_body_bytes": self.rules.max_body_bytes,
                "max_redirects": self.rules.max_redirects,
                "respect_robots_txt": self.rules.respect_robots_txt,
                "allow_private_addresses": self.rules.allow_private_addresses,
                "allow_out_of_scope_redirects": self.rules.allow_out_of_scope_redirects,
                "forbidden_paths": list(self.rules.forbidden_paths),
                "passive_sources": {
                    "crtsh": self.rules.passive_sources.crtsh,
                    "wayback": self.rules.passive_sources.wayback,
                    "max_crtsh_results": self.rules.passive_sources.max_crtsh_results,
                    "max_wayback_urls": self.rules.passive_sources.max_wayback_urls,
                },
                "active_checks": {
                    "enabled": self.rules.active_checks.enabled,
                    "security_headers": self.rules.active_checks.security_headers,
                    "cookies": self.rules.active_checks.cookies,
                    "cors": self.rules.active_checks.cors,
                    "exposed_files": self.rules.active_checks.exposed_files,
                    "graphql_introspection": self.rules.active_checks.graphql_introspection,
                    "takeover_fingerprints": self.rules.active_checks.takeover_fingerprints,
                    "tls": self.rules.active_checks.tls,
                },
            },
            "metadata": self.raw.get("metadata", {}),
        }

    def summary_rows(self) -> list[tuple[str, str]]:
        host_count = len(self.scope.domains)
        modes = "passive (no target packets)" if self.mode == "passive" else "safe-active"
        active = "enabled" if self.rules.active_checks.enabled else "disabled"
        auth = "CONFIRMED" if self.authorization.confirmed else "NOT CONFIRMED"
        return [
            ("Program", self.program_name),
            ("Platform", self.platform or "-"),
            ("Authorization", f"{auth} - {self.authorization.authorized_by or 'unset'}"),
            ("Mode", modes),
            ("Active checks", active),
            ("Scope", f"{host_count} rule(s): {', '.join(self.scope.domains)}"),
            ("Exclusions", ", ".join(self.scope.exclusions) or "-"),
            ("Allowed methods", ", ".join(self.rules.allowed_methods)),
            ("Allowed ports", ", ".join(str(p) for p in self.rules.allowed_ports)),
            ("Rate limit / host", f"{self.rules.max_requests_per_host_per_minute} req/min"),
            ("Request cap", str(self.rules.max_total_requests)),
            ("Runtime cap", f"{self.rules.max_runtime_seconds}s"),
            ("Robots.txt", "respected" if self.rules.respect_robots_txt else "ignored"),
            ("Private addresses", "allowed" if self.rules.allow_private_addresses else "blocked"),
        ]


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a mapping")
    return value


def _bool(value: Any, default: bool, where: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false")
    return value


def _int(value: Any, default: int, where: str, low: int, high: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{where} must be an integer")
    if not low <= value <= high:
        raise PolicyError(f"{where} must be between {low} and {high}")
    return value


def _str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise PolicyError(f"expected a string, got {type(value).__name__}")
    return value.strip()


def _str_list(value: Any, default: list[str], where: str) -> tuple[str, ...]:
    if value is None:
        return tuple(default)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{where} must be a list of strings")
    return tuple(dedupe(item.strip() for item in value if item.strip()))


def _warn_unknown(mapping: dict[str, Any], known: set[str], where: str, warnings: list[str]) -> None:
    unknown = sorted(set(mapping) - known)
    if unknown:
        warnings.append(f"unknown key(s) under {where}: {', '.join(unknown)} (ignored)")


def load_policy(path: str | Path) -> Policy:
    policy_path = Path(path).expanduser()
    if not policy_path.exists():
        raise PolicyError(f"policy file not found: {policy_path}")
    try:
        text = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {policy_path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in {policy_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be a mapping")

    warnings: list[str] = []
    _warn_unknown(raw, {"program", "scope", "rules", "metadata"}, "root", warnings)

    program = _mapping(raw.get("program"), "program")
    _warn_unknown(
        program,
        {"name", "platform", "policy_url", "contact", "authorization"},
        "program",
        warnings,
    )
    name = _str(program.get("name"))
    if not name:
        raise PolicyError("program.name is required")
    platform = _str(program.get("platform"))
    policy_url = _str(program.get("policy_url"))
    contact = _str(program.get("contact")) or policy_url or platform or "n/a"

    auth_raw = _mapping(program.get("authorization"), "program.authorization")
    _warn_unknown(
        auth_raw,
        {"confirmed", "authorized_by", "date", "policy_url"},
        "program.authorization",
        warnings,
    )
    authorization = Authorization(
        confirmed=_bool(auth_raw.get("confirmed"), False, "program.authorization.confirmed"),
        authorized_by=_str(auth_raw.get("authorized_by")),
        date=_str(auth_raw.get("date")),
        policy_url=_str(auth_raw.get("policy_url")) or policy_url,
    )
    if authorization.confirmed and not authorization.authorized_by:
        raise PolicyError(
            "program.authorization.authorized_by is required when confirmed is true"
        )

    scope_raw = _mapping(raw.get("scope"), "scope")
    _warn_unknown(scope_raw, {"domains", "exclusions", "ip_ranges"}, "scope", warnings)
    domains_raw = scope_raw.get("domains")
    if not isinstance(domains_raw, list) or not domains_raw:
        raise PolicyError("scope.domains must be a non-empty list of hostnames")
    domains = tuple(dedupe(validate_domain_pattern(item) for item in domains_raw))
    exclusions = tuple(
        dedupe(validate_domain_pattern(item) for item in _str_list(scope_raw.get("exclusions"), [], "scope.exclusions"))
    )
    ip_ranges: list[str] = []
    ips_raw = _str_list(scope_raw.get("ip_ranges"), [], "scope.ip_ranges")
    for entry in ips_raw:
        try:
            ip_ranges.append(str(ipaddress.ip_network(entry, strict=False)))
        except ValueError as exc:
            raise PolicyError(f"invalid scope.ip_ranges entry {entry!r}: {exc}") from exc

    rules_raw = _mapping(raw.get("rules"), "rules")
    _warn_unknown(
        rules_raw,
        {
            "mode",
            "allowed_methods",
            "allowed_ports",
            "max_requests_per_host_per_minute",
            "max_total_requests",
            "max_runtime_seconds",
            "request_timeout_seconds",
            "max_hosts",
            "max_pages_per_host",
            "max_js_files_per_host",
            "max_paths_per_host",
            "max_hosts_for_exposed_checks",
            "max_hosts_for_deep_checks",
            "max_body_bytes",
            "max_redirects",
            "respect_robots_txt",
            "allow_private_addresses",
            "allow_out_of_scope_redirects",
            "forbidden_paths",
            "passive_sources",
            "active_checks",
        },
        "rules",
        warnings,
    )

    mode = _str(rules_raw.get("mode"), "passive").lower()
    if mode not in _MODES:
        raise PolicyError(f"rules.mode must be one of {sorted(_MODES)}")

    methods = tuple(m.upper() for m in _str_list(rules_raw.get("allowed_methods"), ["GET", "HEAD"], "rules.allowed_methods"))
    bad_methods = [m for m in methods if m not in _METHODS]
    if bad_methods:
        raise PolicyError(f"unsupported method(s): {', '.join(bad_methods)}")
    if not methods:
        raise PolicyError("rules.allowed_methods cannot be empty")

    ports_raw = rules_raw.get("allowed_ports", [80, 443])
    if not isinstance(ports_raw, list) or not ports_raw:
        raise PolicyError("rules.allowed_ports must be a non-empty list of ports")
    ports: list[int] = []
    for port in ports_raw:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise PolicyError(f"invalid port in rules.allowed_ports: {port!r}")
        ports.append(port)

    passive_raw = _mapping(rules_raw.get("passive_sources"), "rules.passive_sources")
    _warn_unknown(
        passive_raw,
        {"crtsh", "wayback", "max_crtsh_results", "max_wayback_urls"},
        "rules.passive_sources",
        warnings,
    )
    passive = PassiveSources(
        crtsh=_bool(passive_raw.get("crtsh"), True, "rules.passive_sources.crtsh"),
        wayback=_bool(passive_raw.get("wayback"), True, "rules.passive_sources.wayback"),
        max_crtsh_results=_int(
            passive_raw.get("max_crtsh_results"), 1000, "rules.passive_sources.max_crtsh_results", 1, 5000
        ),
        max_wayback_urls=_int(
            passive_raw.get("max_wayback_urls"), 2000, "rules.passive_sources.max_wayback_urls", 1, 10000
        ),
    )

    active_raw = _mapping(rules_raw.get("active_checks"), "rules.active_checks")
    _warn_unknown(
        active_raw,
        {
            "enabled",
            "security_headers",
            "cookies",
            "cors",
            "exposed_files",
            "graphql_introspection",
            "takeover_fingerprints",
            "tls",
        },
        "rules.active_checks",
        warnings,
    )
    active = ActiveChecks(
        enabled=_bool(active_raw.get("enabled"), False, "rules.active_checks.enabled"),
        security_headers=_bool(active_raw.get("security_headers"), True, "rules.active_checks.security_headers"),
        cookies=_bool(active_raw.get("cookies"), True, "rules.active_checks.cookies"),
        cors=_bool(active_raw.get("cors"), True, "rules.active_checks.cors"),
        exposed_files=_bool(active_raw.get("exposed_files"), True, "rules.active_checks.exposed_files"),
        graphql_introspection=_bool(
            active_raw.get("graphql_introspection"), False, "rules.active_checks.graphql_introspection"
        ),
        takeover_fingerprints=_bool(
            active_raw.get("takeover_fingerprints"), True, "rules.active_checks.takeover_fingerprints"
        ),
        tls=_bool(active_raw.get("tls"), True, "rules.active_checks.tls"),
    )
    if mode == "safe-active" and not active.enabled:
        warnings.append("rules.mode is safe-active but rules.active_checks.enabled is false; no target requests will be made")
    if mode == "passive" and active.enabled:
        warnings.append("rules.mode is passive; active_checks are ignored")
    if active.graphql_introspection and "POST" not in methods:
        warnings.append("graphql_introspection is enabled but POST is not in allowed_methods; it will be skipped")
    if active.graphql_introspection and not active.enabled:
        warnings.append("graphql_introspection is enabled but active_checks.enabled is false; it will be skipped")
    if rules_raw.get("allow_out_of_scope_redirects") is True:
        warnings.append(
            "allow_out_of_scope_redirects is not honored: every redirect hop is always re-checked against scope"
        )

    rules = Rules(
        mode=mode,
        allowed_methods=methods,
        allowed_ports=tuple(dict.fromkeys(ports)),
        max_requests_per_host_per_minute=_int(
            rules_raw.get("max_requests_per_host_per_minute"), 20, "rules.max_requests_per_host_per_minute", 1, 100000
        ),
        max_total_requests=_int(rules_raw.get("max_total_requests"), 400, "rules.max_total_requests", 1, 20000),
        max_runtime_seconds=_int(rules_raw.get("max_runtime_seconds"), 1200, "rules.max_runtime_seconds", 30, 86400),
        request_timeout_seconds=_int(
            rules_raw.get("request_timeout_seconds"), 15, "rules.request_timeout_seconds", 3, 120
        ),
        max_hosts=_int(rules_raw.get("max_hosts"), 150, "rules.max_hosts", 1, 1000),
        max_pages_per_host=_int(rules_raw.get("max_pages_per_host"), 3, "rules.max_pages_per_host", 1, 25),
        max_js_files_per_host=_int(rules_raw.get("max_js_files_per_host"), 15, "rules.max_js_files_per_host", 0, 100),
        max_paths_per_host=_int(rules_raw.get("max_paths_per_host"), 12, "rules.max_paths_per_host", 1, 40),
        max_hosts_for_exposed_checks=_int(
            rules_raw.get("max_hosts_for_exposed_checks"), 8, "rules.max_hosts_for_exposed_checks", 0, 100
        ),
        max_hosts_for_deep_checks=_int(
            rules_raw.get("max_hosts_for_deep_checks"), 15, "rules.max_hosts_for_deep_checks", 0, 1000
        ),
        max_body_bytes=_int(rules_raw.get("max_body_bytes"), 2_000_000, "rules.max_body_bytes", 1024, 20_000_000),
        max_redirects=_int(rules_raw.get("max_redirects"), 4, "rules.max_redirects", 0, 10),
        respect_robots_txt=_bool(rules_raw.get("respect_robots_txt"), True, "rules.respect_robots_txt"),
        allow_private_addresses=_bool(
            rules_raw.get("allow_private_addresses"), False, "rules.allow_private_addresses"
        ),
        allow_out_of_scope_redirects=_bool(
            rules_raw.get("allow_out_of_scope_redirects"), False, "rules.allow_out_of_scope_redirects"
        ),
        forbidden_paths=_str_list(
            rules_raw.get("forbidden_paths"), list(DEFAULT_FORBIDDEN_PATHS), "rules.forbidden_paths"
        ),
        passive_sources=passive,
        active_checks=active,
    )

    if "DELETE" in methods or "PUT" in methods or "PATCH" in methods:
        warnings.append("destructive methods are allowed by policy, but Bughunter never uses them automatically")

    return Policy(
        path=policy_path.resolve(),
        sha256=sha256_text(text),
        program_name=name,
        platform=platform,
        policy_url=policy_url,
        contact=contact,
        authorization=authorization,
        scope=ScopeConfig(domains=domains, exclusions=exclusions, ip_ranges=tuple(ip_ranges)),
        rules=rules,
        raw=raw,
        warnings=tuple(warnings),
    )
