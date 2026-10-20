from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from ..models import Confidence, Severity
from ..util import dedupe, redact, sha256_text, shannon_entropy, truncate

_STATIC_EXT = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".pdf", ".zip",
)
_SENSITIVE_TOKENS = (
    "api", "graphql", "rest", "v1", "v2", "v3", "admin", "internal", "upload", "auth",
    "oauth", "user", "account", "invite", "reset", "export", "debug", "actuator",
    "swagger", "openapi", "documentation", "docs", "config", "backup", "download",
    "file", "redirect", "callback", "webhook", "billing", "payment", "invoice",
    "role", "permission", "tenant", "organization", "workspace", "secret", "key",
)
_PLACEHOLDERS = (
    "example", "xxxx", "your_", "your-", "placeholder", "changeme", "replace_me",
    "replaceme", "dummy", "redacted", "insert_", "todo", "fixme", "lorem",
)


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    group: int = 0
    min_entropy: float = 0.0
    generic_filter: bool = False


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.HIGH,
        Confidence.LIKELY,
    ),
    SecretPattern(
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.HIGH,
        Confidence.LIKELY,
    ),
    SecretPattern(
        "aws_secret_key",
        re.compile(r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key[\"'\s:=]{1,12}([A-Za-z0-9/+=]{40})"),
        Severity.HIGH,
        Confidence.LIKELY,
        group=1,
    ),
    SecretPattern(
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        Severity.MEDIUM,
        Confidence.LIKELY,
    ),
    SecretPattern(
        "stripe_live_key",
        re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
        Severity.HIGH,
        Confidence.LIKELY,
    ),
    SecretPattern(
        "stripe_test_key",
        re.compile(r"\bsk_test_[0-9A-Za-z]{20,}\b"),
        Severity.LOW,
        Confidence.LIKELY,
    ),
    SecretPattern(
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        Severity.HIGH,
        Confidence.LIKELY,
    ),
    SecretPattern(
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.MEDIUM,
        Confidence.LIKELY,
    ),
    SecretPattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        Severity.LOW,
        Confidence.POSSIBLE,
    ),
    SecretPattern(
        "generic_secret",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password|auth)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-./+=]{16,})[\"']"
        ),
        Severity.LOW,
        Confidence.POSSIBLE,
        group=1,
        min_entropy=3.5,
        generic_filter=True,
    ),
)

_RELATIVE_PATH_RE = re.compile(
    r"""(?P<q>["'`])(?P<path>/(?:[A-Za-z0-9_\-~.%${}]+/){0,8}[A-Za-z0-9_\-~.%${}]*)(?P=q)"""
)
_ABSOLUTE_URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}""")
_SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s\"'`]+)")
_CLOUD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS S3", re.compile(r"https?://([a-z0-9][a-z0-9.-]{1,61})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", re.I)),
    ("AWS S3", re.compile(r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61})", re.I)),
    ("Google Cloud Storage", re.compile(r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,61})", re.I)),
    ("Azure Blob Storage", re.compile(r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.I)),
    ("DigitalOcean Spaces", re.compile(r"https?://([a-z0-9-]+)\.digitaloceanspaces\.com", re.I)),
    ("AWS CloudFront", re.compile(r"https?://([a-z0-9-]+)\.cloudfront\.net", re.I)),
    ("Firebase", re.compile(r"https?://([a-z0-9-]+)\.firebaseapp\.com", re.I)),
)


@dataclass(frozen=True)
class SecretHit:
    kind: str
    redacted: str
    fingerprint: str
    severity: str
    confidence: str
    context: str
    source: str


@dataclass(frozen=True)
class CloudReference:
    provider: str
    identifier: str
    url: str


@dataclass
class JsIntel:
    endpoints: list[str] = field(default_factory=list)
    absolute_urls: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    cloud_references: list[CloudReference] = field(default_factory=list)
    graphql_endpoints: list[str] = field(default_factory=list)
    secret_hits: list[SecretHit] = field(default_factory=list)


def _placeholder(value: str, kind: str) -> bool:
    lower = value.lower()
    if any(token in lower for token in _PLACEHOLDERS):
        return True
    if lower.startswith(("${", "{{", "process.env", "<", "%")):
        return True
    if kind == "generic_secret" and " " in value:
        return True
    if len(set(value)) <= 3:
        return True
    if kind.startswith("stripe_test"):
        return False
    if lower in {"password", "secret", "token", "apikey", "api_key"}:
        return True
    return False


def scan_text(text: str, source: str, *, limit: int = 100) -> list[SecretHit]:
    if not text:
        return []
    hits: list[SecretHit] = []
    seen: set[str] = set()
    seen_values: set[str] = set()
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            if len(hits) >= limit:
                return hits
            raw = match.group(pattern.group) if pattern.group else match.group(0)
            if not raw or _placeholder(raw, pattern.kind):
                continue
            if raw in seen_values:
                continue
            if pattern.min_entropy and shannon_entropy(raw) < pattern.min_entropy:
                continue
            fingerprint = sha256_text(f"{pattern.kind}:{raw}")
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            seen_values.add(raw)
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            context = text[start:end]
            for known in PATTERNS:
                context = known.regex.sub("[REDACTED]", context)
            context = re.sub(r"[A-Za-z0-9_\-+/=]{20,}", "[REDACTED]", context)
            context = context.replace(raw, "[REDACTED]")
            hits.append(
                SecretHit(
                    kind=pattern.kind,
                    redacted=redact(raw),
                    fingerprint=fingerprint,
                    severity=pattern.severity.value,
                    confidence=pattern.confidence.value,
                    context=truncate(" ".join(context.split()), 180),
                    source=source,
                )
            )
    return hits


def interesting_path(path: str) -> bool:
    lower = path.lower()
    if not lower.startswith("/") or len(lower) > 250:
        return False
    if lower.endswith(_STATIC_EXT):
        return False
    if lower in {"/", "/home", "/index", "/index.html", "/about", "/contact", "/login"}:
        return False
    return any(token in lower for token in _SENSITIVE_TOKENS)


def extract_intel(text: str, base_url: str, *, source: str = "") -> JsIntel:
    if not text:
        return JsIntel()
    endpoints: list[str] = []
    for match in _RELATIVE_PATH_RE.finditer(text):
        path = match.group("path")
        if interesting_path(path):
            endpoints.append(urljoin(base_url, path))

    absolute_urls: list[str] = []
    for match in _ABSOLUTE_URL_RE.finditer(text):
        candidate = match.group(0).rstrip(".,;:)]}\"'`")
        absolute_urls.append(candidate)
        try:
            if interesting_path(urlsplit(candidate).path):
                endpoints.append(candidate)
        except ValueError:
            continue

    source_maps: list[str] = []
    for match in _SOURCE_MAP_RE.finditer(text):
        source_maps.append(urljoin(base_url, match.group(1)))

    cloud_references: list[CloudReference] = []
    seen_cloud: set[tuple[str, str]] = set()
    for provider, regex in _CLOUD_PATTERNS:
        for match in regex.finditer(text):
            identifier = match.group(1).lower()
            key = (provider, identifier)
            if key in seen_cloud:
                continue
            seen_cloud.add(key)
            cloud_references.append(
                CloudReference(provider=provider, identifier=identifier, url=match.group(0))
            )
            if len(cloud_references) >= 50:
                break

    graphql = [url for url in endpoints if "graphql" in url.lower()][:30]
    return JsIntel(
        endpoints=dedupe(endpoints)[:300],
        absolute_urls=dedupe(absolute_urls)[:200],
        source_maps=dedupe(source_maps)[:50],
        cloud_references=cloud_references,
        graphql_endpoints=graphql,
        secret_hits=scan_text(text, source or base_url),
    )
