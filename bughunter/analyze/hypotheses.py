from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Confidence, Hypothesis, Severity, Signal, confidence_rank, status_rank
from ..store import Store
from ..util import dedupe, host_of, normalize_host
from .secrets import CloudReference, SecretHit

_INTERESTING_LABELS = {
    "admin": "administrative interface",
    "administrator": "administrative interface",
    "internal": "internal service naming",
    "staging": "non-production environment",
    "stage": "non-production environment",
    "dev": "development environment",
    "test": "test environment",
    "testing": "test environment",
    "qa": "QA environment",
    "uat": "UAT environment",
    "preprod": "pre-production environment",
    "beta": "beta deployment",
    "old": "stale deployment",
    "legacy": "legacy deployment",
    "jenkins": "CI/CD tooling",
    "gitlab": "source control tooling",
    "jira": "issue tracking tooling",
    "confluence": "documentation tooling",
    "grafana": "monitoring tooling",
    "kibana": "logging tooling",
    "prometheus": "monitoring tooling",
    "api": "API surface",
    "graphql": "GraphQL surface",
    "rest": "API surface",
    "upload": "file upload surface",
    "files": "file handling surface",
    "auth": "authentication surface",
    "sso": "authentication surface",
    "login": "authentication surface",
    "oauth": "OAuth surface",
    "debug": "debug interface",
    "actuator": "management interface",
    "backup": "backup naming",
    "vpn": "remote access surface",
    "portal": "customer portal",
    "billing": "billing surface",
    "payment": "payment surface",
}
_HIGH_VALUE_LABELS = {
    "admin", "administrator", "internal", "debug", "actuator", "jenkins", "gitlab",
    "jira", "confluence", "grafana", "kibana", "prometheus", "backup", "vpn",
}
_INTERESTING_PARAMS = {
    "url", "uri", "redirect", "redirect_uri", "next", "return", "returnto", "return_to",
    "callback", "callback_url", "continue", "target", "dest", "destination",
    "file", "filename", "path", "folder", "download", "upload",
    "id", "user", "user_id", "account", "account_id", "tenant", "org", "organization",
    "role", "admin", "debug", "token", "key", "secret", "api_key", "access_token",
    "email", "invite", "reset", "coupon", "price", "amount", "quantity", "plan",
}
_SENSITIVE_PATH_RE = re.compile(
    r"(admin|internal|debug|actuator|graphql|swagger|openapi|api-docs|backup|upload|export|"
    r"invite|reset|billing|payment|invoice|tenant|permission|config|secret)",
    re.I,
)


def _redact_url_values(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = urlencode([(key, "[REDACTED]") for key, _ in pairs], safe="[]")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


@dataclass
class EngineStats:
    emitted: int = 0
    new: int = 0


class HypothesisEngine:
    def __init__(self, store: Store, run_id: str):
        self.store = store
        self.run_id = run_id
        self.stats = EngineStats()
        self._seen: dict[str, Hypothesis] = {}

    def emit(self, signal: Signal) -> Hypothesis | None:
        hypothesis = signal.to_hypothesis()
        previous = self._seen.get(hypothesis.fingerprint)
        if previous is not None:
            if (
                status_rank(hypothesis.status) <= status_rank(previous.status)
                and confidence_rank(hypothesis.confidence.value) <= confidence_rank(previous.confidence.value)
            ):
                return None
        self._seen[hypothesis.fingerprint] = hypothesis
        is_new, _ = self.store.upsert_hypothesis(self.run_id, hypothesis)
        self.stats.emitted += 1
        if is_new:
            self.stats.new += 1
        return hypothesis

    def emit_all(self, signals: list[Signal]) -> list[Hypothesis]:
        emitted = []
        for signal in signals:
            hypothesis = self.emit(signal)
            if hypothesis is not None:
                emitted.append(hypothesis)
        return emitted


def subdomain_signal(host: str, base_domains: tuple[str, ...], *, wildcard: bool = False) -> Signal | None:
    host = normalize_host(host)
    label = ""
    for base in sorted(base_domains, key=len, reverse=True):
        base = normalize_host(base)
        if host == base:
            return None
        if host.endswith("." + base):
            label = host[: -(len(base) + 1)]
            break
    if not label:
        return None
    tokens = [token for token in re.split(r"[-._]", label.lower()) if token]
    matches = dedupe(_INTERESTING_LABELS[token] for token in tokens if token in _INTERESTING_LABELS)
    if not matches:
        return None
    high_value = any(token in _HIGH_VALUE_LABELS for token in tokens)
    wildcard_note = " This host is covered by wildcard DNS, so verify it is a real asset before testing." if wildcard else ""
    return Signal(
        title=f"Interesting subdomain naming: {host}",
        bug_class="interesting_subdomain",
        asset=host,
        severity=Severity.LOW if high_value else Severity.INFO,
        confidence=Confidence.POSSIBLE,
        rationale=(
            f"The hostname suggests {', '.join(matches)}. Human hunters prioritize these because they often "
            f"have weaker controls, stale deployments, or larger attack surface.{wildcard_note}"
        ),
        next_step=(
            "Manually review authentication, authorization, and exposed functionality. "
            "Do not brute force or attempt exploitation automatically."
        ),
        remediation=(
            "Inventory internet-facing non-production and administrative systems; require SSO and "
            "network restrictions, and remove stale DNS records."
        ),
        evidence={"host": host, "label": label, "signals": matches, "wildcard_dns": wildcard},
        source="scope+ct",
        dedupe_key=host,
    )


def archive_param_signal(host: str, urls: list[str], *, source: str = "wayback") -> Signal | None:
    params: set[str] = set()
    examples: list[str] = []
    for url in urls:
        try:
            query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        except ValueError:
            continue
        for name in query:
            params.add(name)
        if query and len(examples) < 5:
            examples.append(_redact_url_values(url))
    interesting = sorted(name for name in params if name.lower() in _INTERESTING_PARAMS)
    if not interesting:
        return None
    return Signal(
        title=f"Archived URLs expose testable parameters on {host}",
        bug_class="archived_parameters",
        asset=host,
        severity=Severity.INFO,
        confidence=Confidence.POSSIBLE,
        rationale=(
            f"Archive data contains {len(params)} distinct query parameter(s), including "
            f"{', '.join(interesting[:10])}. These are high-value manual testing targets for IDOR, "
            "open redirect, SSRF, and authorization flaws."
        ),
        next_step=(
            "Manually test a small number of non-destructive requests. Do not replay archived "
            "logout/delete/checkout URLs, and never test parameters outside the program scope."
        ),
        remediation="Apply server-side authorization and allowlist validation to all parameters; do not trust client input.",
        evidence={"host": host, "parameters": interesting, "all_parameters": sorted(params), "examples": examples},
        source=source,
        dedupe_key="wayback-params",
    )


def archive_path_signal(host: str, urls: list[str], *, source: str = "wayback") -> Signal | None:
    paths: list[str] = []
    for url in urls:
        try:
            path = urlsplit(url).path or "/"
        except ValueError:
            continue
        if _SENSITIVE_PATH_RE.search(path):
            paths.append(path)
    paths = dedupe(paths)
    if not paths:
        return None
    return Signal(
        title=f"Sensitive-looking archived paths on {host}",
        bug_class="archived_paths",
        asset=host,
        severity=Severity.INFO,
        confidence=Confidence.POSSIBLE,
        rationale=(
            "Historical URLs contain paths that commonly expose administrative, API, upload, or "
            "debug functionality. Archived pages may still be live or may reveal removed endpoints."
        ),
        next_step=(
            "Review a few paths manually, starting with documentation and API metadata. "
            "Avoid destructive endpoints and obey the program policy."
        ),
        remediation="Remove obsolete endpoints and enforce authentication/authorization on every route.",
        evidence={"host": host, "paths": paths[:30]},
        source=source,
        dedupe_key="wayback-paths",
    )


def secret_signal(hit: SecretHit, asset: str) -> Signal:
    host = host_of(asset) or asset
    return Signal(
        title=f"Potential {hit.kind.replace('_', ' ')} in client-side code on {host}",
        bug_class=f"secret_{hit.kind}",
        asset=host,
        severity=Severity(hit.severity),
        confidence=Confidence(hit.confidence),
        rationale=(
            "A secret-like value was found in content served by the target. The value is redacted in "
            "this report and was not validated against the provider. If real, public exposure may allow "
            "account access, data access, or billing abuse."
        ),
        next_step=(
            "Confirm the value's validity through an authorized, non-destructive channel. "
            "Do not use the secret or access data it protects. Report immediately if it is live."
        ),
        remediation=(
            "Rotate the credential, remove it from client-side bundles, scope it narrowly, "
            "and add secret scanning to CI."
        ),
        evidence={
            "kind": hit.kind,
            "redacted_value": hit.redacted,
            "fingerprint": hit.fingerprint,
            "context": hit.context,
            "source": hit.source,
        },
        source="js-analysis",
        dedupe_key=hit.fingerprint,
    )


def cloud_signal(reference: CloudReference, asset: str) -> Signal:
    host = host_of(asset) or asset
    return Signal(
        title=f"Cloud storage reference in client code: {reference.provider}",
        bug_class="cloud_storage_reference",
        asset=host,
        severity=Severity.LOW,
        confidence=Confidence.LIKELY,
        rationale=(
            "Client-side code references a storage bucket or CDN distribution. Misconfigured buckets "
            "can allow listing, reading, or writing objects. The storage host may be outside the "
            "program's scope even when the referencing application is in scope."
        ),
        next_step=(
            "Check whether the storage identifier and its host are explicitly in scope before any "
            "interaction. If they are, test the smallest read-only request possible; do not list or "
            "write objects."
        ),
        remediation="Require authenticated access, least-privilege bucket policies, and avoid embedding sensitive object URLs.",
        evidence={
            "provider": reference.provider,
            "identifier": reference.identifier,
            "reference": reference.url,
            "found_in": asset,
        },
        source="js-analysis",
        dedupe_key=f"{reference.provider}:{reference.identifier}",
    )


def source_map_signal(map_url: str, asset: str) -> Signal:
    host = host_of(asset) or asset
    return Signal(
        title=f"Source map reference on {host}",
        bug_class="source_map_reference",
        asset=host,
        severity=Severity.LOW,
        confidence=Confidence.POSSIBLE,
        rationale=(
            "JavaScript references a source map. If publicly reachable, it can disclose original "
            "source code, internal endpoints, and comments that are not intended for production."
        ),
        next_step=(
            "If the map is in scope, fetch it once with a size cap and inspect for secrets or hidden "
            "endpoints. Avoid downloading very large files repeatedly."
        ),
        remediation="Exclude source maps from production builds or restrict access to them.",
        evidence={"map_url": map_url, "found_in": asset},
        source="js-analysis",
        dedupe_key=map_url,
    )


def endpoint_signal(url: str, asset: str, *, found_in: str = "") -> Signal:
    path = ""
    try:
        path = urlsplit(url).path or "/"
    except ValueError:
        pass
    lower = path.lower()
    if "graphql" in lower:
        title = f"GraphQL endpoint discovered on {host_of(url)}"
        bug_class = "graphql_endpoint"
    elif any(token in lower for token in ("swagger", "openapi", "api-docs", "api/docs", "/docs")):
        title = f"API documentation discovered on {host_of(url)}"
        bug_class = "api_docs_endpoint"
    elif any(token in lower for token in ("actuator", "debug")):
        title = f"Debug or management endpoint discovered on {host_of(url)}"
        bug_class = "debug_endpoint"
    elif "admin" in lower:
        title = f"Administrative path discovered on {host_of(url)}"
        bug_class = "admin_endpoint"
    elif "upload" in lower:
        title = f"Upload endpoint discovered on {host_of(url)}"
        bug_class = "upload_endpoint"
    else:
        title = f"Sensitive endpoint discovered on {host_of(url)}"
        bug_class = "sensitive_endpoint"
    return Signal(
        title=title,
        bug_class=bug_class,
        asset=host_of(url) or asset,
        severity=Severity.INFO,
        confidence=Confidence.POSSIBLE,
        rationale=(
            "The endpoint is referenced by application content. It may expose undocumented "
            "functionality or weaker authorization than the main UI."
        ),
        next_step=(
            "Review documentation/metadata if public, then test authorization manually with "
            "low-impact requests. Do not fuzz or exploit in this run."
        ),
        remediation="Document intended exposure, require authentication and object-level authorization, and remove debug routes from production.",
        evidence={"url": url, "path": path, "found_in": found_in or asset},
        source="content-analysis",
        dedupe_key=url,
    )


def dangling_cname_signal(host: str, cname_chain: tuple[str, ...], error: str | None) -> Signal | None:
    if not cname_chain:
        return None
    return Signal(
        title=f"Unresolved CNAME chain on {host}",
        bug_class="dangling_cname",
        asset=host,
        severity=Severity.MEDIUM,
        confidence=Confidence.POSSIBLE,
        rationale=(
            "The CNAME chain does not resolve to an address. If the final target is an unclaimed "
            "third-party resource, the hostname may be vulnerable to subdomain takeover. Many "
            "unresolved CNAMEs are benign, so this is a lead, not a confirmed finding."
        ),
        next_step=(
            "Manually verify whether the final CNAME target is claimable. Do not register or claim "
            "any resource; report the DNS record to the program owner."
        ),
        remediation="Remove stale DNS records or reclaim the third-party resource; monitor CNAME targets for availability.",
        evidence={"host": host, "cname_chain": list(cname_chain), "error": error},
        source="dns",
        dedupe_key="|".join(cname_chain),
    )


__all__ = [
    "HypothesisEngine",
    "EngineStats",
    "archive_param_signal",
    "archive_path_signal",
    "cloud_signal",
    "dangling_cname_signal",
    "endpoint_signal",
    "secret_signal",
    "source_map_signal",
    "subdomain_signal",
]
