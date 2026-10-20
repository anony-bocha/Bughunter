from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..analyze.fingerprint import is_session_cookie
from ..models import Confidence, Severity, Signal
from ..util import host_of

_HEADERS = (
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options / frame-ancestors"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
)
_VERSION_RE = re.compile(r"\d+\.\d+")


def evaluate(url: str, headers: dict[str, str], cookies: list[dict[str, object]]) -> list[Signal]:
    host = host_of(url) or url
    scheme = urlsplit(url).scheme.lower()
    signals: list[Signal] = []

    missing = [label for key, label in _HEADERS if not headers.get(key)]
    if scheme == "https" and "HSTS" in missing:
        pass  # included below
    elif scheme != "https":
        missing = [label for label in missing if label != "HSTS"]
    if missing:
        signals.append(
            Signal(
                title=f"Missing hardening headers on {host}",
                bug_class="missing_security_headers",
                asset=host,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                rationale=(
                    "The response omits defense-in-depth headers: " + ", ".join(missing) + ". "
                    "These are rarely exploitable alone, but they increase the impact of other bugs."
                ),
                next_step="Use browser devtools or a proxy to confirm on the final response, then review in context.",
                remediation="Add HSTS, CSP, nosniff, frame restrictions, Referrer-Policy, and Permissions-Policy where appropriate.",
                evidence={"url": url, "missing": missing, "present": sorted(headers.keys())},
                source="headers",
                dedupe_key="security-headers",
            )
        )

    if scheme == "https":
        for cookie in cookies:
            name = str(cookie.get("name", ""))
            if not name:
                continue
            if cookie.get("prefix") == "__host-":
                violations = []
                if not cookie.get("secure"):
                    violations.append("Secure")
                if cookie.get("path") != "/":
                    violations.append("Path=/")
                if cookie.get("domain"):
                    violations.append("no Domain")
                if violations:
                    signals.append(_cookie_signal(host, url, name, f"__Host- prefix contract violated ({', '.join(violations)})", "low"))
                continue
            if not is_session_cookie(name):
                continue
            issues = []
            if not cookie.get("secure"):
                issues.append("Secure")
            if not cookie.get("httponly"):
                issues.append("HttpOnly")
            if not cookie.get("samesite"):
                issues.append("SameSite")
            if issues:
                severity = "medium" if ("Secure" in issues or "HttpOnly" in issues) else "low"
                signals.append(_cookie_signal(host, url, name, "missing " + ", ".join(issues), severity))
    else:
        for cookie in cookies:
            name = str(cookie.get("name", ""))
            if not name or not is_session_cookie(name):
                continue
            issues = []
            if not cookie.get("httponly"):
                issues.append("HttpOnly")
            if not cookie.get("samesite"):
                issues.append("SameSite")
            if issues:
                severity = "medium" if "HttpOnly" in issues else "low"
                signals.append(_cookie_signal(host, url, name, "missing " + ", ".join(issues), severity))

    banner = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if _VERSION_RE.search(banner) or _VERSION_RE.search(powered):
        signals.append(
            Signal(
                title=f"Version disclosure in response headers on {host}",
                bug_class="version_disclosure",
                asset=host,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                rationale="Server or framework versions are exposed, which helps attackers select known exploits.",
                next_step="Confirm the technology and patch level through manual testing before claiming a vulnerable version.",
                remediation="Suppress version banners and keep the stack patched.",
                evidence={"url": url, "server": banner, "x_powered_by": powered},
                source="headers",
                dedupe_key="version-disclosure",
            )
        )

    if headers.get("x-debug-token") or headers.get("x-debug-token-link"):
        signals.append(
            Signal(
                title=f"Debug token header exposed on {host}",
                bug_class="debug_header",
                asset=host,
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                rationale=(
                    "A debug header is present on a production-looking response. Some frameworks expose "
                    "profiler data or internal links through these headers."
                ),
                next_step="Inspect the header value and linked profiler in a low-impact way; check whether it reveals secrets or internal paths.",
                remediation="Disable debug/profiler headers in production.",
                evidence={
                    "url": url,
                    "x-debug-token_present": bool(headers.get("x-debug-token")),
                    "x-debug-token-link_present": bool(headers.get("x-debug-token-link")),
                },
                source="headers",
                dedupe_key="debug-header",
            )
        )
    return signals


def _cookie_signal(host: str, url: str, name: str, issue: str, severity: str) -> Signal:
    return Signal(
        title=f"Session cookie hardening gap on {host}: {name}",
        bug_class="cookie_flags",
        asset=host,
        severity=Severity(severity),
        confidence=Confidence.CONFIRMED,
        rationale=(
            f"The cookie {name!r} is {issue}. Cookie theft requires another primitive such as XSS or "
            "a network attacker, so this is a hardening issue rather than a standalone exploit."
        ),
        next_step="Check how the cookie is scoped and whether it is the primary session identifier.",
        remediation="Set Secure, HttpOnly, and SameSite=Lax/Strict (or None with Secure when cross-site is required).",
        evidence={"url": url, "cookie_name": name, "issue": issue},
        source="cookies",
        dedupe_key=f"cookie:{name}",
    )
