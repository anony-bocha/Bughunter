from __future__ import annotations

from urllib.parse import urlsplit

from ..models import Confidence, Severity, Signal
from ..net import Capture, GatedSession
from ..util import dedupe, host_of

_TEST_ORIGIN = "https://bughunter.invalid"


def probe(session: GatedSession, endpoints: list[str], *, max_endpoints: int = 6) -> list[Signal]:
    signals: list[Signal] = []
    candidates = [
        url
        for url in dedupe(endpoints)
        if urlsplit(url).scheme in {"http", "https"}
    ][:max_endpoints]
    for url in candidates:
        try:
            result = session.request(
                "GET",
                url,
                purpose="cors",
                headers={"Origin": _TEST_ORIGIN},
                capture=Capture.NONE,
                follow_redirects=False,
            )
        except Exception:
            continue
        if result.blocked or result.error or result.status is None or result.status >= 400:
            continue
        acao = result.header("access-control-allow-origin").strip()
        acac = result.header("access-control-allow-credentials").strip().lower() == "true"
        vary = result.header("vary")
        if not acao:
            continue
        if acao == _TEST_ORIGIN:
            severity = Severity.HIGH if acac else Severity.MEDIUM
            title = (
                f"CORS reflects arbitrary origin with credentials on {host_of(url)}"
                if acac
                else f"CORS reflects arbitrary origin on {host_of(url)}"
            )
            signals.append(
                Signal(
                    title=title,
                    bug_class="cors_misconfiguration",
                    asset=host_of(url),
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    rationale=(
                        "The server reflected an attacker-controlled Origin in Access-Control-Allow-Origin"
                        + (" and allowed credentials. A malicious site could read authenticated responses." if acac
                           else ". This may allow cross-origin reads of unauthenticated or token-bearing responses.")
                    ),
                    next_step=(
                        "Confirm whether the endpoint returns sensitive data and whether credentials are required. "
                        "Use a harmless test account only if the program allows it."
                    ),
                    remediation=(
                        "Use a strict allowlist of trusted origins, validate the Origin server-side, avoid "
                        "reflecting arbitrary origins, and do not combine wildcard/reflected origins with credentials."
                    ),
                    evidence={
                        "url": url,
                        "request_origin": _TEST_ORIGIN,
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": acac,
                        "vary": vary,
                        "status": result.status,
                    },
                    source="cors",
                    dedupe_key=url,
                )
            )
        elif acao == "*" and acac:
            signals.append(
                Signal(
                    title=f"CORS wildcard with credentials on {host_of(url)}",
                    bug_class="cors_misconfiguration",
                    asset=host_of(url),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    rationale=(
                        "The server advertises both a wildcard origin and credentials. Browsers normally reject "
                        "this combination, but some clients or proxy layers may handle it inconsistently."
                    ),
                    next_step="Check whether a reflected origin is accepted and whether sensitive data is returned.",
                    remediation="Replace the wildcard with an explicit origin allowlist and avoid credentialed wildcard CORS.",
                    evidence={
                        "url": url,
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": acac,
                        "request_origin": _TEST_ORIGIN,
                    },
                    source="cors",
                    dedupe_key=url,
                )
            )
    return signals
