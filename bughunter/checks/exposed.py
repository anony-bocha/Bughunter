from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from ..models import Confidence, Severity, Signal
from ..net import Capture, GatedSession
from ..util import host_of


@dataclass(frozen=True)
class ExposedPath:
    path: str
    label: str
    signature: bytes | None
    severity: Severity
    confidence: Confidence
    read_body: bool
    allow_html: bool = False
    method: str = "GET"


PATHS: tuple[ExposedPath, ...] = (
    ExposedPath("/.git/HEAD", "Git metadata", b"ref:", Severity.HIGH, Confidence.CONFIRMED, True),
    ExposedPath("/.env", "environment file", None, Severity.CRITICAL, Confidence.LIKELY, False, method="HEAD"),
    ExposedPath("/.git/config", "Git config", b"[core]", Severity.HIGH, Confidence.CONFIRMED, True),
    ExposedPath("/.DS_Store", "macOS metadata file", b"\x00\x00\x00\x01Bud1", Severity.LOW, Confidence.CONFIRMED, True),
    ExposedPath("/.svn/entries", "SVN metadata", None, Severity.MEDIUM, Confidence.LIKELY, False, method="HEAD"),
    ExposedPath("/server-status", "Apache server-status", b"Apache Server Status", Severity.MEDIUM, Confidence.CONFIRMED, True),
    ExposedPath("/actuator/health", "Spring Actuator health", b'"status"', Severity.LOW, Confidence.CONFIRMED, True),
    ExposedPath("/actuator/env", "Spring Actuator environment", None, Severity.MEDIUM, Confidence.LIKELY, False, method="HEAD"),
    ExposedPath("/swagger-ui.html", "Swagger UI", None, Severity.LOW, Confidence.LIKELY, False, allow_html=True, method="HEAD"),
    ExposedPath("/openapi.json", "OpenAPI specification", b'"openapi"', Severity.LOW, Confidence.CONFIRMED, True),
    ExposedPath("/phpinfo.php", "phpinfo()", b"PHP Version", Severity.MEDIUM, Confidence.CONFIRMED, True),
    ExposedPath("/backup.zip", "backup archive", b"PK\x03\x04", Severity.HIGH, Confidence.CONFIRMED, True),
    ExposedPath("/.env.local", "environment file", None, Severity.CRITICAL, Confidence.LIKELY, False, method="HEAD"),
    ExposedPath("/.aws/credentials", "AWS credentials file", None, Severity.HIGH, Confidence.LIKELY, False, method="HEAD"),
    ExposedPath("/backup.sql", "SQL dump", None, Severity.HIGH, Confidence.LIKELY, False, method="HEAD"),
    ExposedPath("/api-docs", "API documentation", None, Severity.LOW, Confidence.LIKELY, False, allow_html=True, method="HEAD"),
)


def check_exposed(session: GatedSession, base_url: str, *, limit: int = 12) -> list[Signal]:
    parts = urlsplit(base_url)
    if not parts.scheme or not parts.hostname:
        return []
    root = f"{parts.scheme}://{parts.netloc}/"
    signals: list[Signal] = []
    for spec in PATHS[: max(0, limit)]:
        if getattr(session, "budget_exhausted", False):
            break
        url = urljoin(root, spec.path.lstrip("/"))
        headers = {"Range": "bytes=0-1024"} if spec.method == "GET" else {}
        try:
            result = session.request(
                spec.method,
                url,
                purpose=f"exposed:{spec.label}",
                headers=headers,
                capture=Capture.SMALL if spec.read_body else Capture.NONE,
                max_bytes=2048,
                follow_redirects=True,
            )
        except Exception:
            continue
        if result.blocked or result.error or result.status not in {200, 206}:
            continue
        content_type = (result.content_type or "").lower()
        body = result.body or b""
        matched = False
        if spec.signature is not None:
            if spec.path == "/.git/HEAD":
                stripped = body.strip()
                matched = stripped.startswith(b"ref:") or (
                    len(stripped) >= 40 and all(char in b"0123456789abcdef" for char in stripped[:40])
                )
            else:
                matched = spec.signature in body[:2048]
        elif spec.allow_html and "text/html" in content_type:
            matched = True
        elif "text/html" not in content_type:
            matched = True
        if spec.signature is not None and not matched:
            continue
        if not matched:
            continue
        signals.append(
            Signal(
                title=f"Exposed {spec.label} on {host_of(url)}",
                bug_class="exposed_file",
                asset=host_of(url),
                severity=spec.severity,
                confidence=spec.confidence,
                rationale=(
                    f"A request for {spec.path} returned HTTP {result.status} with a matching signature. "
                    "The response body was capped and is not stored in this report. Exposed metadata or "
                    "configuration files commonly enable source disclosure or credential theft."
                ),
                next_step=(
                    "Verify the response manually with a single low-impact request. If it contains secrets, "
                    "do not download or share them; notify the program immediately and rotate affected credentials."
                ),
                remediation=(
                    "Remove the file from the web root, block dotfiles and debug endpoints, and rotate any "
                    "credentials that may have been exposed."
                ),
                evidence={
                    "url": url,
                    "status": result.status,
                    "content_type": result.content_type,
                    "content_length": result.headers.get("content-length", ""),
                    "body_captured": spec.read_body,
                    "signature_matched": True if spec.signature else "status/content-type signal",
                },
                source="exposed-file",
                dedupe_key=spec.path,
            )
        )
    return signals
