from __future__ import annotations

from ..models import Confidence, Severity, Signal
from ..net import TLSInfo


def evaluate(host: str, info: TLSInfo) -> list[Signal]:
    signals: list[Signal] = []
    if info.error:
        lower = info.error.lower()
        if "expired" in lower:
            bug_class = "tls_expired"
            title = f"Expired TLS certificate on {host}"
        elif "hostname" in lower or "match" in lower:
            bug_class = "tls_hostname_mismatch"
            title = f"TLS hostname mismatch on {host}"
        else:
            bug_class = "tls_error"
            title = f"TLS connection or certificate problem on {host}"
        signals.append(
            Signal(
                title=title,
                bug_class=bug_class,
                asset=host,
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                rationale=(
                    "A verified TLS connection could not be established. This can indicate an expired, "
                    "misissued, or hostname-mismatched certificate, or an unsupported protocol."
                ),
                next_step="Inspect the certificate chain with a TLS client and confirm the failure mode before reporting.",
                remediation="Renew and correctly configure the certificate chain; disable obsolete protocol versions.",
                evidence={"host": host, "port": info.port, "error": info.error},
                source="tls",
                dedupe_key=bug_class,
            )
        )
        return signals

    if info.protocol in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
        signals.append(
            Signal(
                title=f"Obsolete TLS protocol on {host}",
                bug_class="tls_weak_protocol",
                asset=host,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                rationale=f"The endpoint negotiated {info.protocol}, which is deprecated and considered insecure.",
                next_step="Confirm with a second TLS client and check whether modern clients are forced onto the legacy protocol.",
                remediation="Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+ with modern cipher suites.",
                evidence={"host": host, "protocol": info.protocol, "cipher": info.cipher},
                source="tls",
                dedupe_key="tls-protocol",
            )
        )
    if info.days_left is not None and info.days_left < 0:
        signals.append(
            Signal(
                title=f"Expired TLS certificate on {host}",
                bug_class="tls_expired",
                asset=host,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                rationale=f"The certificate expired {abs(info.days_left):.0f} day(s) ago.",
                next_step="Verify with a browser or TLS client and check whether the service is externally reachable.",
                remediation="Renew the certificate and automate expiry monitoring.",
                evidence={"host": host, "not_after": info.not_after, "days_left": info.days_left, "issuer": info.issuer},
                source="tls",
                dedupe_key="tls-expired",
            )
        )
    elif info.days_left is not None and info.days_left < 14:
        signals.append(
            Signal(
                title=f"TLS certificate nearing expiry on {host}",
                bug_class="tls_expiring",
                asset=host,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                rationale=f"The certificate expires in {info.days_left:.1f} day(s).",
                next_step="Confirm the certificate is used in production and that renewal is automated.",
                remediation="Renew the certificate and add expiry monitoring/automation.",
                evidence={"host": host, "not_after": info.not_after, "days_left": info.days_left},
                source="tls",
                dedupe_key="tls-expiring",
            )
        )
    cipher = (info.cipher or "").upper()
    if any(token in cipher for token in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT")):
        signals.append(
            Signal(
                title=f"Weak TLS cipher on {host}",
                bug_class="tls_weak_cipher",
                asset=host,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                rationale=f"The endpoint negotiated {info.cipher}, which is considered weak.",
                next_step="Confirm the negotiated cipher with a second client and review the server's TLS configuration.",
                remediation="Remove legacy ciphers and prefer AEAD suites (AES-GCM/ChaCha20-Poly1305).",
                evidence={"host": host, "protocol": info.protocol, "cipher": info.cipher},
                source="tls",
                dedupe_key="tls-cipher",
            )
        )
    return signals
