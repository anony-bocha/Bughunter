from __future__ import annotations

from ..models import Confidence, Severity, Signal
from ..recon.takeover import matching_signature, provider_for


def evaluate(
    host: str,
    cname_chain: tuple[str, ...],
    text: str | None,
    *,
    status: int | None,
    content_type: str = "",
) -> Signal | None:
    if not cname_chain or not text:
        return None
    provider = provider_for(cname_chain)
    if provider is None:
        return None
    signature = matching_signature(provider, text)
    if not signature:
        return None
    return Signal(
        title=f"Possible subdomain takeover on {host}",
        bug_class="subdomain_takeover",
        asset=host,
        severity=Severity.HIGH,
        confidence=Confidence.LIKELY,
        rationale=(
            f"The hostname points to {provider.name} via CNAME and the response contains that provider's "
            "unclaimed-resource message. If the resource is unclaimed, an attacker may be able to take it over. "
            "This is a detection-only lead; no resource was registered or claimed."
        ),
        next_step=(
            "Manually verify the CNAME target and the provider's claim process. Do not register, claim, or modify "
            "the resource. Report the dangling record to the program owner with the exact CNAME chain."
        ),
        remediation=(
            "Remove the dangling DNS record or reclaim the third-party resource. Monitor CNAME targets and "
            "require ownership verification before deleting app resources."
        ),
        evidence={
            "host": host,
            "cname_chain": list(cname_chain),
            "provider": provider.name,
            "matched_signature": signature,
            "http_status": status,
            "content_type": content_type,
        },
        source="takeover",
        dedupe_key="|".join(cname_chain),
    )
