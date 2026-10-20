from __future__ import annotations

import json
from urllib.parse import urlsplit

from ..models import Confidence, Severity, Signal
from ..net import Capture, GatedSession
from ..util import dedupe, host_of

_QUERY = (
    "query BughunterIntrospection { __schema { queryType { name } mutationType { name } } }"
)


def probe(session: GatedSession, endpoints: list[str], *, max_endpoints: int = 3) -> list[Signal]:
    signals: list[Signal] = []
    candidates = [
        url for url in dedupe(endpoints) if urlsplit(url).scheme in {"http", "https"}
    ][:max_endpoints]
    payload = json.dumps({"query": _QUERY}).encode("utf-8")
    for url in candidates:
        try:
            result = session.request(
                "POST",
                url,
                purpose="graphql-introspection",
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                content=payload,
                capture=Capture.SMALL,
                max_bytes=262_144,
                follow_redirects=False,
            )
        except Exception:
            continue
        if result.blocked or result.error or result.status != 200 or not result.body:
            continue
        try:
            data = json.loads(result.body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        schema = ((data or {}).get("data") or {}).get("__schema")
        if not isinstance(schema, dict):
            continue
        query_type = ((schema.get("queryType") or {}).get("name") or "")
        mutation_type = ((schema.get("mutationType") or {}).get("name") or "")
        signals.append(
            Signal(
                title=f"GraphQL introspection enabled on {host_of(url)}",
                bug_class="graphql_introspection",
                asset=host_of(url),
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                rationale=(
                    "The endpoint returned GraphQL schema metadata to an unauthenticated introspection query. "
                    "Introspection is often intentional, but it can reveal hidden mutations and sensitive fields "
                    "that deserve authorization testing."
                ),
                next_step=(
                    "Review the schema for sensitive mutations and fields, then manually test object-level "
                    "authorization with a test account if the program permits it. Do not dump the entire schema repeatedly."
                ),
                remediation="Disable introspection in production or restrict it to authenticated developers; enforce field-level authorization.",
                evidence={
                    "url": url,
                    "query_type": query_type,
                    "mutation_type": mutation_type,
                    "status": result.status,
                },
                source="graphql",
                dedupe_key=url,
            )
        )
    return signals
