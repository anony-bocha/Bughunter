from __future__ import annotations

import json
from urllib.parse import urlencode

from ..net import PassiveClient
from ..util import normalize_host


def discover_urls(
    passive: PassiveClient,
    domain: str,
    *,
    limit: int = 2000,
) -> tuple[list[str], str | None]:
    """Query the Wayback CDX index for archived URLs under a domain.

    This talks to web.archive.org, never to the target. The returned URLs are
    treated as intelligence only and are never replayed automatically.
    """
    domain = normalize_host(domain)
    query = urlencode(
        {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "filter": "statuscode:200",
            "limit": str(limit),
        }
    )
    url = f"https://web.archive.org/cdx/search/cdx?{query}"
    result = passive.get(url, purpose=f"wayback:{domain}")
    if result.error:
        return [], result.error
    if result.status != 200:
        return [], f"Wayback CDX returned HTTP {result.status}"
    text = result.body.decode("utf-8", errors="replace").strip()
    if not text:
        return [], None
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return [], "Wayback CDX returned non-JSON content"
    if not isinstance(rows, list) or not rows:
        return [], None
    urls: list[str] = []
    for row in rows[1:]:
        if isinstance(row, list) and row and isinstance(row[0], str):
            candidate = row[0].strip()
            if candidate.startswith(("http://", "https://")):
                urls.append(candidate)
                if len(urls) >= limit:
                    break
    return urls, None
