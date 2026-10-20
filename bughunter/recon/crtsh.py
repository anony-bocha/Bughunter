from __future__ import annotations

import json
import re
from urllib.parse import quote

from ..net import PassiveClient
from ..util import normalize_host

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _valid_host(host: str) -> bool:
    return bool(_HOST_RE.match(host))


def discover_subdomains(
    passive: PassiveClient,
    domain: str,
    *,
    limit: int = 1000,
) -> tuple[list[str], str | None]:
    """Query certificate transparency for hostnames under a domain.

    This talks to crt.sh, never to the target. Returns (hosts, error).
    """
    domain = normalize_host(domain)
    url = f"https://crt.sh/?q={quote(f'%.{domain}', safe='')}&output=json"
    result = passive.get(url, purpose=f"ct:{domain}")
    if result.error:
        return [], result.error
    if result.status != 200:
        return [], f"crt.sh returned HTTP {result.status}"
    try:
        rows = json.loads(result.body.decode("utf-8", errors="replace") or "[]")
    except json.JSONDecodeError:
        snippet = result.body[:120].decode("utf-8", errors="replace").replace("\n", " ")
        return [], f"crt.sh returned non-JSON content: {snippet!r}"
    if not isinstance(rows, list):
        return [], "crt.sh returned an unexpected JSON shape"

    hosts: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            value = row.get(field)
            if not isinstance(value, str):
                continue
            for candidate in value.replace("\r", "\n").split("\n"):
                candidate = normalize_host(candidate)
                if not candidate or "*" in candidate:
                    continue
                if (candidate == domain or candidate.endswith("." + domain)) and _valid_host(candidate):
                    hosts.add(candidate)
                    if len(hosts) >= limit:
                        return sorted(hosts), None
    return sorted(hosts), None
