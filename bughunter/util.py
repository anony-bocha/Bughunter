from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def truncate(value: str, limit: int = 500, suffix: str = "...") -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - len(suffix))] + suffix


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def parse_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_public_ip(value: str) -> bool:
    ip = parse_ip(value)
    if ip is None:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def slugify(value: str, fallback: str = "program") -> str:
    slug = _SLUG_RE.sub("-", (value or "").lower()).strip("-")
    return (slug or fallback)[:60]


def ensure_dir(path: str | Path) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep + 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-2:]} (len={len(value)})"


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def decode_body(body: bytes, content_type: str = "") -> str:
    charset = "utf-8"
    match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type or "", re.I)
    if match:
        charset = match.group(1)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def looks_textual(content_type: str, body: bytes = b"") -> bool:
    ctype = (content_type or "").lower()
    if any(token in ctype for token in ("text/", "json", "javascript", "xml", "x-www-form-urlencoded", "graphql")):
        return True
    sample = body[:512]
    if not sample:
        return False
    printable = sum(1 for byte in sample if 9 <= byte <= 13 or 32 <= byte <= 126)
    return printable / len(sample) > 0.85


def host_of(url: str) -> str:
    try:
        return normalize_host(urlsplit(url).hostname or "")
    except ValueError:
        return ""


def path_of(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "/"
