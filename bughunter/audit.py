from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .util import canonical_json, ensure_dir, sha256_text, utc_now_iso


class AuditLog:
    """Append-only, hash-chained JSONL audit log.

    Every record includes the hash of the previous record, so gaps or edits are
    detectable. The log is intentionally plain text and easy to review.
    """

    def __init__(self, path: str | Path, run_id: str, meta: dict[str, Any] | None = None):
        self.path = Path(path)
        ensure_dir(self.path.parent)
        self.run_id = run_id
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = "0" * 64
        self._fh = self.path.open("a", encoding="utf-8", newline="\n")
        if meta:
            self.record({"event": "run_started", **meta})

    def record(self, event: dict[str, Any]) -> str:
        with self._lock:
            self._seq += 1
            entry = {
                "ts": utc_now_iso(),
                "run_id": self.run_id,
                "seq": self._seq,
                "prev": self._prev,
                **event,
            }
            digest = sha256_text(canonical_json(entry))
            entry["hash"] = digest
            self._prev = digest
            self._fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            self._fh.flush()
            return digest

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                self._fh.close()

    @staticmethod
    def verify(path: str | Path) -> tuple[bool, str]:
        """Recompute the hash chain and confirm that no record was edited.

        Returns ``(ok, message)``. The check catches edits, deletions, and
        reordering: each record must reference the previous record's hash and
        carry a matching sequence number.
        """
        target = Path(path)
        if not target.exists():
            return False, f"audit log not found: {target}"
        try:
            lines = target.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return False, f"could not read audit log: {exc}"
        previous = "0" * 64
        sequence = 0
        for index, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, f"line {index}: invalid JSON"
            if not isinstance(entry, dict):
                return False, f"line {index}: record is not an object"
            digest = entry.pop("hash", None)
            if entry.get("prev") != previous:
                return False, f"line {index}: previous-hash mismatch (chain broken)"
            if entry.get("seq") != sequence + 1:
                return False, f"line {index}: sequence mismatch"
            expected = sha256_text(canonical_json(entry))
            if digest != expected:
                return False, f"line {index}: record hash mismatch (edited record)"
            previous = digest
            sequence += 1
        return True, f"{sequence} record(s) verified"

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
