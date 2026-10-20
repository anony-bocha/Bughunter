from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import Hypothesis, Observation, confidence_rank, status_rank
from .util import canonical_json, ensure_dir, utc_now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    policy_path TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    stats_json TEXT NOT NULL DEFAULT '{}',
    options_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS assets (
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    ips TEXT NOT NULL DEFAULT '[]',
    cname TEXT NOT NULL DEFAULT '',
    cname_chain TEXT NOT NULL DEFAULT '[]',
    scheme TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    http_status INTEGER,
    title TEXT NOT NULL DEFAULT '',
    server TEXT NOT NULL DEFAULT '',
    tech TEXT NOT NULL DEFAULT '[]',
    in_scope INTEGER NOT NULL DEFAULT 1,
    wildcard INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, host)
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    asset TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    bug_class TEXT NOT NULL,
    asset TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    priority REAL NOT NULL,
    rationale TEXT NOT NULL,
    next_step TEXT NOT NULL,
    remediation TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (run_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    purpose TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    status_code INTEGER,
    elapsed_ms INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_run ON hypotheses(run_id, status, priority);
CREATE INDEX IF NOT EXISTS idx_requests_run ON requests(run_id, decision);
CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id, kind);
"""


class Store:
    def __init__(self, data_dir: str | Path):
        self.data_dir = ensure_dir(data_dir)
        self.path = self.data_dir / "bughunter.db"
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ---------------------------------------------------------------- runs
    def create_run(
        self,
        run_id: str,
        *,
        program: str,
        policy_path: str,
        policy_sha256: str,
        policy_json: dict[str, Any],
        mode: str,
        options: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO runs
                   (id, program, policy_path, policy_sha256, policy_json, mode, status, started_at, options_json)
                   VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?)""",
                (
                    run_id,
                    program,
                    policy_path,
                    policy_sha256,
                    canonical_json(policy_json),
                    mode,
                    utc_now_iso(),
                    canonical_json(options or {}),
                ),
            )

    def finish_run(self, run_id: str, status: str, stats: dict[str, Any] | None = None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE runs SET status = ?, finished_at = ?, stats_json = ? WHERE id = ?",
                (status, utc_now_iso(), canonical_json(stats or {}), run_id),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["policy"] = json.loads(result.pop("policy_json", "{}") or "{}")
        result["stats"] = json.loads(result.pop("stats_json", "{}") or "{}")
        result["options"] = json.loads(result.pop("options_json", "{}") or "{}")
        return result

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT r.*,
                   (SELECT COUNT(*) FROM hypotheses h WHERE h.run_id = r.id AND h.status = 'confirmed') AS confirmed,
                   (SELECT COUNT(*) FROM hypotheses h WHERE h.run_id = r.id AND h.status = 'lead') AS leads,
                   (SELECT COUNT(*) FROM assets a WHERE a.run_id = r.id) AS assets,
                   (SELECT COUNT(*) FROM requests q WHERE q.run_id = r.id) AS requests
                   FROM runs r ORDER BY r.started_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    # -------------------------------------------------------------- assets
    def upsert_asset(self, run_id: str, asset: dict[str, Any]) -> None:
        host = str(asset.get("host", "")).strip().lower()
        if not host:
            return
        now = utc_now_iso()
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT * FROM assets WHERE run_id = ? AND host = ?", (run_id, host)
            ).fetchone()
            row = {
                "source": "",
                "ips": [],
                "cname": "",
                "cname_chain": [],
                "scheme": "",
                "url": "",
                "http_status": None,
                "title": "",
                "server": "",
                "tech": [],
                "in_scope": 1,
                "wildcard": 0,
            }
            if existing:
                old = dict(existing)
                row.update(
                    {
                        "source": old["source"],
                        "ips": json.loads(old["ips"] or "[]"),
                        "cname": old["cname"],
                        "cname_chain": json.loads(old["cname_chain"] or "[]"),
                        "scheme": old["scheme"],
                        "url": old["url"],
                        "http_status": old["http_status"],
                        "title": old["title"],
                        "server": old["server"],
                        "tech": json.loads(old["tech"] or "[]"),
                        "in_scope": old["in_scope"],
                        "wildcard": old["wildcard"],
                    }
                )
            for key, value in asset.items():
                if value is None or value == "" or value == []:
                    continue
                row[key] = value
            self._conn.execute(
                """INSERT INTO assets
                   (run_id, host, source, ips, cname, cname_chain, scheme, url, http_status,
                    title, server, tech, in_scope, wildcard, first_seen, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(run_id, host) DO UPDATE SET
                     source=excluded.source, ips=excluded.ips, cname=excluded.cname,
                     cname_chain=excluded.cname_chain, scheme=excluded.scheme, url=excluded.url,
                     http_status=excluded.http_status, title=excluded.title, server=excluded.server,
                     tech=excluded.tech, in_scope=excluded.in_scope, wildcard=excluded.wildcard,
                     updated_at=excluded.updated_at""",
                (
                    run_id,
                    host,
                    row["source"],
                    canonical_json(row["ips"]),
                    row["cname"],
                    canonical_json(row["cname_chain"]),
                    row["scheme"],
                    row["url"],
                    row["http_status"],
                    row["title"],
                    row["server"],
                    canonical_json(row["tech"]),
                    int(bool(row["in_scope"])),
                    int(bool(row["wildcard"])),
                    now,
                    now,
                ),
            )

    def assets(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM assets WHERE run_id = ? ORDER BY in_scope DESC, host ASC", (run_id,)
            ).fetchall()
        assets = []
        for row in rows:
            item = dict(row)
            item["ips"] = json.loads(item["ips"] or "[]")
            item["cname_chain"] = json.loads(item["cname_chain"] or "[]")
            item["tech"] = json.loads(item["tech"] or "[]")
            item["in_scope"] = bool(item["in_scope"])
            item["wildcard"] = bool(item["wildcard"])
            assets.append(item)
        return assets

    # --------------------------------------------------------- observations
    def add_observation(self, run_id: str, observation: Observation) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO observations
                   (run_id, kind, asset, key, value, source, detail, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    observation.kind,
                    observation.asset,
                    observation.key,
                    canonical_json(observation.value),
                    observation.source,
                    observation.detail,
                    utc_now_iso(),
                ),
            )

    def observations(self, run_id: str, kind: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM observations WHERE run_id = ?"
        params: list[Any] = [run_id]
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        query += " ORDER BY id ASC"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["value"] = json.loads(item["value"] or "null")
            result.append(item)
        return result

    # ---------------------------------------------------------- hypotheses
    def upsert_hypothesis(self, run_id: str, hypothesis: Hypothesis) -> tuple[bool, int]:
        hypothesis.finalize()
        now = utc_now_iso()
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT * FROM hypotheses WHERE run_id = ? AND fingerprint = ?",
                (run_id, hypothesis.fingerprint),
            ).fetchone()
            if existing is None:
                cursor = self._conn.execute(
                    """INSERT INTO hypotheses
                       (run_id, fingerprint, title, bug_class, asset, severity, confidence, status, priority,
                        rationale, next_step, remediation, evidence, source, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run_id,
                        hypothesis.fingerprint,
                        hypothesis.title,
                        hypothesis.bug_class,
                        hypothesis.asset,
                        hypothesis.severity.value,
                        hypothesis.confidence.value,
                        hypothesis.status,
                        hypothesis.priority,
                        hypothesis.rationale,
                        hypothesis.next_step,
                        hypothesis.remediation,
                        canonical_json(hypothesis.evidence),
                        hypothesis.source,
                        now,
                        now,
                    ),
                )
                return True, int(cursor.lastrowid)

            old = dict(existing)
            old_evidence = json.loads(old["evidence"] or "{}")
            merged_evidence = {**old_evidence, **hypothesis.evidence}
            new_status_rank = status_rank(hypothesis.status)
            old_status_rank = status_rank(old["status"])
            new_conf_rank = confidence_rank(hypothesis.confidence.value)
            old_conf_rank = confidence_rank(old["confidence"])
            replace = new_status_rank > old_status_rank or (
                new_status_rank == old_status_rank and new_conf_rank >= old_conf_rank
            )
            if replace:
                self._conn.execute(
                    """UPDATE hypotheses SET title=?, severity=?, confidence=?, status=?, priority=?,
                       rationale=?, next_step=?, remediation=?, evidence=?, source=?, updated_at=?
                       WHERE id=?""",
                    (
                        hypothesis.title,
                        hypothesis.severity.value,
                        hypothesis.confidence.value,
                        hypothesis.status,
                        max(float(old["priority"]), hypothesis.priority),
                        hypothesis.rationale,
                        hypothesis.next_step,
                        hypothesis.remediation or old["remediation"],
                        canonical_json(merged_evidence),
                        hypothesis.source or old["source"],
                        now,
                        old["id"],
                    ),
                )
            else:
                self._conn.execute(
                    "UPDATE hypotheses SET evidence=?, updated_at=? WHERE id=?",
                    (canonical_json(merged_evidence), now, old["id"]),
                )
            return False, int(old["id"])

    def hypotheses(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM hypotheses WHERE run_id = ? ORDER BY priority DESC, id ASC", (run_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item["evidence"] or "{}")
            result.append(item)
        return result

    # ------------------------------------------------------------ requests
    def add_request(
        self,
        run_id: str,
        *,
        method: str,
        url: str,
        host: str,
        purpose: str,
        decision: str,
        reason: str = "",
        status_code: int | None = None,
        elapsed_ms: int = 0,
        bytes_read: int = 0,
        note: str = "",
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO requests
                   (run_id, ts, method, url, host, purpose, decision, reason, status_code,
                    elapsed_ms, bytes, note)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    utc_now_iso(),
                    method,
                    url,
                    host,
                    purpose,
                    decision,
                    reason,
                    status_code,
                    elapsed_ms,
                    bytes_read,
                    note,
                ),
            )

    def request_stats(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) AS n FROM requests WHERE run_id = ?", (run_id,)
            ).fetchone()["n"]
            by_decision = {
                row["decision"]: row["n"]
                for row in self._conn.execute(
                    "SELECT decision, COUNT(*) AS n FROM requests WHERE run_id = ? GROUP BY decision",
                    (run_id,),
                ).fetchall()
            }
            by_purpose = [
                dict(row)
                for row in self._conn.execute(
                    """SELECT purpose, COUNT(*) AS n FROM requests WHERE run_id = ?
                       GROUP BY purpose ORDER BY n DESC LIMIT 15""",
                    (run_id,),
                ).fetchall()
            ]
            by_host = [
                dict(row)
                for row in self._conn.execute(
                    """SELECT host, COUNT(*) AS n FROM requests WHERE run_id = ?
                       GROUP BY host ORDER BY n DESC LIMIT 15""",
                    (run_id,),
                ).fetchall()
            ]
        return {
            "total": total,
            "by_decision": by_decision,
            "by_purpose": by_purpose,
            "by_host": by_host,
        }

    def hypothesis_stats(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, severity, COUNT(*) AS n FROM hypotheses WHERE run_id = ? GROUP BY status, severity",
                (run_id,),
            ).fetchall()
        stats: dict[str, Any] = {"confirmed": 0, "lead": 0, "rejected": 0, "by_severity": {}}
        for row in rows:
            count = int(row["n"])
            stats[row["status"]] = stats.get(row["status"], 0) + count
            if row["status"] == "confirmed":
                stats["by_severity"][row["severity"]] = stats["by_severity"].get(row["severity"], 0) + count
        return stats

    def add_artifact(self, run_id: str, *, kind: str, name: str, path: str, sha256: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO artifacts (run_id, kind, name, path, sha256, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (run_id, kind, name, path, sha256, utc_now_iso()),
            )

    def artifacts(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM artifacts WHERE run_id = ? ORDER BY id ASC", (run_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self, run_id: str) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if run is None:
            return None
        with self._lock:
            asset_count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM assets WHERE run_id = ?", (run_id,)
            ).fetchone()["n"]
        return {
            "run": run,
            "assets": asset_count,
            "hypotheses": self.hypothesis_stats(run_id),
            "requests": self.request_stats(run_id),
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
