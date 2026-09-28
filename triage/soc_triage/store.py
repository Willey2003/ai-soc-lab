"""SQLite store for alerts, verdicts and analyst feedback."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS triage (
    alert_id     TEXT PRIMARY KEY,
    timestamp    TEXT,
    triaged_at   TEXT,
    rule_id      TEXT,
    rule_level   INTEGER,
    rule_description TEXT,
    agent_name   TEXT,
    src_ip       TEXT,
    score        INTEGER,
    priority     TEXT,
    verdict      TEXT,
    provider     TEXT,
    status       TEXT DEFAULT 'open',
    analyst_verdict TEXT,
    analyst_note TEXT,
    alert_json   TEXT,
    result_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_triage_score ON triage(score DESC);
CREATE INDEX IF NOT EXISTS idx_triage_time ON triage(triaged_at DESC);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

SUMMARY_COLUMNS = (
    "alert_id, timestamp, triaged_at, rule_id, rule_level, rule_description, agent_name, "
    "src_ip, score, priority, verdict, provider, status, analyst_verdict"
)


class Store:
    def __init__(self, path: Path) -> None:
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def exists(self, alert_id: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM triage WHERE alert_id=?", (alert_id,)).fetchone() is not None

    def save(self, alert: dict[str, Any], result: dict[str, Any]) -> None:
        with self._lock, self._db:
            self._db.execute(
                """INSERT OR REPLACE INTO triage
                (alert_id, timestamp, triaged_at, rule_id, rule_level, rule_description, agent_name,
                 src_ip, score, priority, verdict, provider, alert_json, result_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    alert["id"], alert.get("timestamp"), result["triaged_at"], alert.get("rule_id"),
                    alert.get("rule_level"), alert.get("rule_description"), alert.get("agent_name"),
                    alert.get("src_ip"), result["score"], result["priority"], result["verdict"],
                    result["provider"], json.dumps(alert), json.dumps(result),
                ),
            )

    def list(self, limit: int = 50, min_score: int = 0, status: str | None = None) -> list[dict[str, Any]]:
        sql = f"SELECT {SUMMARY_COLUMNS} FROM triage WHERE score >= ?"
        args: list[Any] = [min_score]
        if status:
            sql += " AND status = ?"
            args.append(status)
        sql += " ORDER BY triaged_at DESC LIMIT ?"
        args.append(max(1, min(limit, 500)))
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args)]

    def get(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM triage WHERE alert_id=?", (alert_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["alert"] = json.loads(out.pop("alert_json"))
        out["result"] = json.loads(out.pop("result_json"))
        return out

    def feedback(self, alert_id: str, verdict: str, note: str, status: str) -> bool:
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE triage SET analyst_verdict=?, analyst_note=?, status=? WHERE alert_id=?",
                (verdict, note[:2000], status, alert_id),
            )
        return cur.rowcount > 0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            by_priority = dict(self._db.execute("SELECT priority, COUNT(*) FROM triage GROUP BY priority").fetchall())
            by_verdict = dict(self._db.execute("SELECT verdict, COUNT(*) FROM triage GROUP BY verdict").fetchall())
            by_provider = dict(self._db.execute("SELECT provider, COUNT(*) FROM triage GROUP BY provider").fetchall())
            agree = self._db.execute(
                "SELECT COUNT(*), SUM(analyst_verdict = verdict) FROM triage WHERE analyst_verdict IS NOT NULL"
            ).fetchone()
        reviewed, matched = agree[0], agree[1] or 0
        return {
            "total": sum(by_priority.values()),
            "by_priority": by_priority,
            "by_verdict": by_verdict,
            "by_provider": by_provider,
            "analyst_reviewed": reviewed,
            "ai_agreement_rate": round(matched / reviewed, 3) if reviewed else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
