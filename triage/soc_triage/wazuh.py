"""Read Wazuh alerts.json and turn raw alerts into a compact, stable shape."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Iterator

LOG = logging.getLogger(__name__)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def alert_id(alert: dict[str, Any]) -> str:
    """Wazuh ids repeat across restarts, so pair them with the timestamp."""
    raw = f"{alert.get('id', '')}|{alert.get('timestamp', '')}"
    if raw == "|":
        raw = json.dumps(alert, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def normalize(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    mitre = rule.get("mitre") or {}
    win = (data.get("win") or {}).get("eventdata") or {}
    syscheck = alert.get("syscheck") or {}

    return {
        "id": alert_id(alert),
        "timestamp": alert.get("timestamp", ""),
        "rule_id": str(rule.get("id", "")),
        "rule_level": int(rule.get("level", 0) or 0),
        "rule_description": rule.get("description", ""),
        "rule_groups": _as_list(rule.get("groups")),
        "mitre_ids": _as_list(mitre.get("id")),
        "mitre_tactics": _as_list(mitre.get("tactic")),
        "mitre_techniques": _as_list(mitre.get("technique")),
        "agent_name": agent.get("name", ""),
        "agent_ip": agent.get("ip", ""),
        "src_ip": data.get("srcip") or win.get("sourceIp") or "",
        "dst_ip": data.get("dstip") or win.get("destinationIp") or "",
        "src_user": data.get("srcuser") or data.get("dstuser") or win.get("user") or win.get("targetUserName") or "",
        "process": win.get("image") or data.get("process") or "",
        "command_line": win.get("commandLine") or data.get("command") or "",
        "file_path": syscheck.get("path", ""),
        "file_event": syscheck.get("event", ""),
        "hashes": {
            k: v
            for k, v in {
                "md5": syscheck.get("md5_after") or win.get("md5"),
                "sha256": syscheck.get("sha256_after") or win.get("sha256"),
            }.items()
            if v
        },
        "firedtimes": int(rule.get("firedtimes", 1) or 1),
        "full_log": (alert.get("full_log") or "")[:2000],
        "location": alert.get("location", ""),
    }


class AlertTailer:
    """Follow alerts.json like `tail -F`, surviving rotation and truncation."""

    def __init__(self, path: Path, start_at_end: bool = True) -> None:
        self.path = path
        self._pos: int | None = None
        self._inode: int | None = None
        self._start_at_end = start_at_end
        self._partial = b""

    def _open_state(self) -> None:
        st = os.stat(self.path)
        if self._inode != st.st_ino:
            first_open = self._inode is None
            self._inode = st.st_ino
            self._pos = st.st_size if (first_open and self._start_at_end) else 0
            self._partial = b""
        elif self._pos is not None and st.st_size < self._pos:
            LOG.info("alerts file truncated, starting from the top")
            self._pos = 0
            self._partial = b""

    def read_new(self) -> Iterator[dict[str, Any]]:
        try:
            self._open_state()
        except FileNotFoundError:
            return
        with open(self.path, "rb") as fh:
            fh.seek(self._pos or 0)
            chunk = fh.read()
            self._pos = fh.tell()
        if not chunk:
            return
        lines = (self._partial + chunk).split(b"\n")
        self._partial = lines.pop()  # keep an unterminated last line for next time
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                LOG.warning("skipping malformed alert line (%d bytes)", len(line))


class IndexerSource:
    """Poll the Wazuh indexer (OpenSearch) for new alerts, read-only.

    Useful when the triage service can't share a disk with the Wazuh manager,
    e.g. running in its own Kubernetes namespace. Uses `search_after` on
    (timestamp, id) so nothing is skipped or repeated between polls, and keeps
    that cursor in the store so a restart resumes where it left off.
    """

    def __init__(
        self,
        url: str,
        index: str,
        user: str,
        password: str,
        verify: bool | str,
        min_level: int,
        start_at_end: bool,
        cursor_store: Any = None,
        batch: int = 200,
        timeout: float = 30,
    ) -> None:
        import requests

        self.search_url = f"{url.rstrip('/')}/{index}/_search"
        self.http = requests.Session()
        if user:
            self.http.auth = (user, password)
        self.http.verify = verify
        self.min_level = min_level
        self.batch = batch
        self.timeout = timeout
        self.cursor_store = cursor_store
        saved = cursor_store.get_meta("indexer_cursor") if cursor_store else None
        self.cursor: list[Any] | None = json.loads(saved) if saved else None
        self.lookback = "now" if start_at_end else "now-24h"

    def _query(self) -> dict[str, Any]:
        filters: list[dict[str, Any]] = [{"range": {"rule.level": {"gte": self.min_level}}}]
        if self.cursor is None:
            filters.append({"range": {"timestamp": {"gte": self.lookback}}})
        body: dict[str, Any] = {
            "size": self.batch,
            "sort": [{"timestamp": "asc"}, {"id": "asc"}],
            "query": {"bool": {"filter": filters}},
        }
        if self.cursor is not None:
            body["search_after"] = self.cursor
        return body

    def read_new(self) -> Iterator[dict[str, Any]]:
        while True:
            resp = self.http.post(self.search_url, json=self._query(), timeout=self.timeout)
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            if not hits:
                return
            for hit in hits:
                yield hit.get("_source", {})
                self.cursor = hit.get("sort")
            if self.cursor_store and self.cursor is not None:
                self.cursor_store.set_meta("indexer_cursor", json.dumps(self.cursor))
            if len(hits) < self.batch:
                return


SAMPLES_FILE = Path(__file__).resolve().parents[1] / "samples" / "wazuh_alerts.jsonl"


class SimulatedSource:
    """Replays bundled sample alerts with fresh timestamps, one every `every` seconds.

    For clusters without Wazuh: the queue fills with realistic alerts so the AI
    triage path (and the UI) can be exercised end to end. Real alerts can still
    be pushed in at any time with POST /api/triage.
    """

    def __init__(self, every: float, samples: Path = SAMPLES_FILE, clock: Any = None) -> None:
        import time
        from datetime import datetime, timezone

        self._now = clock or time.monotonic
        self._utc = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
        self.every = every
        self.samples = [json.loads(l) for l in samples.read_text().splitlines() if l.strip()]
        self._next_at = self._now()
        self._i = 0
        self._seq = 0

    def read_new(self) -> Iterator[dict[str, Any]]:
        if not self.samples or self._now() < self._next_at:
            return
        self._next_at = self._now() + self.every
        alert = json.loads(json.dumps(self.samples[self._i % len(self.samples)]))
        self._i += 1
        self._seq += 1
        alert["timestamp"] = self._utc()
        alert["id"] = f"sim.{self._seq}.{alert.get('id', '')}"
        alert.setdefault("rule", {})["groups"] = list(alert.get("rule", {}).get("groups", [])) + ["simulated"]
        yield alert
