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
