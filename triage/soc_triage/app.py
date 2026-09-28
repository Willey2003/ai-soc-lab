"""HTTP API, a small analyst queue page, and the background alert tailer."""

from __future__ import annotations

import hmac
import html
import logging
import threading
from typing import Any

from flask import Flask, abort, jsonify, request

from .config import Settings
from .llm import build_providers
from .store import Store
from .triage import VERDICTS, TriageEngine
from .wazuh import AlertTailer, IndexerSource, SimulatedSource, normalize

LOG = logging.getLogger(__name__)
STATUSES = {"open", "acknowledged", "escalated", "closed"}


class Service:
    def __init__(self, settings: Settings, engine: TriageEngine | None = None, store: Store | None = None) -> None:
        self.settings = settings
        self.engine = engine or TriageEngine(settings, build_providers(settings))
        self.store = store or Store(settings.db_path)
        self.stop = threading.Event()
        self.last_error = ""

    def process(self, raw: dict[str, Any], force: bool = False) -> dict[str, Any] | None:
        alert = normalize(raw)
        if not force and alert["rule_level"] < self.settings.min_rule_level:
            return None
        if not force and self.store.exists(alert["id"]):
            return None
        result = self.engine.triage(alert)
        self.store.save(alert, result)
        LOG.info(
            "triaged %s rule=%s level=%s -> %s/%s score=%s via %s",
            alert["id"], alert["rule_id"], alert["rule_level"],
            result["verdict"], result["priority"], result["score"], result["provider"],
        )
        return result

    def make_source(self) -> AlertTailer | IndexerSource | SimulatedSource | None:
        s = self.settings
        if s.alert_source == "none":
            LOG.info("no alert source; send alerts with POST /api/triage")
            return None
        if s.alert_source == "simulate":
            LOG.info("simulating one sample Wazuh alert every %ss", s.simulate_every)
            return SimulatedSource(s.simulate_every)
        if s.alert_source == "indexer":
            if s.indexer_verify is False:
                LOG.warning("INDEXER_VERIFY_TLS=false: indexer certificate is not checked")
            LOG.info("polling %s/%s (min level %d)", s.indexer_url, s.indexer_index, s.min_rule_level)
            return IndexerSource(
                s.indexer_url, s.indexer_index, s.indexer_user, s.indexer_password,
                s.indexer_verify, s.min_rule_level, s.start_at_end, cursor_store=self.store,
            )
        if s.alert_source != "file":
            raise ValueError(
                f"ALERT_SOURCE must be file, indexer, simulate or none, not {s.alert_source!r}"
            )
        LOG.info("watching %s (min level %d)", s.alerts_file, s.min_rule_level)
        return AlertTailer(s.alerts_file, s.start_at_end)

    def run_tailer(self) -> None:
        tailer = self.make_source()
        if tailer is None:
            return
        while not self.stop.is_set():
            try:
                for raw in tailer.read_new():
                    self.process(raw)
                self.last_error = ""
            except Exception as exc:  # keep the tailer alive whatever one alert does
                self.last_error = str(exc)[:300]
                LOG.exception("tailer error")
            self.stop.wait(self.settings.poll_seconds)


def create_app(service: Service) -> Flask:
    app = Flask(__name__)
    settings = service.settings

    @app.before_request
    def require_key() -> None:
        if request.path in ("/health",) or not settings.api_key:
            return
        supplied = request.headers.get("X-API-Key", "") or request.args.get("key", "")
        if not hmac.compare_digest(supplied, settings.api_key):
            abort(401)

    @app.get("/health")
    def health():
        return jsonify(
            status="ok" if not service.last_error else "degraded",
            source=settings.alert_source,
            providers=[p.name for p in service.engine.providers],
            last_error=service.last_error,
        )

    @app.post("/api/triage")
    def triage_now():
        raw = request.get_json(silent=True)
        if not isinstance(raw, dict):
            abort(400, "send one Wazuh alert as a JSON object")
        result = service.process(raw, force=True)
        return jsonify(result)

    @app.get("/api/alerts")
    def list_alerts():
        return jsonify(
            service.store.list(
                limit=request.args.get("limit", 50, type=int),
                min_score=request.args.get("min_score", 0, type=int),
                status=request.args.get("status"),
            )
        )

    @app.get("/api/alerts/<alert_id>")
    def get_alert(alert_id: str):
        row = service.store.get(alert_id)
        if not row:
            abort(404)
        return jsonify(row)

    @app.post("/api/alerts/<alert_id>/feedback")
    def feedback(alert_id: str):
        body = request.get_json(silent=True) or {}
        verdict = body.get("verdict", "")
        status = body.get("status", "closed")
        if verdict not in VERDICTS or status not in STATUSES:
            abort(400, f"verdict must be one of {sorted(VERDICTS)}, status one of {sorted(STATUSES)}")
        if not service.store.feedback(alert_id, verdict, str(body.get("note", "")), status):
            abort(404)
        return jsonify(ok=True)

    @app.get("/api/stats")
    def stats():
        return jsonify(service.store.stats())

    @app.get("/")
    def queue_page():
        rows = service.store.list(limit=100)
        colors = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#15803d", "info": "#475569"}
        body = "".join(
            "<tr><td>{s}</td><td><b style='color:{c}'>{p}</b></td><td>{v}</td><td>{d}</td>"
            "<td>{a}</td><td>{ip}</td><td>{pr}</td><td>{st}</td>"
            "<td><a href='/api/alerts/{id}'>json</a></td></tr>".format(
                s=r["score"], c=colors.get(r["priority"], "#000"), p=html.escape(r["priority"]),
                v=html.escape(r["verdict"] or ""), d=html.escape(r["rule_description"] or ""),
                a=html.escape(r["agent_name"] or ""), ip=html.escape(r["src_ip"] or ""),
                pr=html.escape(r["provider"] or ""), st=html.escape(r["status"] or ""), id=r["alert_id"],
            )
            for r in rows
        )
        return (
            "<!doctype html><meta charset=utf-8><title>SOC Triage Queue</title>"
            "<style>body{font:14px system-ui;margin:24px}table{border-collapse:collapse;width:100%}"
            "td,th{border-bottom:1px solid #ddd;padding:6px;text-align:left}</style>"
            "<h1>AI SOC triage queue</h1><p>Newest first. Auto-refreshes every 15s.</p>"
            "<meta http-equiv=refresh content=15>"
            "<table><tr><th>Score</th><th>Priority</th><th>AI verdict</th><th>Rule</th><th>Agent</th>"
            f"<th>Source IP</th><th>Engine</th><th>Status</th><th></th></tr>{body}</table>"
        )

    return app
