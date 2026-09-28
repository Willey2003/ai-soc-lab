import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from soc_triage.app import Service, create_app
from soc_triage.config import Settings
from soc_triage.enrich import baseline, extract_iocs, redact
from soc_triage.llm import build_providers
from soc_triage.store import Store
from soc_triage.triage import TriageEngine, parse_model_json
from soc_triage.wazuh import AlertTailer, normalize

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "wazuh_alerts.jsonl"
RAW = [json.loads(line) for line in SAMPLES.read_text().splitlines() if line.strip()]
BRUTE, MIMIKATZ, FIM, WEB404, REVSHELL, SUDO = RAW

GOOD_ANSWER = {
    "verdict": "true_positive",
    "severity": "critical",
    "confidence": 0.9,
    "summary": "Reverse shell from db-01 to external IP.",
    "attack_story": "Attacker has code execution as postgres.",
    "mitre": ["T1059.004", "not-a-technique"],
    "recommended_actions": ["Isolate db-01", "Block 45.33.32.156"],
    "false_positive_hints": [],
}


class FakeLLM(BaseHTTPRequestHandler):
    """Speaks both the Ollama /api/chat and OpenAI /chat/completions shapes."""

    answer: str = json.dumps(GOOD_ANSWER)
    status: int = 200
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        if self.status == 429:
            self.send_header("Retry-After", "60")
        self.end_headers()
        if self.path == "/api/chat":
            payload = {"message": {"role": "assistant", "content": self.answer}}
        else:
            payload = {"choices": [{"message": {"role": "assistant", "content": self.answer}}]}
        self.wfile.write(json.dumps(payload).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_llm():
    FakeLLM.answer, FakeLLM.status, FakeLLM.seen = json.dumps(GOOD_ANSWER), 200, []
    server = HTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def make_settings(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings()


def test_normalize_extracts_key_fields():
    a = normalize(MIMIKATZ)
    assert a["rule_level"] == 12
    assert a["mitre_ids"] == ["T1003.001"]
    assert "sekurlsa" in a["command_line"]
    assert a["hashes"]["sha256"].startswith("9f2c")
    assert normalize(MIMIKATZ)["id"] == a["id"]  # stable
    assert normalize(BRUTE)["id"] != a["id"]


def test_baseline_ranks_attacks_above_noise():
    scores = {name: baseline(normalize(r))["score"] for name, r in
              zip(["brute", "mimi", "fim", "web", "rev", "sudo"], RAW)}
    assert scores["rev"] >= 85 and scores["mimi"] >= 85
    assert scores["web"] < 40 and scores["sudo"] < 20
    assert scores["brute"] > scores["web"]


def test_iocs_keep_only_public_ips():
    iocs = extract_iocs(normalize(REVSHELL))
    assert iocs["public_ips"] == ["45.33.32.156"]
    assert extract_iocs(normalize(WEB404))["public_ips"] == []
    assert extract_iocs(normalize(FIM))["md5"] == ["5d41402abc4b2a76b9719d911017c592"]


def test_redaction_hides_internal_details_but_keeps_iocs():
    red = redact(normalize(REVSHELL))
    dump = json.dumps(red)
    assert "192.168.0.30" not in dump and "db-01" not in dump and "postgres" not in dump
    assert "45.33.32.156" in dump


@pytest.mark.parametrize("text", [
    json.dumps(GOOD_ANSWER),
    "Sure! ```json\n" + json.dumps(GOOD_ANSWER) + "\n``` hope that helps",
    "Here you go: " + json.dumps(GOOD_ANSWER) + " done.",
])
def test_parse_model_json_tolerates_chatter(text):
    assert parse_model_json(text)["verdict"] == "true_positive"


def test_ollama_verdict_is_validated_and_blended(monkeypatch, tmp_path, fake_llm):
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="ollama", OLLAMA_URL=fake_llm)
    result = TriageEngine(s, build_providers(s)).triage(normalize(REVSHELL))
    assert result["provider"] == "ollama"
    assert result["verdict"] == "true_positive"
    assert result["mitre"] == ["T1059.004"]  # junk technique dropped
    assert result["priority"] == "critical"
    sent = FakeLLM.seen[0]["body"]
    assert sent["format"] == "json" and sent["stream"] is False
    assert "db-01" in sent["messages"][1]["content"]  # local model sees everything


def test_hosted_gets_redacted_alert_and_bearer_key(monkeypatch, tmp_path, fake_llm):
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="hosted",
                      HOSTED_API_URL=fake_llm + "/openai/v1/chat/completions", HOSTED_API_KEY="k123")
    result = TriageEngine(s, build_providers(s)).triage(normalize(REVSHELL))
    assert result["provider"] == "hosted"
    call = FakeLLM.seen[0]
    assert call["auth"] == "Bearer k123"
    prompt = call["body"]["messages"][1]["content"]
    assert "db-01" not in prompt and "192.168.0.30" not in prompt and "45.33.32.156" in prompt


def test_falls_back_down_the_chain(monkeypatch, tmp_path, fake_llm):
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="ollama,hosted,heuristic",
                      OLLAMA_URL="http://127.0.0.1:9", LLM_TIMEOUT_SECONDS="2",
                      HOSTED_API_URL=fake_llm + "/v1/chat/completions", HOSTED_API_KEY="k")
    result = TriageEngine(s, build_providers(s)).triage(normalize(BRUTE))
    assert result["provider"] == "hosted"
    assert result["provider_errors"] and "ollama" in result["provider_errors"][0]


def test_rate_limit_and_garbage_fall_to_heuristic(monkeypatch, tmp_path, fake_llm):
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="hosted",
                      HOSTED_API_URL=fake_llm + "/v1/chat/completions", HOSTED_API_KEY="k")
    engine = TriageEngine(s, build_providers(s))
    FakeLLM.status = 429
    r1 = engine.triage(normalize(BRUTE))
    assert r1["provider"] == "heuristic" and "429" in r1["provider_errors"][0]
    FakeLLM.status, FakeLLM.answer = 200, "I cannot help with that"
    r2 = engine.triage(normalize(BRUTE))
    assert r2["provider"] == "heuristic"
    assert "cooling down" in r2["provider_errors"][0]  # did not hammer the API during cooldown


def test_confident_false_positive_caps_score(monkeypatch, tmp_path, fake_llm):
    FakeLLM.answer = json.dumps({**GOOD_ANSWER, "verdict": "false_positive", "severity": "high", "confidence": 0.95})
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="ollama", OLLAMA_URL=fake_llm)
    result = TriageEngine(s, build_providers(s)).triage(normalize(BRUTE))
    assert result["score"] <= 25


def test_tailer_follows_appends_partial_lines_and_rotation(tmp_path):
    f = tmp_path / "alerts.json"
    f.write_text(json.dumps(SUDO) + "\n")
    t = AlertTailer(f, start_at_end=True)
    assert list(t.read_new()) == []  # existing history skipped
    line = json.dumps(BRUTE)
    with f.open("a") as fh:
        fh.write(line[:40])
    assert list(t.read_new()) == []  # half-written line held back
    with f.open("a") as fh:
        fh.write(line[40:] + "\n")
    assert [a["id"] for a in t.read_new()] == [BRUTE["id"]]
    f.rename(tmp_path / "alerts.json.1")  # logrotate
    f.write_text(json.dumps(FIM) + "\n")
    assert [a["id"] for a in t.read_new()] == [FIM["id"]]


def test_api_end_to_end(monkeypatch, tmp_path):
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="heuristic", TRIAGE_API_KEY="secret", MIN_RULE_LEVEL="7")
    service = Service(s, store=Store(s.db_path))
    client = create_app(service).test_client()
    assert client.get("/health").status_code == 200
    assert client.get("/api/alerts").status_code == 401
    h = {"X-API-Key": "secret"}

    for raw in RAW:
        service.process(raw)
    rows = client.get("/api/alerts", headers=h).get_json()
    assert len(rows) == 5  # sudo (level 3) filtered out
    assert service.process(REVSHELL) is None  # duplicate ignored

    one = client.post("/api/triage", json=SUDO, headers=h).get_json()
    assert one["priority"] == "info"

    aid = normalize(REVSHELL)["id"]
    assert client.get(f"/api/alerts/{aid}", headers=h).get_json()["result"]["iocs"]["public_ips"] == ["45.33.32.156"]
    ok = client.post(f"/api/alerts/{aid}/feedback", json={"verdict": "needs_investigation", "status": "escalated"}, headers=h)
    assert ok.status_code == 200
    stats = client.get("/api/stats", headers=h).get_json()
    assert stats["total"] == 6 and stats["analyst_reviewed"] == 1 and stats["ai_agreement_rate"] == 1.0
    page = client.get("/?key=secret").get_data(as_text=True)
    assert "Reverse shell" in page


class FakeIndexer(BaseHTTPRequestHandler):
    """Minimal OpenSearch _search: level filter, (timestamp, id) sort, search_after."""

    docs: list = []
    bodies: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).bodies.append({"body": body, "auth": self.headers.get("Authorization"), "path": self.path})
        min_level = body["query"]["bool"]["filter"][0]["range"]["rule.level"]["gte"]
        rows = sorted(
            ((d["timestamp"], d["id"], d) for d in self.docs if d["rule"]["level"] >= min_level),
            key=lambda r: (r[0], r[1]),
        )
        after = body.get("search_after")
        if after:
            rows = [r for r in rows if (r[0], r[1]) > tuple(after)]
        hits = [{"_source": d, "sort": [ts, i]} for ts, i, d in rows[: body["size"]]]
        payload = json.dumps({"hits": {"hits": hits}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_indexer():
    FakeIndexer.docs, FakeIndexer.bodies = [], []
    server = HTTPServer(("127.0.0.1", 0), FakeIndexer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_indexer_source_pages_filters_and_resumes(monkeypatch, tmp_path, fake_indexer):
    s = make_settings(
        monkeypatch, tmp_path, LLM_PROVIDERS="heuristic", ALERT_SOURCE="indexer",
        INDEXER_URL=fake_indexer, INDEXER_USER="reader", INDEXER_PASSWORD="pw", MIN_RULE_LEVEL="7",
    )
    store = Store(s.db_path)
    service = Service(s, store=store)
    FakeIndexer.docs = [BRUTE, MIMIKATZ, SUDO]
    source = service.make_source()
    source.batch = 1  # force paging

    for raw in source.read_new():
        service.process(raw)
    assert {r["rule_id"] for r in store.list()} == {"5763", "92052"}  # sudo (level 3) filtered server-side
    first = FakeIndexer.bodies[0]
    assert first["path"] == "/wazuh-alerts-4.x-*/_search"
    assert first["auth"].startswith("Basic ")
    assert "search_after" not in first["body"]
    assert FakeIndexer.bodies[1]["body"]["search_after"] == [BRUTE["timestamp"], BRUTE["id"]]

    # a restarted service resumes from the saved cursor and only sees new alerts
    FakeIndexer.docs.append(REVSHELL)
    FakeIndexer.bodies = []
    resumed = Service(s, store=store).make_source()
    new = list(resumed.read_new())
    assert [a["id"] for a in new] == [REVSHELL["id"]]
    assert FakeIndexer.bodies[0]["body"]["search_after"] == [MIMIKATZ["timestamp"], MIMIKATZ["id"]]


def test_unknown_alert_source_is_rejected(monkeypatch, tmp_path):
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="heuristic", ALERT_SOURCE="splunk")
    with pytest.raises(ValueError):
        Service(s).make_source()


def test_simulated_source_emits_fresh_alerts_on_schedule(monkeypatch, tmp_path):
    from soc_triage.wazuh import SimulatedSource

    now = [0.0]
    src = SimulatedSource(every=30, clock=lambda: now[0])
    first = list(src.read_new())
    assert len(first) == 1 and "simulated" in first[0]["rule"]["groups"]
    assert list(src.read_new()) == []  # not due yet
    now[0] = 31
    second = list(src.read_new())
    assert len(second) == 1 and second[0]["id"] != first[0]["id"]
    assert normalize(first[0])["id"] != normalize(RAW[0])["id"]  # never collides with the sample itself

    # the full service triages them like any other alert
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="heuristic", ALERT_SOURCE="simulate", MIN_RULE_LEVEL="0")
    service = Service(s, store=Store(s.db_path))
    source = service.make_source()
    for raw in source.read_new():
        service.process(raw)
    assert len(service.store.list()) == 1


def test_source_none_means_api_only(monkeypatch, tmp_path):
    s = make_settings(monkeypatch, tmp_path, LLM_PROVIDERS="heuristic", ALERT_SOURCE="none")
    service = Service(s)
    assert service.make_source() is None
    service.run_tailer()  # returns immediately instead of looping
