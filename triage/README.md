# AI SOC Triage Service

Watches Wazuh `alerts.json`, triages every alert at or above a rule level with
an LLM, and keeps a scored queue an analyst can work through.

```
 Wazuh manager                       soc-triage (this service)
 alerts.json ──tail -F──▶ normalize ──▶ enrich ──▶ AI backend chain ──▶ validate + blend ──▶ SQLite
                          (rule, agent,   (IOCs,     ollama ─▶ hosted ─▶ heuristic          │
                           MITRE, IPs,     baseline   (first one that                        ▼
                           cmdline, FIM)   score,     answers wins)            REST API + queue page :8020
                                           redaction)                           Grafana (Infinity datasource)
```

## What it does per alert

1. **Normalize** the raw Wazuh JSON (Linux syslog, Sysmon/Windows eventdata,
   auditd, FIM/syscheck) into one compact shape.
2. **Enrich** deterministically: public IPs, hashes and domains as IOCs, plus a
   rule-based **baseline score** (0-100) from Wazuh level, MITRE tactic,
   repetition, sensitive files and red-flag strings (`sekurlsa`, `/dev/tcp/`,
   `-enc`, `vssadmin delete`, ...).
3. **Ask the AI** for a structured verdict: `true_positive`,
   `benign_true_positive`, `false_positive` or `needs_investigation`, with
   severity, confidence, summary, attack story, MITRE ids, recommended actions
   and false-positive hints. The prompt tells the model to treat alert fields as
   untrusted data (log lines can contain prompt injection).
4. **Validate** the answer (bad enums, fake MITRE ids and oversized text are
   dropped) and **blend** it with the baseline: the model's weight is
   `0.7 x confidence`, so the rules always keep at least 30%. A confident false
   positive is capped at score 25.
5. **Store** it in SQLite and expose it over the API and a simple queue page.

## AI backends

`LLM_PROVIDERS` is an ordered chain; the first backend that answers wins, and
`heuristic` (rules only) is always appended so triage never stalls.

| Provider | Where it runs | Speed | Cost / limits | Privacy |
|---|---|---|---|---|
| `ollama` (default) | your box | depends on CPU/GPU | free, unlimited | nothing leaves the lab |
| `hosted` | Groq by default | very fast (hundreds of tokens/s) | free tier, rate-limited per minute and per day | alert is **redacted** first |
| `heuristic` | your box | instant | free | nothing leaves the lab |

No hosted API is truly unlimited. Groq's free tier is the fastest free option
and its limits are generous for a home lab, but it returns HTTP 429 when you
exceed them. The service handles that by honouring `Retry-After`, cooling down,
and falling through to the next backend. For genuinely unlimited use, Ollama is
the answer; `ollama,hosted,heuristic` gives you local-first with a fast hosted
backup.

`hosted` speaks the OpenAI chat-completions format, so other free providers
work by changing two variables:

| Provider | `HOSTED_API_URL` | Example `HOSTED_MODEL` |
|---|---|---|
| Groq | `https://api.groq.com/openai/v1/chat/completions` | `llama-3.1-8b-instant` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions` | `gemini-2.0-flash` |
| OpenRouter | `https://openrouter.ai/api/v1/chat/completions` | any `:free` model |
| Cerebras | `https://api.cerebras.ai/v1/chat/completions` | `llama3.1-8b` |

Model names change often; check the provider's model list if one is rejected.

**Redaction** (`REDACT_FOR_HOSTED=true`, default): before anything goes to a
hosted API, private IPs become `10.x.x.N`, the username becomes `<user>` and the
agent name becomes `<host>`. Public IPs and hashes are kept because they are the
useful IOCs. Ollama always gets the full alert.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ALERT_SOURCE` | `file` | `file` follows alerts.json; `indexer` polls the Wazuh indexer (read-only); `simulate` replays the sample alerts with fresh timestamps (no Wazuh needed); `none` is API only |
| `SIMULATE_EVERY_SECONDS` | `60` | pace of the simulator |
| `WAZUH_ALERTS_FILE` | `/var/ossec/logs/alerts/alerts.json` | file to follow (rotation-safe) |
| `INDEXER_URL` / `INDEXER_INDEX` | `https://wazuh-indexer:9200` / `wazuh-alerts-4.x-*` | indexer source |
| `INDEXER_USER` / `INDEXER_PASSWORD` | empty | read-only indexer user, e.g. `grafana_reader` |
| `INDEXER_VERIFY_TLS` / `INDEXER_CA_FILE` | `true` / empty | TLS checking for the indexer |
| `POLL_SECONDS` | `2` | how often to check for new alerts |
| `MIN_RULE_LEVEL` | `7` | skip alerts below this Wazuh level |
| `START_AT_END` | `true` | ignore history on first start |
| `LLM_PROVIDERS` | `ollama,heuristic` | backend chain |
| `OLLAMA_URL` / `OLLAMA_MODEL` | `http://ollama:11434` / `llama3.2:3b` | local model |
| `HOSTED_API_URL` / `HOSTED_MODEL` / `HOSTED_API_KEY` | Groq | hosted model |
| `REDACT_FOR_HOSTED` | `true` | mask internal details for hosted calls |
| `LLM_TIMEOUT_SECONDS` | `60` | per-call timeout |
| `TRIAGE_API_KEY` | empty (open) | required `X-API-Key` for everything except `/health` |
| `DB_PATH` | `/var/lib/soc-triage/triage.db` | SQLite file |

Model sizing for Ollama: `llama3.2:3b` runs on CPU with ~4 GB RAM and answers
in a few seconds. `qwen2.5:7b` or `llama3.1:8b` give better verdicts if you
have 8 GB+ spare or a GPU.

## API

All endpoints except `/health` need `X-API-Key: $TRIAGE_API_KEY` (or `?key=` for the browser page).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness and active backend chain |
| GET | `/` | analyst queue page (auto-refresh) |
| POST | `/api/triage` | triage one raw Wazuh alert now (ignores level filter) |
| GET | `/api/alerts?limit=&min_score=&status=` | queue, newest first |
| GET | `/api/alerts/<id>` | full alert + AI result |
| POST | `/api/alerts/<id>/feedback` | `{"verdict": "...", "status": "closed", "note": "..."}` |
| GET | `/api/stats` | counts by priority/verdict/backend and AI-vs-analyst agreement rate |

Analyst feedback is stored next to the AI verdict, so `/api/stats` tells you how
often the model agrees with you, which is the number to watch when you swap
models.

## Run it

With the full lab (from the repo root):

```bash
./scripts/deploy.sh generate-secrets   # also creates TRIAGE_API_KEY
./scripts/deploy.sh up                 # starts Ollama, pulls the model, starts soc-triage
./scripts/deploy.sh triage-demo        # replays samples/wazuh_alerts.jsonl
open "http://localhost:8020/?key=$TRIAGE_API_KEY"
```

To use Groq instead: get a free key at https://console.groq.com/keys, set
`HOSTED_API_KEY=...` and `LLM_PROVIDERS=hosted,heuristic` (or
`ollama,hosted,heuristic`) in `docker/.env`, then `./scripts/deploy.sh restart`.

Standalone, without Docker:

```bash
cd triage
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
LLM_PROVIDERS=heuristic DB_PATH=./triage.db python -m soc_triage replay samples/wazuh_alerts.jsonl
```

On Kubernetes, see [k8s/triage/README.md](../k8s/triage/README.md) for an
isolated deployment in its own namespace.

## Sample alerts

`samples/wazuh_alerts.jsonl` covers SSH brute force from a Tor exit, Mimikatz
via Sysmon on a DC, `/etc/passwd` FIM change, a harmless 404, a bash reverse
shell, and a routine `sudo apt update` (filtered out at level 3). With the
rules-only backend they rank: reverse shell 100, Mimikatz 95, brute force 80,
passwd change 65, 404 35.

## Tests

`python -m pytest -q` runs 18 tests with fake Ollama and OpenAI-compatible
servers: parsing, validation, redaction (checks internal names never reach a
hosted call), the fallback chain, 429 cooldown, log rotation and partial lines,
the indexer source (paging, resume after restart), the simulator, and the API end to end. CI runs them plus a Docker build
(`.github/workflows/triage-tests.yml`).
