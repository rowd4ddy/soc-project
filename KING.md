# KING — Architecture Reference

> KING was the target spec. PAWN chased it. The pawn reached the king.
> This file is now the canonical technical reference for the system as built.
> For the build narrative and bug log, see PAWN.md.

---

## System overview

Four LangGraph agents run sequentially. Each receives the previous agent's output via a shared `PipelineState` TypedDict and returns an enriched version of that state. A parallel `SharedMemory` singleton provides standalone-testing fallback and per-field write history.

```
Source logs
    │
    ▼
┌──────────────────────────────────────────────────────┐
│                  LangGraph DAG                        │
│  Extractor ──▶ Analyzer ──▶ Reporter ──▶ Executor    │
│    SLM         SLM+RAG      SLM+RAG      rules+SLM   │
└──────────────────────────────────────────────────────┘
    │                              │
    │         SharedMemory         │
    │    (fallback + audit log)    │
    ▼                              ▼
ChromaDB                      src/output/
(3 collections)               (timestamped artifacts)
    │
    ▼
Dashboard (FastAPI + JS)
http://localhost:8080
```

---

## State contract

```python
class PipelineState(TypedDict):
    raw_lines:        list[str]   # Agent 1 writes
    extracted_events: list[dict]  # Agent 1 writes → Agent 2 reads
    analysis_result:  dict        # Agent 2 writes → Agent 3 reads
    report:           dict        # Agent 3 writes → Agent 4 reads
    actions_taken:    list[str]   # Agent 4 writes → pipeline output
```

Each agent does `return {**state, "my_key": my_result}`. Nothing is lost between nodes — the state grows, never shrinks.

---

## Containers

### Baseline (always active)

| Container | Image | Port | Role |
|-----------|-------|------|------|
| soc-ollama | ollama/ollama | 11434 | Qwen 2.5 7B inference, GPU-accelerated |
| soc-app | python:3.11-slim (build) | — | LangGraph pipeline (all 4 agents) |
| soc-chroma | chromadb/chroma:0.5.5 | 8000 | Vector DB — 3 RAG collections |
| soc-dashboard | python:3.11-slim (build) | 8080 | FastAPI + HTML dashboard |

### ELK profile (`--profile elk`)

| Container | Image | Port | Role |
|-----------|-------|------|------|
| soc-elasticsearch | elasticsearch:8.13.0 | 9200 | Log storage and search |
| soc-kibana | kibana:8.13.0 | 5601 | Log visualization |

### Sandbox profile (`--profile sandbox`)

| Container | Image | Role |
|-----------|-------|------|
| soc-victim | ubuntu:24.04 (build) | Target — nginx, SSH, rsyslog. Capability NET_ADMIN for iptables |
| soc-attacker | python:3.11-slim (build) | Attack generator — brute force, SQLi, port scan, directory traversal |
| soc-log-shipper | python:3.11-slim (build) | Tails victim logs → Elasticsearch (sandbox+elk combined mode) |

### Volumes

| Volume | Contents |
|--------|----------|
| ollama-models | Qwen 2.5 7B weights (~4 GB) |
| chroma-data | ChromaDB collections (persistent across restarts) |
| onnx-cache | all-MiniLM-L6-v2 embedding model (~79 MB) — mounted in soc-app AND soc-dashboard |
| es-data | Elasticsearch indices (elk profile) |
| victim-logs | Shared between soc-victim (write) and soc-app + soc-log-shipper (read) |

---

## Agents

### Agent 1 — Extractor (`src/agents/extractor.py`)

**Input:** Raw log lines from one of five sources (priority order):
1. `state["raw_lines"]` already populated
2. `LIVE_MODE=true` → `/victim-logs/auth.log` + `/victim-logs/nginx/access.log`
3. `ELK_MODE=true` → HTTP GET on `soc-elasticsearch:9200/{index}/_search`
4. Newest file in `src/data/incoming/`
5. `src/data/sample_logs.log`

**Processing:**
- Keyword pre-filter (~20 keywords) — no SLM cost on benign lines
- Regex extraction of timestamps and IPs as fallback
- SLM call per filtered line — returns `{event_type, source_ip, target, severity, summary}` as JSON at temperature 0.1

**Output:** `extracted_events` — list of structured event dicts

**RAG:** None (intentional — structure extraction doesn't benefit from retrieved context)

**Measured:** 29/36 lines pass pre-filter (100% attack recall), 28/29 correctly classified (96.6%)

---

### Agent 2 — Analyzer (`src/agents/analyzer.py`)

**Input:** `extracted_events` from Agent 1

**Processing:**
1. Correlation by `(event_type, source_ip)` — groups repeated events into incidents
2. Severity escalation — if ≥10 medium events in a group → high
3. RAG query on `mitre_attack` collection — top 3 MITRE techniques by cosine similarity
4. RAG query on `analyst_feedback` collection — past analyst verdicts on similar incidents
5. SLM call per incident — augmented prompt returns `{confirmed_attack, attack_name, mitre_technique_id, threat_level, confidence, explanation, recommended_action}`

**Output:** `analysis_result` — incidents, confirmed attacks, overall threat level

**RAG:** `mitre_attack` (10 techniques) + `analyst_feedback` (analyst verdicts, adaptive)

**Measured:** 9 incidents → 6 confirmed, 3 correctly rejected. 100% MITRE mapping on confirmed.

---

### Agent 3 — Reporter (`src/agents/reporter.py`)

**Input:** `analysis_result` from Agent 2

**Processing:**
1. Build attack timeline from event timestamps
2. Compute severity distribution statistics
3. RAG query on `soc_playbooks` — matching remediation playbook per confirmed incident
4. SLM call per confirmed incident — 3–4 sentence professional analyst narrative at temperature 0.3
5. Assemble and save dual output

**Output:** `report` dict + files:
- `src/output/report_YYYYMMDD-HHMMSS.json` → read by dashboard
- `src/output/incident_report_YYYYMMDD-HHMMSS.txt` → human readable

**RAG:** `soc_playbooks` (7 playbooks — brute force, port scan, SQLi, malware, C2, SYN flood, privilege escalation)

---

### Agent 4 — Executor (`src/agents/executor.py`)

**Input:** `report` from Agent 3

**Processing:**
1. Keyword dispatch (no SLM) — maps recommendation text to handler function
2. Handler executes in simulated or live mode depending on `EXECUTOR_LIVE_MODE`
3. Critical incidents trigger SLM call for supplementary actions (`plan_additional_actions`)
4. Every action appended to `src/output/audit_trail.log` as JSON-Lines

**Keyword → handler map:**
- `block` → `block_ip(ip, reason, incident_id)`
- `isolate` → `isolate_host(hostname, reason, incident_id)`
- `notify` → `notify_admin(message, incident_id)`
- `rate` → `apply_rate_limit(target, incident_id)`
- `forensic` → `trigger_forensics(target, incident_id)`
- (no match) → `manual_review(incident_id)`

**Simulated mode (default):** logs the command that would run, returns `status: "simulated"`

**Live mode (`EXECUTOR_LIVE_MODE=true`):**
```python
client = docker.from_env()          # reads /var/run/docker.sock
container = client.containers.get("soc-victim")
result = container.exec_run("iptables -A INPUT -s {ip} -j DROP")
# returns status: "executed_live"
```

**Output:** `actions_taken` list + `audit_trail.log` + `actions_taken_*.json`

---

## RAG collections

| Collection | Documents | Stored as | Used by |
|------------|-----------|-----------|---------|
| `mitre_attack` | 10 MITRE techniques | Observable log-language descriptions | Agent 2 |
| `soc_playbooks` | 7 remediation playbooks | Tag fields (brute_force, T1110, etc.) | Agent 3 |
| `analyst_feedback` | Analyst verdicts (grows over time) | Incident summary + verdict + MITRE ID | Agent 2 |

All collections are idempotent — `get_or_create_collection` + `upsert` on every startup. Safe to restart.

Embedding model: `all-MiniLM-L6-v2` (ONNX, ~79 MB, persisted in `onnx-cache` volume).

---

## Dashboard endpoints

| Endpoint | Method | Returns |
|----------|--------|---------|
| `/api/summary` | GET | Latest `actions_taken_*.json` + aggregated counts |
| `/api/audit` | GET | Last 50 lines of `audit_trail.log`, newest first |
| `/api/report` | GET | Latest `report_*.json` in full |
| `/api/feedback` | POST | Writes analyst verdict to `analyst_feedback` ChromaDB collection |
| `/api/clear` | DELETE | Removes all files in `src/output/` — does not touch ChromaDB |

---

## Log source resolution

```
state["raw_lines"] set?  ──yes──▶ use it
         │ no
         ▼
LIVE_MODE=true?  ──yes──▶ /victim-logs/auth.log + nginx/access.log
         │ no
         ▼
ELK_MODE=true?  ──yes──▶ GET soc-elasticsearch:9200/{ES_INDEX}/_search
         │ no
         ▼
src/data/incoming/ has files?  ──yes──▶ newest .log or .txt file
         │ no
         ▼
src/data/sample_logs.log  (fallback)
```

---

## Measured results (on `src/data/sample_logs.log`)

| Metric | Value |
|--------|-------|
| Pre-filter recall | 100% (0 attack lines dropped) |
| Line-level accuracy | 96.6% (28/29) |
| MITRE mapping accuracy | 100% (6/6 confirmed incidents) |
| False positive rate | 0% |
| Pipeline duration — GPU (RTX 4060) | ~100–130 s |
| Pipeline duration — CPU | ~10–12 min |
| Total SLM calls | ~47 |
| Adaptive learning cosine relevance | 0.838 (Port Scanning false positive) |
| ELK ingestion | 36/36 documents |

---

## Known limitations

- Pipeline is sequential — 47 SLM calls one after another. Agent 1 alone accounts for 29.
- MITRE knowledge base covers 10 of ~200 real techniques.
- Dataset is 36 lines — a demo, not production scale.
- 1 false negative: UFW BLOCK line classified "other" instead of "port_scan."
- SharedMemory is in-RAM only — a container restart during a run loses session state.

---

*rowd4ddy 2025/2026*