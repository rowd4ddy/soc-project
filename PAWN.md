# PAWN — Current Progress

> This document tracks exactly what has been built, how it works, and the decisions made along the way.
> Updated as each component is completed.

---

## Project Status — Snapshot

| Deliverable (per project spec) | Status |
|---|---|
| Code source — 4 agents | ✅ Done (main branch) |
| Simulated SOC dataset | ✅ Done |
| Technical documentation (architecture + agent descriptions) | ✅ This file + KING.md |
| Experimentation report | ✅ Done — `Experimentation_Report.docx` |
| Bonus: visualization dashboard | ✅ Done and finalized — FastAPI + live HTML dashboard, all known UI issues resolved |
| Bonus: real tool integration (ELK/Splunk) | 🔲 Designed, not built — `pawn-test` |
| Bonus: adaptive learning system | 🔲 Designed, not built — `pawn-test` |
| Bonus: live remediation sandbox (not in original spec, added scope) | 🟡 Partially built — `pawn-test` |

**Branch model:** `main` holds the fully working, demo-safe, submission-ready system described below — code, dataset, report, and dashboard are all locked. `pawn-test` is where the three bonus extensions are being built; nothing there has touched `main` yet, and `main` does not depend on any of it. Next bonus work in priority order: adaptive learning, then the live remediation sandbox, then ELK/Splunk if time remains.

---

## Environment

### Stack

| Component | Technology | Purpose |
|---|---|---|
| Containerization | Docker Desktop + Docker Compose | Isolates everything from the host Windows machine |
| AI Model Server | Ollama | Runs the SLM locally inside a container |
| Language Model | Qwen 2.5 7B | The SLM that powers all four agents |
| GPU Acceleration | NVIDIA RTX 4060 (8GB VRAM) | Offloads model inference from CPU to GPU — ~5-6x latency reduction |
| Vector Database | ChromaDB 0.5.5 | Two collections: MITRE ATT&CK techniques, remediation playbooks |
| Agent Orchestration | LangGraph (DAG) | Wires all 4 agents together into a directed pipeline |
| Agent Framework | LangChain | Provides agent primitives |
| Dashboard Backend | FastAPI | Serves pipeline output as a REST API |
| Dashboard Frontend | Vanilla JS + Chart.js | Terminal-style live operations dashboard |
| Language | Python 3.11 | All agent code |
| Host OS | Windows 11 | Development machine |

### Why Docker

The entire project runs inside containers. The host Windows machine only has Docker Desktop installed. This means:
- A single command (`docker compose down -v`) wipes everything cleanly
- No risk of breaking the host system during development or testing
- The environment is fully reproducible — clone the repo anywhere and it works

### Container Architecture (main branch)

```
Windows Host (laptop)
│
└── Docker — project: soc-project (default)
     ├── soc-ollama      → Qwen 2.5 7B, GPU-accelerated (RTX 4060)
     ├── soc-app         → Python pipeline: all 4 agents, LangGraph, ChromaDB client
     ├── soc-chroma      → ChromaDB — MITRE ATT&CK + playbook collections
     └── soc-dashboard   → FastAPI + HTML dashboard, port 8080
```

A second, fully isolated Compose project (`soc-sandbox`) exists on the `pawn-test` branch for the live remediation extension — see "On pawn-test" below. It shares only application source code with the stack above; no networks, volumes, or containers overlap.

### Project Folder Structure

```
soc-project/
│
├── docker-compose.yml         # Defines all 4 containers (main branch)
├── Dockerfile                 # Builds the Python app container
├── requirements.txt           # Python dependencies
├── PAWN.md                    # This file
├── KING.md                    # End-goal architecture & spec mapping
│
└── src/
    ├── main.py                # Entry point — builds and runs the full LangGraph pipeline
    │
    ├── agents/
    │   ├── extractor.py       # Agent 1 ✅
    │   ├── analyzer.py        # Agent 2 ✅
    │   ├── reporter.py        # Agent 3 ✅
    │   └── executor.py        # Agent 4 ✅
    │
    ├── rag/
    │   ├── mitre_loader.py    # MITRE ATT&CK → ChromaDB
    │   └── playbook_loader.py # Remediation playbooks → ChromaDB
    │
    ├── shared/
    │   └── memory.py          # Thread-safe shared memory bus between agents
    │
    ├── dashboard/
    │   ├── main.py            # FastAPI backend (/api/summary, /api/audit, /api/report)
    │   ├── index.html         # Live dashboard — Operations + Incident Report tabs
    │   └── Dockerfile
    │
    ├── data/
    │   ├── sample_logs.log    # Bundled simulated SOC dataset (36 lines)
    │   └── incoming/          # Drag-and-drop folder — newest file here overrides the sample
    │
    └── output/                 # Timestamped, non-overwriting run artifacts (gitignored)
        ├── incident_report_<ts>.txt
        ├── report_<ts>.json    # Read by the dashboard's Incident Report tab
        ├── actions_taken_<ts>.json
        ├── audit_trail.log
        └── admin_notifications.txt
```

---

## What Has Been Built (main branch — complete)

### ✅ Agent 1 — Extractor (`src/agents/extractor.py`)

**Role:** Reads raw log lines, filters relevant ones, and uses the SLM to extract structured security events.

**How it works — three stages:**

1. **Pre-filter (keyword match, no LLM cost)** — scans each line for ~15 suspicious keywords. Consistently flags 29 of 36 lines as relevant on the bundled dataset, with zero attack-related lines dropped (100% recall at this stage).
2. **Fast regex parsing** — extracts timestamp, log level, and source IPs without touching the SLM.
3. **SLM extraction (Qwen via Ollama)** — each relevant line is classified into one of nine event types with severity, source IP, target, and a one-sentence summary, returned as JSON.

**Log source resolution (drag-and-drop):** before reading any file, the Extractor checks `src/data/incoming/` for the newest `.log` or `.txt` file and uses it automatically; if that folder is empty it falls back to the bundled `sample_logs.log`. This means swapping in a teacher-provided dataset requires no code changes — just drop the file in and re-run.

**Output:** structured event list written to shared memory and passed to Agent 2 via LangGraph state.

**Measured accuracy:** 28/29 lines correctly classified (96.6%) against the bundled dataset's known ground truth. Full breakdown in `Experimentation_Report.docx`, §3.2.

---

### ✅ Agent 2 — Analyzer (`src/agents/analyzer.py`)

**Role:** Correlates events into incidents, retrieves matching MITRE ATT&CK techniques via RAG, and produces a structured threat assessment.

**How it works — four stages:**

1. **Event correlation** — groups events by `(event_type, source_ip)`; severity auto-escalates with event volume.
2. **RAG retrieval (ChromaDB)** — each incident's combined summary is embedded and matched against 10 curated MITRE ATT&CK technique descriptions.
3. **SLM analysis** — the model receives both the incident details and the retrieved ATT&CK context, and returns `confirmed_attack`, `attack_name`, `mitre_technique_id`, `threat_level`, `confidence`, `explanation`, and `recommended_action`.
4. **Overall threat computation** — picks the highest threat level across confirmed attacks for the session summary.

**Measured result on the bundled dataset:** 29 events → 9 correlated incidents → 6 confirmed attacks, all 6 with independently-verified-correct MITRE technique IDs (100% mapping accuracy on confirmed incidents). 3 incidents correctly left unconfirmed due to low model confidence rather than forced classification.

---

### ✅ Agent 3 — Reporter (`src/agents/reporter.py`)

**Role:** Turns the Analyzer's output into a complete, readable incident report.

**How it works:**

1. **Timeline construction** — flattens all confirmed-incident timestamps into chronological order.
2. **Statistics computation** — severity distribution, attack type breakdown, top attacker IPs.
3. **RAG playbook retrieval** — for each confirmed incident, queries the `soc_playbooks` ChromaDB collection (7 curated remediation playbooks) for the matching response procedure.
4. **SLM narrative generation** — writes a professional 3-4 sentence analyst narrative per incident, using the retrieved playbook as grounding context.
5. **Dual file output** — every run writes a timestamped human-readable `.txt` report **and** a timestamped `.json` version (added specifically so the dashboard's Incident Report tab has structured data to read).

**Output:** `src/output/incident_report_<timestamp>.txt` and `report_<timestamp>.json`, plus the structured report dict written to shared memory for Agent 4.

---

### ✅ Agent 4 — Executor (`src/agents/executor.py`)

**Role:** Dispatches remediation actions from the report's recommendations and maintains a full audit trail.

**How it works:**

1. **Action dispatcher** — matches keywords in each recommendation (`block`, `isolate`, `notify`, `rate`, `forensic`, `monitor`, `lock`) to a handler function. This is intentionally rule-based, not SLM-driven, for the primary dispatch — fast and deterministic.
2. **Simulated handlers** (default) — each handler logs the exact command that would run (e.g. the precise `iptables` rule) and returns a structured result; nothing executes against a real system.
3. **One real action** — `notify_admin()` actually writes a timestamped alert file (`admin_notifications.txt`) rather than simulating, since writing a local file is safe to do for real.
4. **SLM supplementary planning** — for critical incidents only, asks the model for 2 additional response actions beyond the primary recommendation.
5. **Audit trail** — every action, simulated or real, is appended as a JSON line to `audit_trail.log` with a full timestamp.

**Feature-flag design (forward-looking):** every handler is written so a future "live mode" (see `pawn-test`) can swap the simulated body for a real Docker SDK call without changing the function's return contract — the dashboard and audit trail need zero changes to support it.

**Output:** `src/output/actions_taken_<timestamp>.json`, `audit_trail.log`, `admin_notifications.txt`.

---

### ✅ Shared Memory Bus (`src/shared/memory.py`)

A thread-safe Python dict that all agents read from and write to, with a full read/write audit history. In a production system this would be Redis; in-memory is sufficient at this scale.

---

### ✅ RAG Knowledge Bases (`src/rag/`)

Two ChromaDB collections, both idempotent (safe to reload on every startup):

- **`mitre_loader.py`** — 10 MITRE ATT&CK techniques (T1110, T1046, T1190, T1059, T1014, T1071, T1498, T1548, T1078, T1136), each described in log-observable terms.
- **`playbook_loader.py`** — 7 remediation playbooks (brute force, port scan, SQL injection, malware/rootkit, C2 communication, DoS/SYN flood, privilege escalation), each with immediate/investigate/harden/notify steps.

---

### ✅ Operations Dashboard (`src/dashboard/`)

A separate FastAPI container serving a live, two-tab dashboard at `localhost:8080`.

**Backend (`main.py`):**
- `/api/summary` — aggregated action counts (simulated/executed/flagged, severity breakdown) from the latest `actions_taken_*.json`
- `/api/audit` — last 50 entries from `audit_trail.log`
- `/api/report` — full latest `report_*.json` (executive summary, timeline, per-incident narratives, recommendations)

**Frontend (`index.html`):** terminal/phosphor-style design (monospace data, hairline borders, severity color reserved for meaning rather than decoration). Two tabs:
- **Operations** — KPI row, severity breakdown bars, live audit feed (new entries fade in), filterable/expandable incidents table with stable fixed-height layout
- **Incident Report** — executive summary grid, expandable incident cards with full analyst narratives and MITRE mapping, attack timeline, prioritized recommendations

Polls every 5 seconds; refresh button gives explicit visual feedback (pulse + "last updated HH:MM:SS").

**Finalization pass (post-initial-build fixes):**
- **Empty Incident Report tab** — root-caused to `reporter.py` only ever writing the `.txt` report and never a `report_*.json`; fixed at the source (see Agent 3 section above) rather than patched in the dashboard.
- **Doughnut chart removed** — replaced with a severity breakdown panel (count, percentage, and most-recent-incident-at-that-severity per row); the chart looked finished but carried no information beyond what the KPI row already showed. Bars are also click-to-filter, so they now do something the chart didn't.
- **Table jump on filter** — the incidents table used to resize the whole panel when switching severity filters (6 rows → 2 rows snapping the layout). Fixed with a fixed-height scroll container and a sticky header.
- **Refresh button feedback** — the button always worked but gave zero visual confirmation it had fired, which read as broken. It now pulses green on click and updates a live "last updated HH:MM:SS" timestamp next to the status dot.
- **Live feel** — the pipeline produces a finished snapshot per run, not a true mid-run stream, so rather than fake a progress animation, the audit feed now detects genuinely new entries between 5-second polls and fades only those in at the top. Real new data feels live without fabricating activity that isn't happening.

---

### ✅ Simulated SOC Dataset (`src/data/sample_logs.log`)

36 log lines covering: SSH brute force (10 failed + 1 successful root login), SQL injection (3 mod_security blocks), port scan (5 UFW blocks across 5 ports), SYN flood/DoS, privilege escalation (SELinux AVC denial), a second brute-force actor (5 common-username attempts), rootkit execution, C2 communication, and 7 benign control lines.

---

### ✅ Experimentation Report (`Experimentation_Report.docx`)

15-page Word document covering all four required areas: detection efficacy (with full per-category accuracy tables), SLM performance (CPU vs GPU timing, per-stage latency breakdown), limits (model-level, architectural, dataset-level), and perspectives (near-term optimizations, what was actually built along the way, and the three designed bonus extensions). Built with real numbers from actual test runs, not placeholder figures.

---

## Day-to-Day Commands

```powershell
# Start everything
docker compose up -d

# Run the pipeline
docker exec soc-app python src/main.py --run

# Watch live logs
docker logs soc-app -f

# Drag-and-drop a new dataset — drop the file, then:
docker exec soc-app python src/main.py --run
# (Extractor auto-picks the newest file in src/data/incoming/)

# View the dashboard
# → http://localhost:8080

# Stop everything (model stays)
docker compose down

# Full reset (wipes model — needs re-download)
docker compose down -v
docker compose up --build -d
docker exec soc-ollama ollama pull qwen2.5:7b
```

---

## Known Issues & Resolved Notes

- ChromaDB pinned to `0.5.5` on both server image and client package (newer versions broke the v1 API the client expected) — resolved.
- `PYTHONDONTWRITEBYTECODE=1` set in the Dockerfile — prevents stale `__pycache__` from masking code edits inside the container (was the root cause of several "my fix isn't applying" sessions).
- `onnx-cache` named Docker volume persists ChromaDB's embedding model — without it, every container rebuild re-triggered an 8-10 minute download.
- GPU passthrough via `deploy.resources.reservations.devices` in `docker-compose.yml` — reduced per-call SLM latency roughly 5-6x.
- All pipeline output files are timestamped and never overwritten; `.gitignore` excludes generated output but keeps the `src/output/` and `src/data/incoming/` folders themselves tracked via `.gitkeep`.

---

## On `pawn-test` — Bonus Extensions In Progress

None of the following affects `main`. Each is designed to plug into exactly one existing agent through the same patterns already proven on `main` (a new RAG collection, or a feature-flagged branch with a safe fallback).

| Extension | Touches | Status |
|---|---|---|
| Adaptive learning (analyst feedback loop) | Agent 2 only — new `analyst_feedback` ChromaDB collection | 🔲 Designed (KING.md §6.3 / report §6.3), not built |
| Live remediation sandbox | Agent 1 (live log tail) + Agent 4 (real Docker SDK actions) | 🟡 Victim container, attacker traffic generator, trigger script, and feature-flagged agent code written; sandbox `docker-compose.yml` not yet finalized/tested |
| ELK / Splunk integration | Agent 1 only — swap static file read for an Elasticsearch query | 🔲 Designed (report §6.5), not built |

See `Experimentation_Report.docx` §6 and `KING.md` for full technical design of each, including why they can be built independently or all together without conflict.