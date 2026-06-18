# PAWN — Current Progress

> This document tracks exactly what has been built, how it works, and the decisions made along the way.
> Updated as each component is completed.

---

## Project Overview

A multi-agent AI system that automates Security Operations Center (SOC) analyst tasks.
Four intelligent agents collaborate in a pipeline to collect, analyze, report, and respond to security incidents — fully automated, locally run, isolated in Docker.

---

## Environment

### Stack

| Component | Technology | Purpose |
|---|---|---|
| Containerization | Docker Desktop + Docker Compose | Isolates everything from the host Windows machine |
| AI Model Server | Ollama | Runs the SLM locally inside a container |
| Language Model | Qwen 2.5 7B | The SLM that powers all four agents |
| GPU Acceleration | NVIDIA RTX 4060 (8GB VRAM) | Offloads model inference from CPU to GPU |
| Vector Database | ChromaDB | Stores MITRE ATT&CK embeddings for RAG retrieval |
| Agent Orchestration | LangGraph (DAG) | Wires agents together into a directed pipeline |
| Agent Framework | LangChain | Provides agent primitives and memory abstractions |
| Language | Python 3.11 | All agent code |
| Host OS | Windows 11 | Development machine |

### Why Docker

The entire project runs inside three containers. The host Windows machine only has Docker Desktop installed. This means:
- A single command (`docker compose down -v`) wipes everything cleanly
- No risk of breaking the host system during development or testing
- The environment is fully reproducible — clone the repo anywhere and it works

### Container Architecture

```
Windows Host (your laptop)
│
└── Docker
     ├── soc-ollama    → Runs Qwen 2.5 7B on the RTX 4060 GPU
     ├── soc-app       → Python pipeline (agents, LangGraph, ChromaDB client)
     └── soc-chroma    → ChromaDB vector database (MITRE ATT&CK knowledge base)
```

### Project Folder Structure

```
soc-project/
│
├── docker-compose.yml       # Defines all three containers
├── Dockerfile               # Builds the Python app container
├── requirements.txt         # Python dependencies
│
└── src/
    ├── main.py              # Entry point — builds and runs the LangGraph pipeline
    │
    ├── agents/
    │   ├── extractor.py     # Agent 1 ✅
    │   └── analyzer.py      # Agent 2 ✅
    │
    ├── rag/
    │   └── mitre_loader.py  # Loads MITRE ATT&CK into ChromaDB for RAG
    │
    ├── shared/
    │   └── memory.py        # Thread-safe shared memory bus between agents
    │
    └── data/
        └── sample_logs.log  # Simulated SOC log dataset (36 lines, realistic attacks)
```

---

## What Has Been Built

### ✅ Agent 1 — Extractor (`src/agents/extractor.py`)

**Role:** Reads raw log files, filters relevant lines, and uses the SLM to extract structured security events.

**How it works — three stages:**

1. **Pre-filter (regex, no LLM cost)**
   Scans each log line for ~15 suspicious keywords (`failed`, `denied`, `rootkit`, `execve`, etc.).
   Lines with no keywords are dropped immediately — saves SLM calls on benign INFO logs.
   Result: 29 of 36 lines flagged as relevant.

2. **Fast regex parsing**
   Extracts timestamp, log level, and source IP addresses from each line without touching the SLM.
   This gives us concrete structured fields before the expensive LLM call.

3. **SLM extraction (Qwen via Ollama)**
   Each relevant line is sent to Qwen with a tight prompt asking for a JSON object containing:
   - `event_type` — one of: brute_force, sql_injection, port_scan, malware, dos_attack, privilege_escalation, c2_communication, unauthorized_access, other
   - `source_ip` — extracted IP address
   - `target` — targeted service or port
   - `severity` — low / medium / high / critical
   - `summary` — one-sentence plain English description

**Output:** 29 structured event dicts written to shared memory and passed to Agent 2 via LangGraph state.

**Sample output:**
```
[evt-0011] unauthorized_access | critical | Root user accepted password after brute force from 203.0.113.42
[evt-0027] malware | critical | AVC denied execve for suspected rootkit at /tmp/.hidden
[evt-0028] c2_communication | medium | Query denied for suspected C2 server evil-c2-server.ru
```

---

### ✅ Agent 2 — Analyzer (`src/agents/analyzer.py`)

**Role:** Correlates events into incidents, retrieves matching MITRE ATT&CK techniques via RAG, and uses the SLM to produce a structured threat assessment.

**How it works — four stages:**

1. **Event correlation**
   Groups individual events by `(event_type, source_ip)`.
   Example: 10 `brute_force` events from `203.0.113.42` become one incident, not 10.
   Severity is escalated automatically based on volume (≥10 events of the same type → high).

2. **RAG retrieval (ChromaDB)**
   For each incident, a combined text description is sent to ChromaDB as a semantic search query.
   ChromaDB converts it to a vector embedding and finds the 3 most similar MITRE ATT&CK technique descriptions.
   Example: "10 failed SSH logins followed by successful root login from same IP" → retrieves T1110 (Brute Force), T1078 (Valid Accounts).

3. **SLM analysis (Qwen via Ollama)**
   Each incident is sent to Qwen with both the event details AND the retrieved ATT&CK techniques as context.
   The model returns a JSON assessment:
   - `confirmed_attack` — true/false
   - `attack_name` — human-readable name
   - `mitre_technique_id` — e.g. T1110
   - `threat_level` — low / medium / high / critical
   - `confidence` — low / medium / high
   - `explanation` — 2-3 sentence analysis
   - `recommended_action` — one concrete remediation step

4. **Overall threat computation**
   Picks the highest threat level across all confirmed attacks for the session summary.

**Output:** Full analysis result written to shared memory for Agent 3.

---

### ✅ Shared Memory Bus (`src/shared/memory.py`)

A thread-safe Python dict that all agents read from and write to.
Acts as the message bus between pipeline steps.
Includes a full audit trail of every read and write with timestamps.

In a production system this would be Redis. For this project, in-memory is sufficient.

---

### ✅ MITRE ATT&CK RAG Knowledge Base (`src/rag/mitre_loader.py`)

10 curated ATT&CK technique descriptions loaded into ChromaDB on first run.
Techniques covered: T1110, T1046, T1190, T1059, T1014, T1071, T1498, T1548, T1078, T1136.
Each description is written in log-observable terms so ChromaDB can match them to real log events.
Idempotent — safe to call on every startup, won't duplicate entries.

---

### ✅ Simulated SOC Dataset (`src/data/sample_logs.log`)

36 realistic log lines covering:
- SSH brute force (10 failed attempts + successful root login)
- SQL injection attempts (3 mod_security blocks)
- Port scan (5 UFW blocks across ports 21, 23, 139, 445, 3389)
- Rootkit execution attempt (SELinux AVC denial for /tmp/.hidden)
- C2 communication (DNS query denied for evil-c2-server.ru)
- SYN flood / DoS
- Privilege escalation attempts

---

## Day-to-Day Commands

```powershell
# Start everything
docker compose up -d

# Run the pipeline
docker exec soc-app python src/main.py --run

# Watch live logs
docker logs soc-app -f

# Stop everything (model stays)
docker compose down

# Full reset (wipes model — needs re-download)
docker compose down -v
docker compose up --build -d
docker exec soc-ollama ollama pull qwen2.5:7b
```

---

## Known Issues & Notes

- ChromaDB upgraded to v2 API — `mitre_loader.py` uses updated `chromadb.Settings` to connect.
- The `version` field in `docker-compose.yml` has been removed (was causing obsolete warnings).
- `CHROMA_HOST` environment variable is passed from `docker-compose.yml` to the app container.
- GPU passthrough configured via `deploy.resources.reservations.devices` in `docker-compose.yml`.

---

## What Is Not Built Yet

| Component | Status |
|---|---|
| Agent 3 — Reporter | 🔲 Next |
| Agent 4 — Executor | 🔲 Planned |
| Full pipeline integration | 🔲 Planned |
| Experimentation report | 🔲 Planned |
| Optional dashboard | 🔲 Bonus |
