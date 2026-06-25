# SOC Multi-Agent AI System

Automated security operations pipeline that takes raw logs from detection to remediation without human intervention. Built with LangGraph, Qwen 2.5 7B (local, no cloud), ChromaDB RAG, and Docker.

**96.6% detection accuracy · 100% MITRE ATT&CK mapping · ~2 min full pipeline on GPU**

---

## What it does

Four specialized agents run sequentially in a LangGraph DAG:

| Agent | Role |
|-------|------|
| **Extractor** | Parses raw logs, pre-filters noise, classifies each line into structured JSON events via SLM |
| **Analyzer** | Correlates events into incidents, maps to MITRE ATT&CK via RAG, confirms attacks with confidence scoring |
| **Reporter** | Retrieves matching remediation playbooks via RAG, generates professional incident narratives, saves timestamped reports |
| **Executor** | Keyword-dispatches remediation actions (block IP, isolate host, notify admin), maintains a full audit trail |

Each agent reads from the previous agent's output via a shared LangGraph state dictionary. No agent calls another directly.

---

## Stack

- **Orchestration:** LangGraph 0.2 (DAG, not a chain)
- **Model:** Qwen 2.5 7B via Ollama — local inference, no API calls
- **RAG:** ChromaDB 0.5.5 — MITRE ATT&CK techniques + remediation playbooks + analyst feedback
- **Infrastructure:** Docker Compose — fully containerized, reproducible, resets with one command
- **Dashboard:** FastAPI + vanilla JS — operations feed and incident report, live polling
- **GPU:** NVIDIA RTX 4060 — ×5–6 speedup vs CPU

---

## Quickstart

```bash
# Start everything
docker compose up -d

# Pull the model (first time only, ~4 GB)
docker exec soc-ollama ollama pull qwen2.5:7b

# Run the pipeline
docker exec soc-app python src/main.py --run

# Dashboard → http://localhost:8080
```

---

## Operating modes

```bash
# Baseline — static dataset
docker compose up -d
docker exec soc-app python src/main.py --run

# ELK Stack — logs indexed in Elasticsearch, visible in Kibana
docker compose --profile elk up -d
docker exec soc-app python src/rag/elk_ingest.py
docker exec -e ELK_MODE=true soc-app python src/main.py --run
# Kibana → http://localhost:5601

# Live sandbox — real attacker/victim containers, real iptables blocking
docker compose --profile sandbox up -d
docker exec soc-attacker python3 -c "import generate_traffic as g; g.ssh_brute_force()"
docker exec -e LIVE_MODE=true -e EXECUTOR_LIVE_MODE=true -e VICTIM_CONTAINER=soc-victim \
  soc-app python src/main.py --run
docker exec soc-victim iptables -L INPUT -n  # confirm DROP rule applied
```

---

## Project structure

```
src/
├── agents/
│   ├── extractor.py       # Agent 1
│   ├── analyzer.py        # Agent 2
│   ├── reporter.py        # Agent 3
│   └── executor.py        # Agent 4
├── rag/
│   ├── mitre_loader.py    # MITRE ATT&CK → ChromaDB
│   ├── playbook_loader.py # Remediation playbooks → ChromaDB
│   ├── feedback_loader.py # Analyst feedback → ChromaDB (adaptive learning)
│   ├── elk_ingest.py      # Bulk insert logs into Elasticsearch
│   └── elk_live_shipper.py# Tail victim logs → Elasticsearch real-time
├── sandbox/
│   ├── victim/            # Ubuntu 24.04 target (nginx, SSH, rsyslog)
│   └── attacker/          # Attack traffic generator (brute force, SQLi, port scan)
├── dashboard/
│   ├── main.py            # FastAPI — /api/summary, /api/audit, /api/report, /api/feedback
│   └── index.html         # Operations + Incident Report tabs
├── shared/
│   └── memory.py          # Thread-safe shared state bus
├── data/
│   ├── sample_logs.log    # 36-line SOC simulation dataset (7 attack types)
│   └── incoming/          # Drop a log file here to use it instead of the sample
├── output/                # Timestamped run artifacts (gitignored)
└── main.py                # LangGraph StateGraph entry point
```

---

## Results

| Metric | Value |
|--------|-------|
| Line-level classification accuracy | 96.6% (28/29) |
| MITRE ATT&CK mapping accuracy | 100% (6/6 confirmed) |
| False positive rate | 0% |
| Full pipeline — GPU (RTX 4060) | ~100–130 s |
| Full pipeline — CPU | ~10–12 min |
| Total SLM calls per run | ~47 |

---

## Branches

- **`main`** — submission-stable, all results in this README are from this branch
- **`pawn-test`** — bonus extensions: adaptive learning (validated), ELK Stack (validated), live sandbox with real iptables remediation (validated)

---

*rowd4ddy 2025/2026*