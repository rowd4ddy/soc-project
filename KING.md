# KING — End Goal

> This document describes the complete finished system — every agent, every component,
> every deliverable. Use this as the north star while building.

---

## What the Finished System Does

A fully automated, locally-run, GPU-accelerated multi-agent AI system that:

1. **Reads** raw security logs from multiple sources (syslog, network, SIEM, IDS/IPS)
2. **Detects** threats and anomalies using an SLM + MITRE ATT&CK RAG knowledge base
3. **Generates** a detailed incident report with severity scores, attack timeline, and graphs
4. **Executes** automated remediation actions (block IP, isolate machine, notify admin)
5. **Traces** every action taken for audit compliance

All of this happens autonomously — no human in the loop — orchestrated by a LangGraph DAG pipeline.

---

## Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    INPUT SOURCES                                 │
│  System Logs │ Network Traffic │ SIEM Alerts │ IDS/IPS Events  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              LangGraph DAG Orchestrator                          │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────────┐
│  │  Agent 1    │───▶│  Agent 2    │───▶│  Agent 3    │───▶│  Agent 4    │
│  │  Extractor  │    │  Analyzer   │    │  Reporter   │    │  Executor   │
│  └─────────────┘    └─────────────┘    └─────────────┘    └──────────────┘
│         │                 │                  │                   │
│    SLM+RAG           SLM+RAG            SLM+RAG            SLM+RAG+MCP
└─────────────────────────────────────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                │   Shared Memory     │
                │   (audit trail)     │
                └─────────────────────┘
```

---

## All Four Agents — Complete Specification

### Agent 1 — Extractor ✅ (built)

**Input:** Raw log files (syslog, JSON, CSV, network captures)
**Process:**
- Keyword pre-filter (no LLM cost on benign lines)
- Regex parsing for timestamps, IPs, log levels
- SLM extraction of structured event fields
**Output:** List of structured event dicts in shared memory
**SLM prompt style:** Structured JSON extraction
**RAG use:** Log format templates (optional enhancement)

---

### Agent 2 — Analyzer ✅ (built)

**Input:** Structured events from Agent 1
**Process:**
- Event correlation by (type, source IP) into incidents
- Severity escalation based on event volume
- RAG retrieval from ChromaDB — finds matching MITRE ATT&CK techniques
- SLM analysis with ATT&CK context injected into prompt
- Overall threat level computation
**Output:** Full analysis result with confirmed attacks, MITRE IDs, threat levels
**SLM prompt style:** Threat analysis with retrieved context
**RAG use:** MITRE ATT&CK technique descriptions (10 techniques, ChromaDB)

---

### Agent 3 — Reporter 🔲 (to build)

**Input:** Analysis result from Agent 2
**Process:**
- Reads confirmed attacks and their details from shared memory
- Groups incidents by severity for the executive summary
- Generates an attack timeline from event timestamps
- Produces severity distribution statistics
- SLM writes a professional narrative incident report
- Outputs a structured JSON report + formatted text version
**Output:** Full incident report written to shared memory and saved as a file
**SLM prompt style:** Report generation / summarization
**RAG use:** Report templates and remediation playbooks

**Report structure:**
```
INCIDENT REPORT
═══════════════
Executive Summary
  - Overall threat level
  - Number of confirmed attacks
  - Most critical finding

Attack Timeline
  - Chronological list of events with timestamps

Incident Details (per attack)
  - Attack name and MITRE technique
  - Source IP and target
  - Explanation
  - Recommended action

Statistics
  - Severity breakdown (pie chart data)
  - Event count over time (timeline data)

Recommendations
  - Prioritized list of actions
```

---

### Agent 4 — Executor 🔲 (to build)

**Input:** Incident report from Agent 3
**Process:**
- Reads recommended actions from the report
- Maps each recommendation to a concrete action function
- Executes actions according to predefined playbooks
- Logs every action taken with timestamp (audit trail)
- Simulates actions that cannot be run safely in a dev environment
**Output:** List of actions taken, written to shared memory and logged
**SLM prompt style:** Action planning / decision making
**RAG use:** Remediation playbooks (what to do for each attack type)
**MCP use:** Model Context Protocol for tool execution

**Action types:**
| Action | Implementation in project |
|---|---|
| Block IP address | Simulated — logs the iptables command that would run |
| Isolate machine | Simulated — logs the network isolation steps |
| Notify administrator | Real — writes a formatted alert to a file |
| Close port | Simulated — logs the firewall rule |
| Kill process | Simulated — logs the kill command |
| Audit trail entry | Real — writes timestamped record to audit log |

> Note: Actions are simulated (logged but not executed) for safety in a university project.
> The architecture supports real execution by swapping the simulation functions for real ones.

---

## Complete File Structure (finished project)

```
soc-project/
│
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── PAWN.md                          # Progress tracker
├── KING.md                          # This file
│
└── src/
    ├── main.py                      # LangGraph pipeline entry point
    │
    ├── agents/
    │   ├── extractor.py             # Agent 1 ✅
    │   ├── analyzer.py              # Agent 2 ✅
    │   ├── reporter.py              # Agent 3 🔲
    │   └── executor.py              # Agent 4 🔲
    │
    ├── rag/
    │   ├── mitre_loader.py          # MITRE ATT&CK → ChromaDB ✅
    │   └── playbook_loader.py       # Remediation playbooks → ChromaDB 🔲
    │
    ├── shared/
    │   └── memory.py                # Shared memory bus ✅
    │
    ├── data/
    │   ├── sample_logs.log          # Simulated SOC dataset ✅
    │   └── audit_trail.log          # Written by Agent 4 🔲
    │
    └── output/
        ├── incident_report.txt      # Written by Agent 3 🔲
        └── actions_taken.json       # Written by Agent 4 🔲
```

---

## Deliverables Required by Teacher

### 1. Code source ✅🔲
The complete `src/` folder with all four agents.
- Agent 1: ✅ done
- Agent 2: ✅ done
- Agent 3: 🔲 to build
- Agent 4: 🔲 to build

### 2. Simulated SOC environment ✅
`src/data/sample_logs.log` — 36 realistic log lines covering 7 attack types.
Can be extended with more log entries or additional log format files.

### 3. Technical documentation 🔲
Two documents covering:
- **System architecture** — the DAG diagram, container layout, agent descriptions
- **Agent descriptions** — inputs, outputs, SLM prompts, RAG usage for each agent

### 4. Experimentation report 🔲
Four sections required:
- **Detection efficacy** — how accurately did the system classify attacks?
  Compare Qwen's classifications against the ground truth we know from the log file.
- **SLM performance** — how long does each agent take? Memory usage? GPU vs CPU comparison.
- **Limits** — what does the system struggle with? (e.g. novel attack patterns not in MITRE)
- **Perspectives** — what would a production version add? (real log ingestion, more techniques, adaptive learning)

### 5. Optional bonus — dashboard 🔲
A simple web UI (Flask or Streamlit) that:
- Shows the pipeline running in real time
- Displays the incident report visually
- Shows severity charts

---

## Build Order (remaining work)

```
Week 2 (now)
  └── Agent 3 — Reporter
        ├── reporter.py
        └── playbook_loader.py (RAG for remediation)

Week 3
  └── Agent 4 — Executor
        └── executor.py

Week 4
  ├── Full pipeline test (all 4 agents end-to-end)
  ├── Technical documentation
  ├── Experimentation report
  │     ├── Run pipeline with GPU vs CPU and record times
  │     ├── Manually verify attack classifications
  │     └── Write analysis of limits and results
  └── Optional: dashboard UI
```

---

## Key Design Decisions (to explain in your presentation)

**Why one SLM instead of four different models?**
One Qwen 2.5 7B instance serves all four agents with different system prompts.
This is the correct academic interpretation of "multi-agent" — agents differ by role and prompt, not by model. It is also simpler to deploy and defend in a presentation.

**Why RAG instead of fine-tuning?**
Fine-tuning a model on MITRE ATT&CK would require significant compute and time.
RAG achieves the same result at query time — the model gets the relevant technique descriptions injected into its prompt and reasons over them. No training required.

**Why Docker instead of running directly on Windows?**
Isolation, reproducibility, and safety. The entire environment can be wiped and rebuilt in minutes. Nothing touches the host machine.

**Why ChromaDB for the vector store?**
Lightweight, runs as a container, has a simple Python client, and integrates cleanly with LangChain. Perfect for a university project scope.

**Why LangGraph instead of plain LangChain?**
LangGraph models the pipeline as an explicit directed graph (DAG). This matches the project specification exactly, makes the flow visible and debuggable, and allows conditional edges (e.g. skip Executor if threat level is low) in future extensions.

---

## One-liner to explain the whole project (for your presentation)

> "We built a four-agent AI system where each agent is a LangGraph node powered by a local Qwen 2.5 7B model. Agent 1 extracts structured events from raw logs, Agent 2 correlates them into incidents and matches them to MITRE ATT&CK techniques using RAG over ChromaDB, Agent 3 generates a formatted incident report, and Agent 4 executes remediation actions. Everything runs locally on GPU inside Docker containers with no cloud dependency."
