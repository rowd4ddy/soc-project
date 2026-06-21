# KING — End Goal

> This document describes the complete finished system — every agent, every component,
> every deliverable. Use this as the north star, and as the reference for the presentation.

---

## What the Finished System Does

A fully automated, locally-run, GPU-accelerated multi-agent AI system that:

1. **Reads** raw security logs (bundled sample dataset, drag-and-drop external files, or — on `pawn-test` — a live sandboxed victim container)
2. **Detects** threats and anomalies using an SLM + MITRE ATT&CK RAG knowledge base
3. **Generates** a detailed incident report with severity scores, attack timeline, and analyst narratives
4. **Executes** automated remediation actions (block IP, isolate machine, notify admin) — simulated by default, with a feature-flagged path to real execution against a disposable sandbox target
5. **Traces** every action taken for audit compliance
6. **Visualizes** the entire pipeline live through a two-tab operations dashboard

All of this happens autonomously — no human in the loop during a run — orchestrated by a LangGraph DAG pipeline.

**Status: all four agents, the full pipeline, and the dashboard bonus are built, tested, and finalized on `main` — nothing left to fix there. This document is now the design reference and build order for the three further bonus extensions in progress on `pawn-test`: adaptive learning first, then the live remediation sandbox, then ELK/Splunk if time remains.**

---

## Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    INPUT SOURCES                                 │
│  Bundled sample log  │  Drag-and-drop file  │  (pawn-test: live  │
│                       │  (src/data/incoming) │   victim sandbox) │
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
│        SLM            SLM + RAG           SLM + RAG          rules + SLM
│                     (MITRE ATT&CK)       (playbooks)       (+ Docker SDK
│                                                              on pawn-test)
└─────────────────────────────────────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                │   Shared Memory     │
                │   (audit trail)     │
                └──────────┬──────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   Operations Dashboard   │
              │  Operations | Incident   │
              │  Report tabs, live poll  │
              └─────────────────────────┘
```

---

## All Four Agents — Complete Specification

### Agent 1 — Extractor ✅ (built)

**Input:** Raw log lines — bundled sample, drag-and-drop file, or (pawn-test) a live victim container's logs.
**Process:**
- Keyword pre-filter (no LLM cost on benign lines) — 100% recall on the test dataset, 0 attack lines dropped
- Regex parsing for timestamps, IPs, log levels
- Log source resolution: checks `src/data/incoming/` for the newest file before falling back to the bundled dataset, so a new dataset can be evaluated with zero code changes
- SLM extraction of structured event fields (event_type, source_ip, target, severity, summary)
**Output:** List of structured event dicts in shared memory
**SLM prompt style:** Structured JSON extraction
**RAG use:** None — Agent 1 is intentionally RAG-free; structure extraction doesn't benefit from retrieved context the way threat analysis does
**Measured:** 96.6% line-level classification accuracy (28/29) against known ground truth

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
**Measured:** 29 events → 9 incidents → 6 confirmed attacks; 100% MITRE mapping accuracy on confirmed incidents; 3 incidents correctly left unconfirmed on low confidence rather than forced

---

### Agent 3 — Reporter ✅ (built)

**Input:** Analysis result from Agent 2
**Process:**
- Reads confirmed attacks and their details from shared memory
- Groups incidents by severity for the executive summary
- Generates an attack timeline from event timestamps
- Produces severity distribution statistics
- RAG retrieval of the matching remediation playbook per incident
- SLM writes a professional narrative incident report per incident, grounded in the retrieved playbook
- Outputs both a structured JSON report and a formatted text version, both timestamped and never overwritten
**Output:** Full incident report written to shared memory for Agent 4, and saved as two files (`.txt` for humans, `.json` for the dashboard)
**SLM prompt style:** Report generation / summarization
**RAG use:** Remediation playbooks (7 playbooks, ChromaDB collection `soc_playbooks`)

**Report structure (as implemented):**
```
INCIDENT REPORT
═══════════════
Executive Summary
  - Overall threat level
  - Number of confirmed attacks
  - Critical / high counts
  - Top source IP

Attack Timeline
  - Chronological list of events with timestamps

Incident Details (per confirmed attack)
  - Attack name and MITRE technique ID
  - Source IP and target
  - Confidence level
  - Analyst narrative (SLM-generated, playbook-grounded)
  - Recommended action

Statistics
  - Severity distribution
  - Attack type breakdown
  - Top source IPs

Recommendations
  - Prioritized list of actions, one per confirmed incident
```

---

### Agent 4 — Executor ✅ (built)

**Input:** Incident report from Agent 3
**Process:**
- Reads recommended actions from the report
- Maps each recommendation to a concrete action function via keyword dispatch (rule-based, not SLM — fast and deterministic for the primary action)
- Executes the simulated version of each action by default — logs the exact command/procedure and returns a structured result
- For critical incidents, asks the SLM for supplementary action ideas beyond the primary recommendation
- Logs every action taken with timestamp (audit trail), simulated or real
**Output:** List of actions taken, written to shared memory and logged
**SLM prompt style:** Supplementary action planning (critical incidents only — primary dispatch is rule-based)
**RAG use:** None directly — consumes Agent 3's playbook-grounded recommendations rather than querying ChromaDB itself

**Action types (as implemented):**
| Action | Implementation in project |
|---|---|
| Block IP address | Simulated — logs the exact `iptables` command that would run |
| Isolate machine | Simulated — logs the network isolation steps |
| Notify administrator | **Real** — writes a formatted alert to `admin_notifications.txt` |
| Lock account | Simulated — logs the account-lock procedure |
| Audit trail entry | **Real** — writes a timestamped JSON-line record to `audit_trail.log` |

> Actions are simulated (logged but not executed against any real system) by default — the safe, demo-stable behavior used for every result in `Experimentation_Report.docx`. On `pawn-test`, a feature flag (`EXECUTOR_LIVE_MODE`) swaps `block_ip` and `isolate_host` to genuinely execute inside an isolated, disposable victim container via the Docker SDK — every handler keeps an identical return shape in both modes, so the dashboard and audit trail need no changes to support either. See "Bonus Extension Designs" below.

---

## Complete File Structure (as built, main branch)

```
soc-project/
│
├── docker-compose.yml               # 4 containers: ollama, app, chroma, dashboard
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
    │   ├── reporter.py              # Agent 3 ✅
    │   └── executor.py              # Agent 4 ✅
    │
    ├── rag/
    │   ├── mitre_loader.py          # MITRE ATT&CK → ChromaDB ✅
    │   └── playbook_loader.py       # Remediation playbooks → ChromaDB ✅
    │
    ├── shared/
    │   └── memory.py                # Shared memory bus ✅
    │
    ├── dashboard/
    │   ├── main.py                  # FastAPI backend ✅
    │   ├── index.html               # Live dashboard, 2 tabs ✅
    │   └── Dockerfile
    │
    ├── data/
    │   ├── sample_logs.log          # Bundled simulated SOC dataset ✅
    │   └── incoming/                # Drag-and-drop folder ✅
    │
    └── output/                       # Timestamped run artifacts (gitignored)
        ├── incident_report_<ts>.txt
        ├── report_<ts>.json
        ├── actions_taken_<ts>.json
        ├── audit_trail.log
        └── admin_notifications.txt
```

---

## Deliverables Required by Teacher

### 1. Code source ✅
The complete `src/` folder with all four agents — all built and tested end-to-end.

### 2. Simulated SOC environment ✅
`src/data/sample_logs.log` — 36 realistic log lines covering 7 attack types. Extendable without code changes via the drag-and-drop `src/data/incoming/` folder.

### 3. Technical documentation ✅
- **System architecture** — this file (DAG diagram, container layout, full agent specs)
- **Agent descriptions** — inputs, outputs, SLM prompts, RAG usage for each agent (above) and progress narrative in `PAWN.md`

### 4. Experimentation report ✅
`Experimentation_Report.docx` — 15 pages, all four required sections, built from real measured data:
- **Detection efficacy** — full per-category accuracy tables against known ground truth (96.6% line-level, 100% MITRE mapping on confirmed incidents, 0% false positive rate)
- **SLM performance** — CPU vs GPU timing tables, per-stage latency breakdown, ~100-130s full pipeline runtime on GPU
- **Limits** — model-level (the one real misclassification, label granularity collapse), architectural (sequential calls, static knowledge bases, simulated-not-live remediation), and dataset limits
- **Perspectives** — near-term optimizations, what was built along the way, and full technical designs for all three bonus extensions below

### 5. Optional bonus — dashboard ✅
FastAPI + live HTML dashboard, two tabs (Operations, Incident Report), terminal-style design, 5-second polling, severity filtering, expandable incident detail. Finalized: severity breakdown bars (click-to-filter) replaced an uninformative doughnut chart, the incidents table holds a fixed height so filtering no longer jumps the layout, the refresh button gives visible pulse + timestamp feedback, and the audit feed fades in genuinely new entries between polls for an honest live-update feel.

### 6. Optional bonus — real tool integration / adaptive learning 🔲
Both designed in full below and in the experimentation report §6; not yet built. In progress on `pawn-test`.

---

## Bonus Extension Designs (in progress on `pawn-test`)

None of the following touches `main`. Each extension upgrades exactly one agent, reusing a pattern already proven in the working system — either a new RAG collection queried the same way as the existing two, or a feature-flagged branch that falls back cleanly to the proven simulated behavior. Any subset can be built independently, and all three can coexist, because they communicate only through the same shared-memory/state-dict contract every agent already uses. Build order, confirmed: **adaptive learning → live remediation sandbox → ELK/Splunk (skip if no time)**.

### A. Adaptive learning system — touches Agent 2 only — build first

**Goal:** let the system improve over time from analyst feedback — if an incident is marked a false positive, similar future incidents are treated with appropriate skepticism rather than re-triggering the same confident misclassification.

**Design:**
1. An analyst marks a confirmed incident as a false positive (or true positive) via a dashboard action.
2. That feedback — the incident's description, its assigned MITRE technique, and the analyst's verdict — is embedded and stored in a new ChromaDB collection, `analyst_feedback`.
3. On every subsequent Analyzer run, each new incident's combined summary is additionally queried against `analyst_feedback` alongside the existing MITRE ATT&CK query.
4. If a semantically similar past incident was marked a false positive, that context is injected into the SLM's analysis prompt, directly influencing the returned `threat_level` and `confidence`.

This reuses the exact RAG pattern already proven twice in the working system (MITRE collection, playbook collection) — one new ChromaDB collection, one new query call inside `analyzer.py`, one new dashboard interaction. Estimated 2-3 hours given the pattern is already battle-tested. Built first because it's the cheapest extension and the most direct reuse of existing patterns. **Status: designed, not yet built.**

---

### B. Live remediation sandbox — touches Agent 1 (read path) + Agent 4 (write path) — build second

**Goal:** let Agent 4 take real containment actions against a disposable, fully isolated target instead of only logging simulated commands, and let Agent 1 optionally read from that target's live logs instead of a static file.

**Isolation guarantee:** runs as a second, fully independent Docker Compose project (`COMPOSE_PROJECT_NAME=soc-sandbox`), with its own networks and volumes. The two stacks share only application source code via a read-only bind mount — the baseline's ChromaDB data, Ollama models, and all results in the experimentation report are never touched by sandbox operation.

**Components:**
| Component | Purpose | Status |
|---|---|---|
| `soc-victim-sandbox` (Ubuntu 24.04) | Runs nginx, rsyslog, OpenSSH with intentionally weak auth — a real target with real log output | Dockerfile + entrypoint written |
| `soc-attacker` | Generates realistic but harmless attack traffic on a timer (SSH brute force, port scan, SQLi-shaped requests, connection bursts), plus `trigger.sh` for on-demand attacks during a live demo | Generator script + trigger script written |
| Extractor, live mode | Reads the victim's live `auth.log` / nginx logs via a mounted volume instead of the static file, gated behind `LIVE_MODE` | Implemented, feature-flagged |
| Executor, live mode | Uses the Python Docker SDK against the mounted Docker socket to run real `iptables` rules and network-disconnect operations inside `soc-victim-sandbox`, gated behind `EXECUTOR_LIVE_MODE` | `block_ip` and `isolate_host` implemented; automatic fallback to simulated mode if the flag is off |

**Tooling decision:** the Python Docker SDK, called directly from a LangGraph tool function, was chosen over Docker's MCP Gateway. MCP Gateway's protocol overhead is designed for coordinating many agents against many, possibly third-party, tool servers — this project has one application container talking to one Docker daemon it already controls, so the simpler direct-SDK approach carries materially lower implementation risk for the same functional outcome.

**Safety design:** every live-mode handler preserves the exact return contract used by its simulated counterpart (`action`, `status`, `description`, `incident_id`) — only the `status` value changes (e.g. `executed_live` instead of `simulated`). The dashboard and audit trail require zero changes to support live mode. A single environment variable reverts every agent to the proven, demo-safe simulated behavior at any time.

**Remaining work:** the sandbox's own `docker-compose.yml` and `.env` (defining `COMPOSE_PROJECT_NAME=soc-sandbox`) are not yet written — this is what's needed to actually bring victim + attacker + live-mode app containers up together and test the full loop.

---

### C. ELK Stack / Splunk integration — touches Agent 1 only — build last, if time remains

**Goal:** replace the static log file with a real log ingestion platform, the other named target in the project's bonus criteria.

**Design:** run a single Elasticsearch container within the sandbox stack; ingest the live victim container's logs into it (reusing the same log-sharing volume built for extension B); modify only the Extractor's log-loading function to query Elasticsearch's API instead of reading a file. Because the Extractor already separates "where logs come from" from "how logs are processed" — the same separation that makes the drag-and-drop and live-victim-log modes interchangeable on `main` and in extension B — this integration touches exactly one function and no other agent. **Status: designed, lowest priority, build only if time remains.**

---

### Why all three coexist cleanly

Extension A upgrades Agent 2 only. Extension B upgrades Agent 1's read path and Agent 4's write path. Extension C upgrades Agent 1's read path again, in a way that's a natural superset of B's live-log-tailing (a victim container shipping logs to Elasticsearch instead of being tailed directly). None of the three requires either of the others to function, and building all three simultaneously introduces no shared state conflicts, because every extension communicates through the same per-run state dict already passed between all four agents on `main`.

---

## Key Design Decisions (for the presentation)

**Why one SLM instead of four different models?**
One Qwen 2.5 7B instance serves all four agents with different system prompts. This is the correct academic interpretation of "multi-agent" — agents differ by role and prompt, not by model. It is also simpler to deploy and defend in a presentation.

**Why RAG instead of fine-tuning?**
Fine-tuning a model on MITRE ATT&CK would require significant compute and time. RAG achieves the same result at query time — the model gets the relevant technique descriptions injected into its prompt and reasons over them. No training required. The same pattern carried over cleanly to the playbook knowledge base for Agent 3, and is the basis for the adaptive learning extension design above.

**Why Docker instead of running directly on Windows?**
Isolation, reproducibility, and safety. The entire environment can be wiped and rebuilt in minutes. Nothing touches the host machine — a property that became directly load-bearing once the live remediation sandbox was designed, since it lets Agent 4 take genuinely real actions with a hard guarantee they can never escape a disposable container.

**Why ChromaDB for the vector store?**
Lightweight, runs as a container, has a simple Python client, integrates cleanly with LangChain. Proven across two production collections (MITRE, playbooks) in the working system.

**Why LangGraph instead of plain LangChain?**
Models the pipeline as an explicit directed graph (DAG), matching the project specification exactly, and makes the flow visible and debuggable.

**Why simulated remediation by default, with live mode as an opt-in flag rather than the default?**
Safety and demo reliability. Every result in the experimentation report was produced against the simulated, fully deterministic behavior. Live mode is additive and reversible with a single environment variable — the system never depends on live mode working correctly in order to be gradeable or demoable.

---

## One-liner to explain the whole project (for the presentation)

> "We built a four-agent AI system where each agent is a LangGraph node powered by a local Qwen 2.5 7B model. Agent 1 extracts structured events from raw logs, Agent 2 correlates them into incidents and matches them to MITRE ATT&CK techniques using RAG over ChromaDB, Agent 3 generates a formatted incident report using a second RAG knowledge base of remediation playbooks, and Agent 4 executes remediation actions and maintains a full audit trail. Everything runs locally on GPU inside Docker containers with no cloud dependency, with a live dashboard visualizing the whole pipeline end to end."