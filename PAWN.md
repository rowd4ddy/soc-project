# PAWN — Build Log

> PAWN started as a progress tracker chasing the target spec in KING.md.
> The pawn reached the king. This file is now the final project record — what was built, what broke, and what was learned.

---

## Final Status

| Deliverable | Branch | Status |
|-------------|--------|--------|
| 4-agent LangGraph pipeline | main | ✅ Done |
| SOC simulation dataset (36 lines, 7 attack types) | main | ✅ Done |
| ChromaDB RAG — MITRE ATT&CK (10 techniques) | main | ✅ Done |
| ChromaDB RAG — Remediation playbooks (7 playbooks) | main | ✅ Done |
| Shared memory bus | main | ✅ Done |
| Operations + Incident Report dashboard | main | ✅ Done |
| Experimentation report | main | ✅ Done |
| Adaptive learning — analyst feedback loop | pawn-test | ✅ Done + validated |
| ELK Stack — Elasticsearch 8.13 + Kibana | pawn-test | ✅ Done + validated |
| Live sandbox — real victim/attacker containers | pawn-test | ✅ Done + validated |
| Real executor — iptables DROP via Docker SDK | pawn-test | ✅ Done + validated |

---

## What was built, in order

### Phase 1 — Core pipeline (main)

Started with Agent 1. The first working version just called the SLM on each line and printed the result. No structure, no pipeline. Got that working, then added the pre-filter (keyword list before any SLM call) — this cut the number of LLM calls from 36 to 29 on the sample dataset with zero attack lines missed.

Agent 2 was the hardest agent to get right. The correlation logic (grouping by event_type + source_ip) was straightforward, but getting ChromaDB to actually return useful MITRE techniques required tuning the stored descriptions. The first version stored raw MITRE spec language and got bad similarity matches. Rewrote the descriptions to use observable log language instead — "repeated failed SSH logins from same IP" rather than "adversary attempts to obtain valid credentials." Match quality improved noticeably.

Agent 3 was fast to build once the playbook RAG pattern was clear from Agent 2. The main challenge was getting the dual output (`.txt` for humans, `.json` for the dashboard) to save reliably — early versions only saved `.txt`, which left the dashboard Incident Report tab empty.

Agent 4 had two phases. Phase 1: rule-based keyword dispatch with simulated actions — built in an afternoon. Phase 2 (on pawn-test): real execution via Docker SDK — took longer because the executor.py on disk was an old version that didn't have the live mode code, and the socket mount was missing from docker-compose.yml.

LangGraph wiring happened incrementally — tested each agent standalone via its `__main__` block before connecting them into the graph. This saved a lot of debugging time.

### Phase 2 — Dashboard (main)

FastAPI backend was quick. The frontend took longer than expected. Issues hit:

- Incident Report tab was empty — traced to reporter.py not saving `.json`
- The doughnut chart looked unfinished and didn't add information — replaced with severity bars that also filter the table on click
- Layout jumped when filtering by severity — fixed with a fixed-height scroll container
- Refresh button had no visual feedback — added pulse + last-updated timestamp
- After clicking Clear, new pipeline results wouldn't appear — the catch block was rebuilding the DOM and destroying element IDs; fixed with a `wasCleared` flag and conditional `renderShell()`

### Phase 3 — Bonus extensions (pawn-test)

**Adaptive learning:** The design was already clear from how MITRE and playbook RAG worked. Adding a third collection (`analyst_feedback`) and querying it in the Analyzer alongside the MITRE collection was the logical extension. The dashboard already had the card structure — just added true/false positive buttons. Validation: marked Port Scanning as false positive → next run logged `feedback match → false_positive (relevance: 0.838)` → confidence dropped HIGH → LOW → 5 confirmed attacks instead of 6.

**ELK Stack:** Elasticsearch + Kibana added as an optional Docker Compose profile. `elk_ingest.py` does a bulk insert of the sample logs. The Extractor got a third source resolution path (`ELK_MODE=true` → HTTP query on ES). Validated: 36/36 docs indexed, pipeline reads from ES, results identical to file mode.

**Live sandbox:** This was the most complex bonus. Two new containers — `soc-victim` (Ubuntu 24.04, nginx, SSH, rsyslog) and `soc-attacker` (openssh-client, nmap, curl). Several things broke before it worked:

- rsyslog loop: Ubuntu 24.04 has no systemd. `service rsyslog start` fails silently. Fixed by calling `rsyslogd` directly in entrypoint.sh.
- SSH brute force generated no auth.log entries: `sshpass` was missing from the attacker image. Switched to `openssh-client` with password via stdin.
- SQLi payloads were disappearing from nginx logs: curl URL-encodes special characters. Added `--path-as-is` flag.
- 0 lines read in LIVE_MODE: the `victim-logs` volume wasn't mounted in `soc-app`. Added it to docker-compose.yml.
- Agent 4 stayed simulated despite the flag: the executor.py on disk was the old version without the live mode code. Replaced the file.
- `NameError: ACTIONS_FILE` after successful execution: a variable was used before being assigned. Fixed with `actions_file = get_actions_file()`.

Validation: brute force attack → pipeline → `[LIVE] iptables -A INPUT -s 172.19.0.10 -j DROP -> exit=0` → `iptables -L INPUT -n` shows the DROP rule → re-run the attack → no new entries in auth.log.

---

## What broke and the fix

| Bug | Root cause | Fix |
|-----|-----------|-----|
| Dashboard Incident Report tab empty | reporter.py only saved .txt, never .json | Added json.dump() output in reporter.py |
| Feedback submit timeout (60s) | soc-dashboard re-downloaded ONNX model (79 MB) on every call | Added onnx-cache volume to soc-dashboard |
| ChromaDB API 404 errors | pip installed v0.6.x, Docker image was v0.5.5 | Pinned both sides to 0.5.5 |
| soc-victim restarting in loop | Ubuntu 24.04 no systemd, `service rsyslog start` fails | Changed to `rsyslogd` direct binary in entrypoint |
| SQLi not appearing in nginx logs | curl URL-encodes special chars | Added `--path-as-is` + URL-encoded spaces |
| SSH brute force no auth.log entries | sshpass missing → no ssh binary | Switched to openssh-client with stdin password |
| Agent 4 always simulated | Old executor.py on disk, no live mode code | Replaced the file |
| 0 lines in LIVE_MODE | victim-logs volume not mounted in soc-app | Added mount to docker-compose.yml |
| NameError: ACTIONS_FILE | Variable used before assigned | `actions_file = get_actions_file()` |
| Dashboard breaks after Clear | catch block destroyed DOM element IDs | wasCleared flag + conditional renderShell() |

---

## Decisions worth noting

**One SLM for four agents.** Each agent is differentiated by its prompt system, not by the model. This is the standard LangGraph interpretation of "multi-agent" and it worked — Agent 1 extracts JSON at temperature 0.1, Agent 3 writes narrative prose at 0.3, same model, completely different behavior.

**RAG descriptions in observable log language.** The MITRE ATT&CK descriptions stored in ChromaDB are not the official spec text. They're written in terms of what you'd actually see in a log file. This made a real difference to similarity match quality.

**Keyword dispatch in Agent 4 instead of SLM.** Deterministic, fast, auditable. A rule that says "block" → `block_ip()` is better than asking an LLM to decide whether to block an IP. The SLM is only called for the supplementary "additional actions" on critical incidents.

**Feature flags instead of separate branches for live mode.** `LIVE_MODE` and `EXECUTOR_LIVE_MODE` environment variables let the same codebase run in simulated or real mode with no code changes. Every live handler has an identical return shape to its simulated counterpart — the dashboard and audit trail work in both modes without modification.

**ChromaDB version pinned both sides.** Learned this the hard way. Client and server must be the same version. 0.5.5 everywhere.

---

*rowd4ddy 2025/2026*