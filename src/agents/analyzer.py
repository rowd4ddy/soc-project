"""
agents/analyzer.py
------------------
Agent 2: Analyzer

Responsibilities:
  - Read extracted events from shared memory (written by Agent 1)
  - Correlate related events into incidents
    (e.g. 10 failed SSHs + 1 success = one brute force incident, not 11 events)
  - Query ChromaDB to retrieve matching MITRE ATT&CK techniques (RAG step)
  - Use the SLM to analyze the correlated incidents with ATT&CK context
  - Assign overall threat level: low / medium / high / critical
  - Write the analysis result to shared memory for Agent 3

This is a LangGraph node — it receives the pipeline state and returns an updated state.
"""

import os
import re
import json
import logging
from collections import defaultdict
from typing import TypedDict

from ollama import Client

from shared.memory import memory
from rag.mitre_loader import load_mitre_knowledge_base, query_techniques
from agents.extractor import PipelineState

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ANALYZER] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

OLLAMA_HOST  = os.getenv("OLLAMA_HOST", "http://localhost:11434")
CHROMA_HOST  = os.getenv("CHROMA_HOST", "soc-chroma")
MODEL        = "qwen2.5:7b"


# ── Step 1: Event Correlation ─────────────────────────────────────────────────
#
# Raw events from Agent 1 are individual log lines.
# Correlation groups them into meaningful incidents.
# Example: 10 "Failed password" events from the same IP → one brute_force incident.

def correlate_events(events: list[dict]) -> list[dict]:
    """
    Group related events into incidents based on:
      - Same event type
      - Same source IP (when available)

    Returns a list of incident dicts, each containing:
      - all the raw events that belong to it
      - a combined summary for RAG querying
      - the highest severity seen across events
    """
    # Group by (event_type, source_ip) — the natural correlation key
    groups = defaultdict(list)
    for event in events:
        key = (
            event.get("event_type", "other"),
            event.get("source_ip") or "unknown",
        )
        groups[key].append(event)

    incidents = []
    for (event_type, source_ip), group_events in groups.items():

        # Severity ladder — pick the highest severity in the group
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_severity = max(
            group_events,
            key=lambda e: severity_order.get(e.get("severity", "low"), 0)
        ).get("severity", "low")

        # Escalate severity if there are many events (volume = more suspicious)
        count = len(group_events)
        if count >= 10 and max_severity == "medium":
            max_severity = "high"
        if count >= 5 and max_severity == "low":
            max_severity = "medium"

        # Build a combined text description for RAG querying
        summaries = [e.get("summary", "") for e in group_events if e.get("summary")]
        combined_summary = f"{event_type} from {source_ip}: " + " | ".join(summaries[:5])

        incidents.append({
            "incident_id":   f"inc-{len(incidents)+1:03d}",
            "event_type":    event_type,
            "source_ip":     source_ip,
            "event_count":   count,
            "severity":      max_severity,
            "timestamps":    [e.get("timestamp") for e in group_events],
            "combined_summary": combined_summary,
            "raw_events":    group_events,
        })

    # Sort by severity descending so the most critical come first
    severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    incidents.sort(key=lambda i: severity_order.get(i["severity"], 0), reverse=True)

    logger.info(f"Correlation: {len(events)} events → {len(incidents)} incidents")
    return incidents


# ── Step 2: RAG — Retrieve matching MITRE ATT&CK techniques ───────────────────
#
# For each incident, search ChromaDB for the most semantically similar
# ATT&CK technique descriptions. These get injected into the SLM prompt.

def enrich_with_mitre(incidents: list[dict], collection) -> list[dict]:
    """
    For each incident, query ChromaDB to find the most relevant MITRE ATT&CK techniques.
    Adds a 'mitre_techniques' list to each incident dict.
    """
    for incident in incidents:
        query_text = incident["combined_summary"]

        # RAG retrieval — find the 3 most similar ATT&CK technique descriptions
        techniques = query_techniques(collection, query_text, n_results=3)
        incident["mitre_techniques"] = techniques

        if techniques:
            top = techniques[0]
            logger.info(
                f"  [{incident['incident_id']}] → {top['id']} {top['name']} "
                f"(relevance: {top['relevance']})"
            )

    return incidents


# ── Step 3: SLM Analysis ──────────────────────────────────────────────────────
#
# Now that each incident has ATT&CK context from RAG, we send it to the SLM
# for a structured analysis. The model sees both the raw events AND the
# relevant technique descriptions — this is the "Augmented Generation" part.

def build_analysis_prompt(incident: dict) -> str:
    """
    Build the prompt for a single incident analysis.
    The MITRE techniques retrieved via RAG are injected as context.
    """
    # Format the ATT&CK context block
    mitre_context = ""
    for t in incident.get("mitre_techniques", []):
        mitre_context += f"\n- {t['id']} ({t['name']}): {t['description'][:200]}..."

    return f"""You are a SOC analyst. Analyze this security incident and return ONLY valid JSON.

INCIDENT DETAILS:
- Type: {incident['event_type']}
- Source IP: {incident['source_ip']}
- Number of events: {incident['event_count']}
- Severity detected: {incident['severity']}
- Summary: {incident['combined_summary']}

RELEVANT MITRE ATT&CK TECHNIQUES (retrieved from knowledge base):
{mitre_context}

Analyze this incident and return ONLY this JSON structure:
{{
  "confirmed_attack": true or false,
  "attack_name": "short name of the attack (e.g. SSH Brute Force)",
  "mitre_technique_id": "most relevant technique ID from the list above (e.g. T1110)",
  "mitre_technique_name": "name of that technique",
  "threat_level": "one of: low | medium | high | critical",
  "confidence": "one of: low | medium | high",
  "explanation": "2-3 sentences explaining what happened and why it is suspicious",
  "recommended_action": "one concrete action to take (e.g. block IP, isolate machine)"
}}

JSON:"""


def analyze_incident(client: Client, incident: dict) -> dict:
    """
    Send one incident to the SLM for analysis.
    Returns the SLM's structured assessment merged with the incident metadata.
    """
    prompt = build_analysis_prompt(incident)

    try:
        response = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},
        )
        raw = response["message"]["content"].strip()

        # Strip markdown fences if present
        raw = re.sub(r"^```(?:json)?", "", raw).strip()
        raw = re.sub(r"```$", "", raw).strip()

        slm_result = json.loads(raw)

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"SLM analysis failed for {incident['incident_id']}: {e}")
        slm_result = {
            "confirmed_attack":    False,
            "attack_name":         incident["event_type"],
            "mitre_technique_id":  "unknown",
            "mitre_technique_name":"unknown",
            "threat_level":        incident["severity"],
            "confidence":          "low",
            "explanation":         "Analysis failed — review manually.",
            "recommended_action":  "Manual investigation required.",
        }

    # Merge incident metadata with SLM analysis
    return {
        "incident_id":         incident["incident_id"],
        "event_type":          incident["event_type"],
        "source_ip":           incident["source_ip"],
        "event_count":         incident["event_count"],
        "timestamps":          incident["timestamps"],
        "mitre_techniques":    incident.get("mitre_techniques", []),
        **slm_result,
    }


# ── Step 4: Overall threat summary ───────────────────────────────────────────

def compute_overall_threat(analyzed_incidents: list[dict]) -> str:
    """
    Compute one overall threat level for the entire session.
    Returns the highest threat level found across all confirmed attacks.
    """
    level_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    confirmed = [i for i in analyzed_incidents if i.get("confirmed_attack")]

    if not confirmed:
        return "low"

    highest = max(confirmed, key=lambda i: level_order.get(i.get("threat_level", "low"), 0))
    return highest.get("threat_level", "low")


# ── Main LangGraph node ───────────────────────────────────────────────────────

def analyzer_node(state: PipelineState) -> PipelineState:
    """
    LangGraph node for Agent 2 — Analyzer.

    Input:  state with 'extracted_events' populated by Agent 1
    Output: state with 'analysis_result' populated for Agent 3
    """
    logger.info("=== Agent 2: Analyzer starting ===")

    client     = Client(host=OLLAMA_HOST)

    # Step 1: Load events from pipeline state (or fall back to shared memory)
    events = state.get("extracted_events") or memory.get("extracted_events", [])
    if not events:
        logger.error("No extracted events found — did Agent 1 run?")
        return {**state, "analysis_result": {"error": "No events to analyze"}}

    logger.info(f"Received {len(events)} events from Agent 1")

    # Step 2: Load MITRE ATT&CK knowledge base into ChromaDB (idempotent)
    logger.info("Loading MITRE ATT&CK knowledge base into ChromaDB...")
    collection = load_mitre_knowledge_base(chroma_host=CHROMA_HOST)

    # Step 3: Correlate events into incidents
    incidents = correlate_events(events)

    # Step 4: Enrich each incident with RAG-retrieved ATT&CK techniques
    logger.info("Querying ChromaDB for relevant MITRE ATT&CK techniques...")
    incidents = enrich_with_mitre(incidents, collection)

    # Step 5: SLM analysis for each incident
    logger.info(f"Sending {len(incidents)} incidents to SLM for analysis...")
    analyzed_incidents = []
    for i, incident in enumerate(incidents):
        logger.info(f"Analyzing incident {i+1}/{len(incidents)}: {incident['event_type']} from {incident['source_ip']}")
        result = analyze_incident(client, incident)
        analyzed_incidents.append(result)
        logger.info(
            f"  → {result.get('attack_name')} | "
            f"threat: {result.get('threat_level')} | "
            f"confidence: {result.get('confidence')} | "
            f"MITRE: {result.get('mitre_technique_id')}"
        )

    # Step 6: Compute overall threat level
    overall_threat = compute_overall_threat(analyzed_incidents)
    logger.info(f"Overall threat level: {overall_threat.upper()}")

    analysis_result = {
        "overall_threat_level": overall_threat,
        "total_incidents":      len(analyzed_incidents),
        "confirmed_attacks":    sum(1 for i in analyzed_incidents if i.get("confirmed_attack")),
        "incidents":            analyzed_incidents,
    }

    # Step 7: Write to shared memory for Agent 3
    memory.set("analysis_result", analysis_result)
    memory.set("analyzer_status", "done")

    logger.info(
        f"=== Analyzer done: {analysis_result['confirmed_attacks']} confirmed attacks "
        f"out of {analysis_result['total_incidents']} incidents ==="
    )

    return {
        **state,
        "analysis_result": analysis_result,
    }


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from agents.extractor import extractor_node

    # Run extractor first to populate events
    initial_state: PipelineState = {
        "raw_lines": [], "extracted_events": [],
        "analysis_result": {}, "report": {}, "actions_taken": [],
    }

    print("Running Extractor first...")
    state_after_extractor = extractor_node(initial_state)

    print("\nRunning Analyzer...")
    final_state = analyzer_node(state_after_extractor)

    print("\n── Analysis Result ───────────────────────────")
    result = final_state["analysis_result"]
    print(f"Overall threat: {result['overall_threat_level'].upper()}")
    print(f"Incidents: {result['total_incidents']} total, {result['confirmed_attacks']} confirmed\n")

    for inc in result["incidents"]:
        print(f"[{inc['incident_id']}] {inc.get('attack_name')}")
        print(f"  MITRE : {inc.get('mitre_technique_id')} — {inc.get('mitre_technique_name')}")
        print(f"  Threat: {inc.get('threat_level')} | Confidence: {inc.get('confidence')}")
        print(f"  Action: {inc.get('recommended_action')}")
        print()