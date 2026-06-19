"""
agents/reporter.py
------------------
Agent 3: Reporter

Responsibilities:
  - Read the analysis result from shared memory (written by Agent 2)
  - Retrieve relevant remediation playbooks via RAG (ChromaDB)
  - Use the SLM to write a professional narrative for each confirmed attack
  - Build a complete incident report with:
      * Executive summary
      * Attack timeline
      * Per-incident details with MITRE mapping and playbook steps
      * Severity statistics
      * Prioritized recommendations
  - Save the report to src/output/incident_report.txt
  - Write the structured report dict to shared memory for Agent 4

This is a LangGraph node — receives pipeline state, returns updated state.
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import TypedDict

from ollama import Client

from shared.memory import memory
from rag.playbook_loader import load_playbook_knowledge_base, query_playbook
from agents.extractor import PipelineState

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [REPORTER] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

OLLAMA_HOST  = os.getenv("OLLAMA_HOST", "http://localhost:11434")
CHROMA_HOST  = os.getenv("CHROMA_HOST", "soc-chroma")
MODEL        = "qwen2.5:7b"
OUTPUT_DIR   = os.path.join(os.path.dirname(__file__), "..", "output")
def get_output_file() -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(OUTPUT_DIR, f"incident_report_{ts}.txt")

# Severity display helpers
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ── Step 1: Build the attack timeline ────────────────────────────────────────

def build_timeline(incidents: list[dict]) -> list[dict]:
    """
    Flatten all event timestamps across confirmed incidents into a
    single chronological timeline. Used in the report's timeline section.
    """
    timeline_events = []

    for inc in incidents:
        if not inc.get("confirmed_attack"):
            continue
        timestamps = inc.get("timestamps", [])
        for ts in timestamps:
            timeline_events.append({
                "timestamp":  ts,
                "attack_name": inc.get("attack_name", inc.get("event_type")),
                "source_ip":  inc.get("source_ip", "unknown"),
                "severity":   inc.get("threat_level", "medium"),
            })

    # Sort chronologically
    timeline_events.sort(key=lambda e: e["timestamp"])
    return timeline_events


# ── Step 2: Compute severity statistics ──────────────────────────────────────

def compute_statistics(incidents: list[dict]) -> dict:
    """
    Count incidents by severity, event types, and top attacking IPs.
    Used in the statistics section of the report.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    event_type_counts = {}
    ip_counts = {}

    for inc in incidents:
        if not inc.get("confirmed_attack"):
            continue

        # Severity
        level = inc.get("threat_level", "low")
        severity_counts[level] = severity_counts.get(level, 0) + 1

        # Event types
        etype = inc.get("attack_name", inc.get("event_type", "other"))
        event_type_counts[etype] = event_type_counts.get(etype, 0) + 1

        # Source IPs
        ip = inc.get("source_ip", "unknown")
        if ip and ip != "unknown":
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return {
        "severity_distribution": severity_counts,
        "attack_types":          event_type_counts,
        "top_source_ips":        dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)),
    }


# ── Step 3: SLM narrative generation ─────────────────────────────────────────

def build_narrative_prompt(incident: dict, playbook: dict | None) -> str:
    """
    Ask the SLM to write a professional analyst narrative for one incident.
    The playbook retrieved via RAG is injected as context.
    """
    playbook_section = ""
    if playbook:
        playbook_section = f"""
RELEVANT RESPONSE PLAYBOOK:
{playbook['content'][:500]}
"""

    return f"""You are a senior SOC analyst writing an incident report.
Write a professional 3-4 sentence analyst narrative for this security incident.
Be specific, technical, and actionable. Do not use bullet points.

INCIDENT:
- Attack: {incident.get('attack_name', 'Unknown')}
- MITRE Technique: {incident.get('mitre_technique_id')} — {incident.get('mitre_technique_name')}
- Source IP: {incident.get('source_ip', 'unknown')}
- Threat Level: {incident.get('threat_level', 'unknown')}
- Confidence: {incident.get('confidence', 'unknown')}
- Analysis: {incident.get('explanation', '')}
- Recommended Action: {incident.get('recommended_action', '')}
{playbook_section}

Write only the narrative paragraph, no headers or labels:"""


def generate_narrative(client: Client, incident: dict, playbook: dict | None) -> str:
    """Generate a professional analyst narrative for one confirmed incident."""
    prompt = build_narrative_prompt(incident, playbook)
    try:
        response = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3},  # slightly higher temp for natural prose
        )
        return response["message"]["content"].strip()
    except Exception as e:
        logger.warning(f"Narrative generation failed: {e}")
        return incident.get("explanation", "Narrative generation failed — review manually.")


# ── Step 4: Assemble the full report ─────────────────────────────────────────

def assemble_report(
    confirmed_incidents: list[dict],
    timeline: list[dict],
    statistics: dict,
    narratives: dict,
    overall_threat: str,
) -> dict:
    """
    Assemble all components into a single structured report dict.
    This dict is both saved to file and written to shared memory for Agent 4.
    """
    now = datetime.now().isoformat()

    return {
        "report_id":        f"INC-{datetime.now().strftime('%Y%m%d-%H%M')}",
        "generated_at":     now,
        "overall_threat":   overall_threat,
        "total_confirmed":  len(confirmed_incidents),
        "executive_summary": {
            "threat_level":     overall_threat,
            "confirmed_attacks": len(confirmed_incidents),
            "critical_count":   statistics["severity_distribution"].get("critical", 0),
            "high_count":       statistics["severity_distribution"].get("high", 0),
            "top_threat":       confirmed_incidents[0].get("attack_name") if confirmed_incidents else "none",
            "top_source_ip":    list(statistics["top_source_ips"].keys())[0] if statistics["top_source_ips"] else "unknown",
        },
        "timeline":   timeline,
        "incidents":  [
            {
                **inc,
                "narrative": narratives.get(inc["incident_id"], ""),
            }
            for inc in confirmed_incidents
        ],
        "statistics": statistics,
        "recommendations": [
            {
                "priority": idx + 1,
                "action":   inc.get("recommended_action", ""),
                "for":      inc.get("attack_name", ""),
                "severity": inc.get("threat_level", ""),
            }
            for idx, inc in enumerate(confirmed_incidents)
            if inc.get("recommended_action")
        ],
    }


# ── Step 5: Render the report as readable text ───────────────────────────────

def render_report_text(report: dict) -> str:
    """
    Convert the structured report dict into a formatted text file.
    This is what gets saved to incident_report.txt.
    """
    sep  = "═" * 68
    sep2 = "─" * 68
    lines = []

    # Header
    lines += [
        sep,
        f"  SOC INCIDENT REPORT — {report['report_id']}",
        f"  Generated : {report['generated_at']}",
        f"  Overall Threat Level : {report['overall_threat'].upper()}",
        sep,
        "",
    ]

    # Executive Summary
    es = report["executive_summary"]
    lines += [
        "EXECUTIVE SUMMARY",
        sep2,
        f"  Threat Level     : {SEVERITY_EMOJI.get(es['threat_level'], '')} {es['threat_level'].upper()}",
        f"  Confirmed Attacks: {es['confirmed_attacks']}",
        f"  Critical         : {es['critical_count']}  |  High: {es['high_count']}",
        f"  Primary Threat   : {es['top_threat']}",
        f"  Top Attacker IP  : {es['top_source_ip']}",
        "",
    ]

    # Attack Timeline
    lines += ["ATTACK TIMELINE", sep2]
    for event in report["timeline"]:
        emoji = SEVERITY_EMOJI.get(event["severity"], "⚪")
        lines.append(
            f"  {event['timestamp'][:19]}  {emoji}  "
            f"{event['attack_name']:<35} src={event['source_ip']}"
        )
    lines.append("")

    # Incident Details
    lines += ["INCIDENT DETAILS", sep2]
    for inc in report["incidents"]:
        emoji = SEVERITY_EMOJI.get(inc.get("threat_level", "low"), "⚪")
        lines += [
            f"  [{inc['incident_id']}] {emoji} {inc.get('attack_name', 'Unknown Attack').upper()}",
            f"  MITRE   : {inc.get('mitre_technique_id')} — {inc.get('mitre_technique_name')}",
            f"  Source  : {inc.get('source_ip', 'unknown')}",
            f"  Threat  : {inc.get('threat_level', '').upper()}  |  Confidence: {inc.get('confidence', '').upper()}",
            f"  Events  : {inc.get('event_count', 1)} log entries",
            "",
            f"  ANALYSIS:",
        ]
        # Word-wrap the narrative at 65 chars
        narrative = inc.get("narrative", inc.get("explanation", ""))
        words = narrative.split()
        line_buf = "  "
        for word in words:
            if len(line_buf) + len(word) + 1 > 67:
                lines.append(line_buf)
                line_buf = "  " + word
            else:
                line_buf += (" " if line_buf.strip() else "") + word
        if line_buf.strip():
            lines.append(line_buf)

        lines += [
            "",
            f"  RECOMMENDED ACTION:",
            f"  → {inc.get('recommended_action', 'Manual investigation required.')}",
            "",
            sep2,
        ]

    # Statistics
    stats = report["statistics"]
    lines += [
        "",
        "STATISTICS",
        sep2,
        "  Severity Distribution:",
    ]
    for level in ["critical", "high", "medium", "low"]:
        count = stats["severity_distribution"].get(level, 0)
        bar = "█" * count
        lines.append(f"    {level:<10} {bar} ({count})")

    lines += ["", "  Attack Types:"]
    for atype, count in stats["attack_types"].items():
        lines.append(f"    {atype:<35} {count}")

    if stats["top_source_ips"]:
        lines += ["", "  Top Attacker IPs:"]
        for ip, count in stats["top_source_ips"].items():
            lines.append(f"    {ip:<20} {count} incident(s)")

    # Recommendations
    lines += ["", "", "PRIORITIZED RECOMMENDATIONS", sep2]
    for rec in report["recommendations"]:
        emoji = SEVERITY_EMOJI.get(rec["severity"], "⚪")
        lines += [
            f"  [{rec['priority']}] {emoji} {rec['for']}",
            f"      → {rec['action']}",
            "",
        ]

    lines += [sep, "  END OF REPORT", sep]
    return "\n".join(lines)


# ── Main LangGraph node ───────────────────────────────────────────────────────

def reporter_node(state: PipelineState) -> PipelineState:
    """
    LangGraph node for Agent 3 — Reporter.

    Input:  state with 'analysis_result' populated by Agent 2
    Output: state with 'report' populated for Agent 4
    """
    logger.info("=== Agent 3: Reporter starting ===")

    client = Client(host=OLLAMA_HOST)

    # Step 1: Read analysis from pipeline state or shared memory
    analysis = state.get("analysis_result") or memory.get("analysis_result", {})
    if not analysis:
        logger.error("No analysis result found — did Agent 2 run?")
        return {**state, "report": {"error": "No analysis to report"}}

    all_incidents    = analysis.get("incidents", [])
    overall_threat   = analysis.get("overall_threat_level", "unknown")
    confirmed        = [i for i in all_incidents if i.get("confirmed_attack")]

    logger.info(f"Building report for {len(confirmed)} confirmed attacks")

    # Step 2: Load playbook knowledge base (RAG)
    logger.info("Loading remediation playbooks into ChromaDB...")
    playbook_collection = load_playbook_knowledge_base(chroma_host=CHROMA_HOST)

    # Step 3: Build timeline and statistics
    timeline   = build_timeline(all_incidents)
    statistics = compute_statistics(all_incidents)
    logger.info(f"Timeline: {len(timeline)} events | Stats computed")

    # Step 4: Generate SLM narrative for each confirmed incident
    logger.info(f"Generating analyst narratives for {len(confirmed)} incidents...")
    narratives = {}

    for i, inc in enumerate(confirmed):
        logger.info(f"  Narrative {i+1}/{len(confirmed)}: {inc.get('attack_name')}")

        # RAG — retrieve relevant playbook
        query = f"{inc.get('attack_name', '')} {inc.get('mitre_technique_id', '')} {inc.get('event_type', '')}"
        playbook = query_playbook(playbook_collection, query)
        if playbook:
            logger.info(f"    Playbook retrieved: {playbook['title']}")

        # SLM narrative generation
        narrative = generate_narrative(client, inc, playbook)
        narratives[inc["incident_id"]] = narrative

    # Step 5: Assemble structured report
    report = assemble_report(confirmed, timeline, statistics, narratives, overall_threat)

    # Step 6: Render to text and save file
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report_text = render_report_text(report)

    output_file = get_output_file()
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_text)

    logger.info(f"✅ Report saved to {output_file}")

    # Step 7: Write to shared memory for Agent 4
    memory.set("report", report)
    memory.set("reporter_status", "done")

    logger.info(f"=== Reporter done: report {report['report_id']} generated ===")

    return {
        **state,
        "report": report,
    }


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from agents.extractor import extractor_node
    from agents.analyzer  import analyzer_node

    initial: PipelineState = {
        "raw_lines": [], "extracted_events": [],
        "analysis_result": {}, "report": {}, "actions_taken": [],
    }

    print("Running Extractor...")
    s1 = extractor_node(initial)
    print("Running Analyzer...")
    s2 = analyzer_node(s1)
    print("Running Reporter...")
    s3 = reporter_node(s2)

    print(f"\n✅ Report saved to: {OUTPUT_FILE}")
    print("\nFirst 30 lines of report:")
    with open(OUTPUT_FILE) as f:
        for i, line in enumerate(f):
            if i >= 30:
                break
            print(line, end="")