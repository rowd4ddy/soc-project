"""
agents/executor.py
------------------
Agent 4: Executor

Responsibilities:
  - Read the incident report from shared memory (written by Agent 3)
  - Map each recommended action to a concrete response function
  - Execute actions according to priority (critical first)
  - Simulate actions that cannot run safely in a dev environment
    (real execution would swap simulation functions for real ones)
  - Write a full audit trail with timestamps to src/output/audit_trail.log
  - Write the actions taken list to shared memory

This is the final LangGraph node — it closes the pipeline loop.

Note on simulation:
  In a production SOC system, these functions would call real APIs:
    - block_ip()     → iptables / firewall API / SIEM
    - isolate_host() → network switch API / EDR agent
    - notify_admin() → email / Slack / PagerDuty
  For this university project, each action is simulated and logged.
  The architecture supports swapping simulation for real execution
  by replacing the function bodies — no structural changes needed.
"""

import os
import json
import logging
from datetime import datetime

from ollama import Client

from shared.memory import memory
from agents.extractor import PipelineState

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EXECUTOR] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL       = "qwen2.5:7b"
OUTPUT_DIR  = os.path.join(os.path.dirname(__file__), "..", "output")
AUDIT_FILE  = os.path.join(OUTPUT_DIR, "audit_trail.log")


def get_actions_file() -> str:
    """Return a timestamped path so each run gets its own actions file."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(OUTPUT_DIR, f"actions_taken_{ts}.json")


# ── Action keyword dispatcher ─────────────────────────────────────────────────
# Maps keywords found in recommendation text to handler function names.

ACTION_KEYWORDS = {
    "block":     "block_ip",
    "isolate":   "isolate_host",
    "notify":    "notify_admin",
    "rate":      "apply_rate_limit",
    "forensic":  "trigger_forensics",
    "monitor":   "enable_monitoring",
    "lock":      "lock_account",
}


# ── Audit trail writer ────────────────────────────────────────────────────────

def write_audit(entry: dict) -> None:
    """
    Append one action record to the audit trail log file.
    Every action — simulated or real — gets logged here for compliance.
    Format: one JSON object per line (JSON Lines format).
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ── Simulated action handlers ─────────────────────────────────────────────────

def block_ip(ip: str, reason: str, incident_id: str) -> dict:
    """
    Simulate blocking an IP address at the firewall.
    Real implementation: subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    """
    if not ip or ip == "unknown":
        return {
            "action":  "block_ip",
            "status":  "skipped",
            "reason":  "No valid IP address available to block",
        }
    command = f"iptables -A INPUT -s {ip} -j DROP"
    logger.info(f"  [SIMULATED] {command}")
    return {
        "action":      "block_ip",
        "status":      "simulated",
        "target_ip":   ip,
        "command":     command,
        "description": f"Firewall rule added to block all inbound traffic from {ip}",
        "incident_id": incident_id,
    }


def isolate_host(ip: str, reason: str, incident_id: str) -> dict:
    """
    Simulate isolating a compromised host from the network.
    Real implementation: EDR agent API or network switch VLAN change.
    """
    logger.info(f"  [SIMULATED] Network isolation triggered for host {ip}")
    return {
        "action":      "isolate_host",
        "status":      "simulated",
        "target":      ip if ip and ip != "unknown" else "affected-host",
        "steps": [
            "Host removed from production VLAN",
            "Host placed in quarantine VLAN",
            "All outbound connections terminated",
            "EDR agent deployed for forensic collection",
        ],
        "description": "Host isolated from network to prevent lateral movement",
        "incident_id": incident_id,
    }


def notify_admin(message: str, severity: str, incident_id: str) -> dict:
    """
    Write a real notification file — this action is NOT simulated.
    In production: send email / Slack / PagerDuty alert.
    """
    notify_file = os.path.join(OUTPUT_DIR, "admin_notifications.txt")
    timestamp   = datetime.now().isoformat()
    notification = (
        f"\n{'='*60}\n"
        f"SECURITY ALERT — {timestamp}\n"
        f"Incident: {incident_id}\n"
        f"Severity: {severity.upper()}\n"
        f"Message : {message}\n"
        f"{'='*60}\n"
    )
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(notify_file, "a", encoding="utf-8") as f:
        f.write(notification)
    logger.info(f"  [REAL] Admin notification written to {notify_file}")
    return {
        "action":      "notify_admin",
        "status":      "executed",
        "file":        notify_file,
        "description": f"Admin notification written for incident {incident_id}",
        "incident_id": incident_id,
    }


def apply_rate_limit(ip: str, reason: str, incident_id: str) -> dict:
    """Simulate applying SYN packet rate limiting rules."""
    command = (
        "iptables -A INPUT -p tcp --syn -m limit "
        "--limit 1/s --limit-burst 3 -j ACCEPT"
    )
    logger.info(f"  [SIMULATED] {command}")
    return {
        "action":      "apply_rate_limit",
        "status":      "simulated",
        "command":     command,
        "description": "SYN packet rate limiting applied to mitigate flood attack",
        "incident_id": incident_id,
    }


def trigger_forensics(ip: str, reason: str, incident_id: str) -> dict:
    """Simulate triggering a forensic investigation workflow."""
    logger.info(f"  [SIMULATED] Forensic collection initiated for incident {incident_id}")
    return {
        "action":  "trigger_forensics",
        "status":  "simulated",
        "steps": [
            "Memory dump initiated",
            "Disk image queued for acquisition",
            "Process list captured",
            "Network connections snapshot taken",
            "Malware sample submitted to sandbox",
        ],
        "description": f"Forensic investigation workflow triggered for {incident_id}",
        "incident_id": incident_id,
    }


def enable_monitoring(ip: str, reason: str, incident_id: str) -> dict:
    """Simulate enabling enhanced monitoring for a suspicious IP."""
    logger.info(f"  [SIMULATED] Enhanced monitoring enabled for {ip}")
    return {
        "action":      "enable_monitoring",
        "status":      "simulated",
        "target_ip":   ip,
        "description": f"Enhanced logging and alerting enabled for traffic from {ip}",
        "incident_id": incident_id,
    }


def lock_account(ip: str, reason: str, incident_id: str) -> dict:
    """Simulate locking a compromised user account."""
    command = "passwd -l root && pkill -u root"
    logger.info(f"  [SIMULATED] {command}")
    return {
        "action":      "lock_account",
        "status":      "simulated",
        "command":     command,
        "description": "Root account locked and active sessions terminated",
        "incident_id": incident_id,
    }


# ── Action dispatcher ─────────────────────────────────────────────────────────

def dispatch_action(recommendation: str, incident: dict) -> dict:
    """
    Match the recommendation text to an action handler and call it.
    Falls back to manual_review if no keyword matches.
    """
    rec_lower   = recommendation.lower()
    incident_id = incident.get("incident_id", "unknown")
    source_ip   = incident.get("source_ip", "unknown")
    severity    = incident.get("threat_level", "medium")

    handler_name = None
    for keyword, action in ACTION_KEYWORDS.items():
        if keyword in rec_lower:
            handler_name = action
            break

    handlers = {
        "block_ip":          lambda: block_ip(source_ip, recommendation, incident_id),
        "isolate_host":      lambda: isolate_host(source_ip, recommendation, incident_id),
        "notify_admin":      lambda: notify_admin(recommendation, severity, incident_id),
        "apply_rate_limit":  lambda: apply_rate_limit(source_ip, recommendation, incident_id),
        "trigger_forensics": lambda: trigger_forensics(source_ip, recommendation, incident_id),
        "enable_monitoring": lambda: enable_monitoring(source_ip, recommendation, incident_id),
        "lock_account":      lambda: lock_account(source_ip, recommendation, incident_id),
    }

    if handler_name and handler_name in handlers:
        return handlers[handler_name]()

    logger.info(f"  [MANUAL] No automated handler — flagged for manual review")
    return {
        "action":         "manual_review",
        "status":         "flagged",
        "description":    "No automated handler matched — flagged for manual SOC review",
        "recommendation": recommendation,
        "incident_id":    incident_id,
    }


# ── SLM additional action planning ───────────────────────────────────────────

def plan_additional_actions(client: Client, incident: dict) -> list[str]:
    """
    Ask the SLM for 2 additional response actions beyond the primary recommendation.
    Only called for critical incidents.
    """
    import re
    prompt = f"""You are a SOC responder. Given this confirmed attack, list 2 additional
response actions beyond the primary recommendation. Return ONLY a JSON array of strings.

Attack: {incident.get('attack_name')}
MITRE: {incident.get('mitre_technique_id')}
Threat: {incident.get('threat_level')}
Primary action already taken: {incident.get('recommended_action', '')}

Return ONLY a JSON array like: ["action one", "action two"]
JSON:"""

    try:
        response = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},
        )
        raw = response["message"]["content"].strip()
        raw = re.sub(r"^```(?:json)?", "", raw).strip()
        raw = re.sub(r"```$", "", raw).strip()
        actions = json.loads(raw)
        if isinstance(actions, list):
            return actions[:2]
    except Exception as e:
        logger.warning(f"SLM action planning failed: {e}")

    return []


# ── Main LangGraph node ───────────────────────────────────────────────────────

def executor_node(state: PipelineState) -> PipelineState:
    """
    LangGraph node for Agent 4 — Executor.

    Input:  state with 'report' populated by Agent 3
    Output: state with 'actions_taken' populated (pipeline complete)
    """
    logger.info("=== Agent 4: Executor starting ===")

    client = Client(host=OLLAMA_HOST)

    # Step 1: Read report from pipeline state or shared memory
    report = state.get("report") or memory.get("report", {})
    if not report or "error" in report:
        logger.error("No report found — did Agent 3 run?")
        return {**state, "actions_taken": []}

    recommendations = report.get("recommendations", [])
    logger.info(f"Processing {len(recommendations)} recommendations")

    # Step 2: Initialize audit trail for this session
    session_start = datetime.now().isoformat()
    write_audit({
        "event":                 "session_start",
        "timestamp":             session_start,
        "report_id":             report.get("report_id"),
        "total_recommendations": len(recommendations),
    })

    # Step 3: Execute actions in priority order
    all_actions          = []
    actions_by_severity  = {"critical": [], "high": [], "medium": [], "low": []}

    for rec in recommendations:
        priority    = rec.get("priority", 99)
        action_text = rec.get("action", "")
        severity    = rec.get("severity", "medium")
        inc_name    = rec.get("for", "unknown")

        # Find the matching incident by attack name
        incident = next(
            (inc for inc in report.get("incidents", [])
             if inc.get("attack_name") == inc_name),
            {}
        )

        logger.info(f"[Priority {priority}] {inc_name} ({severity.upper()})")
        logger.info(f"  Recommendation: {action_text[:80]}")

        # Dispatch primary action
        result              = dispatch_action(action_text, incident)
        result["priority"]  = priority
        result["severity"]  = severity
        result["timestamp"] = datetime.now().isoformat()
        all_actions.append(result)

        write_audit({
            "event":       "action_executed",
            "timestamp":   result["timestamp"],
            "priority":    priority,
            "incident":    inc_name,
            "severity":    severity,
            "action":      result.get("action"),
            "status":      result.get("status"),
            "description": result.get("description"),
        })

        # For critical incidents, also send admin notification
        if severity == "critical":
            notify_result = notify_admin(
                f"{inc_name}: {action_text}",
                severity,
                incident.get("incident_id", "unknown"),
            )
            notify_result["timestamp"] = datetime.now().isoformat()
            all_actions.append(notify_result)
            write_audit({
                "event":     "admin_notified",
                "timestamp": notify_result["timestamp"],
                "incident":  inc_name,
                "severity":  severity,
            })

        actions_by_severity[severity].append(result)
        logger.info(
            f"  ✅ {result.get('status', 'done').upper()}: "
            f"{result.get('description', '')[:60]}"
        )

    # Step 4: SLM additional action planning for critical incidents only
    critical_incidents = [
        inc for inc in report.get("incidents", [])
        if inc.get("threat_level") == "critical"
    ]

    if critical_incidents:
        logger.info(
            f"Planning additional actions for {len(critical_incidents)} critical incidents..."
        )
        for inc in critical_incidents:
            extra_actions = plan_additional_actions(client, inc)
            for action_text in extra_actions:
                logger.info(f"  Additional: {action_text}")
                write_audit({
                    "event":     "additional_action_recommended",
                    "timestamp": datetime.now().isoformat(),
                    "incident":  inc.get("attack_name"),
                    "action":    action_text,
                    "source":    "SLM",
                })

    # Step 5: Write session summary to audit trail
    write_audit({
        "event":         "session_complete",
        "timestamp":     datetime.now().isoformat(),
        "report_id":     report.get("report_id"),
        "total_actions": len(all_actions),
        "simulated":     sum(1 for a in all_actions if a.get("status") == "simulated"),
        "executed":      sum(1 for a in all_actions if a.get("status") == "executed"),
        "flagged":       sum(1 for a in all_actions if a.get("status") == "flagged"),
    })

    # Step 6: Save actions to timestamped JSON file
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    actions_file = get_actions_file()
    with open(actions_file, "w", encoding="utf-8") as f:
        json.dump({
            "report_id":     report.get("report_id"),
            "executed_at":   session_start,
            "total_actions": len(all_actions),
            "actions":       all_actions,
        }, f, indent=2)

    # Step 7: Write to shared memory
    memory.set("actions_taken", all_actions)
    memory.set("executor_status", "done")

    # Step 8: Print execution summary
    simulated = sum(1 for a in all_actions if a.get("status") == "simulated")
    executed  = sum(1 for a in all_actions if a.get("status") == "executed")
    flagged   = sum(1 for a in all_actions if a.get("status") == "flagged")

    logger.info("=== Executor done ===")
    logger.info(f"  Total actions  : {len(all_actions)}")
    logger.info(f"  Simulated      : {simulated}")
    logger.info(f"  Executed (real): {executed}")
    logger.info(f"  Flagged manual : {flagged}")
    logger.info(f"  Audit trail    : {AUDIT_FILE}")
    logger.info(f"  Actions JSON   : {actions_file}")

    return {
        **state,
        "actions_taken": all_actions,
    }


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from agents.extractor import extractor_node
    from agents.analyzer  import analyzer_node
    from agents.reporter  import reporter_node

    initial: PipelineState = {
        "raw_lines": [], "extracted_events": [],
        "analysis_result": {}, "report": {}, "actions_taken": [],
    }

    print("Running full pipeline...")
    s1 = extractor_node(initial)
    s2 = analyzer_node(s1)
    s3 = reporter_node(s2)
    s4 = executor_node(s3)

    print(f"\n✅ Actions taken: {len(s4['actions_taken'])}")