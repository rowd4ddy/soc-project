"""
agents/extractor.py
-------------------
Agent 1: Extractor

Responsibilities:
  - Read raw log lines from a log file
  - Pre-filter lines to find potentially relevant events
  - Use the SLM (Qwen via Ollama) to extract structured fields
  - Write clean JSON events into shared memory for Agent 2

This agent is a LangGraph node — it receives the pipeline state,
does its work, and returns an updated state dict.
"""

import os
import re
import json
import glob
import logging
from datetime import datetime
from typing import TypedDict

from ollama import Client

from shared.memory import memory

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EXTRACTOR] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = "qwen2.5:7b"

# ── Log file paths ──────────────────────────────────────────────────────────
DATA_DIR     = os.path.join(os.path.dirname(__file__), "..", "data")
INCOMING_DIR = os.path.join(DATA_DIR, "incoming")
DEFAULT_LOG_FILE = os.path.join(DATA_DIR, "sample_logs.log")

# ── Keywords that flag a line as worth sending to the SLM ──
RELEVANT_KEYWORDS = [
    "failed", "invalid", "denied", "blocked", "error",
    "critical", "warning", "attack", "flood", "rootkit",
    "execve", "union", "select", "drop table", "c2",
]

# ── Severity mapping from log level words ──
SEVERITY_MAP = {
    "critical": "critical",
    "warning":  "medium",
    "error":    "medium",
    "info":     "low",
}


# ── LangGraph state schema ──────────────────────────────────────────────────

class PipelineState(TypedDict):
    """Shared state dict that flows through the LangGraph DAG."""
    raw_lines:        list[str]
    extracted_events: list[dict]
    analysis_result:  dict
    report:           dict
    actions_taken:    list[str]


# ── Helper functions ─────────────────────────────────────────────────────────

def resolve_log_file() -> str:
    """
    Decide which log file to process.

    Drag-and-drop workflow: any .log or .txt file placed in
    src/data/incoming/ is picked up automatically — the newest file wins.
    This lets you swap datasets (e.g. a teacher-provided log file) without
    touching any code: just drop the file into that folder and re-run.

    Falls back to the bundled sample_logs.log if incoming/ is empty.
    """
    os.makedirs(INCOMING_DIR, exist_ok=True)

    candidates = (
        glob.glob(os.path.join(INCOMING_DIR, "*.log"))
        + glob.glob(os.path.join(INCOMING_DIR, "*.txt"))
    )

    if candidates:
        newest = max(candidates, key=os.path.getmtime)
        logger.info(f"Found dropped log file: {newest}")
        return newest

    logger.info("No files in data/incoming/ — using bundled sample_logs.log")
    return DEFAULT_LOG_FILE


def load_log_file(path: str) -> list[str]:
    """Read all lines from the log file, stripping blanks."""
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    logger.info(f"Loaded {len(lines)} log lines from {path}")
    return lines


def pre_filter(lines: list[str]) -> list[str]:
    """
    Cheap keyword filter before sending to the SLM.
    Keeps lines that contain at least one suspicious keyword.
    This saves LLM calls on totally benign INFO lines.
    """
    relevant = []
    for line in lines:
        low = line.lower()
        if any(kw in low for kw in RELEVANT_KEYWORDS):
            relevant.append(line)

    logger.info(f"Pre-filter: {len(relevant)}/{len(lines)} lines flagged as relevant")
    return relevant


def parse_timestamp(line: str) -> str:
    """Extract ISO timestamp from the beginning of a log line."""
    match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    if match:
        try:
            dt = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            pass
    return datetime.now().isoformat()


def parse_log_level(line: str) -> str:
    """Pull the log level (INFO / WARNING / CRITICAL / ERROR) from the line."""
    match = re.search(r"\b(INFO|WARNING|ERROR|CRITICAL)\b", line)
    return match.group(1).upper() if match else "UNKNOWN"


def extract_ips(line: str) -> list[str]:
    """Find all IPv4 addresses in a log line."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)


def build_extraction_prompt(log_line: str) -> str:
    """
    Prompt for the SLM. Instructs it to return only valid JSON.
    We keep the prompt small and explicit so a 7B model handles it reliably.
    """
    return f"""You are a SOC log parser. Extract security-relevant fields from this log line.

Return ONLY a valid JSON object with exactly these fields:
{{
  "event_type": "one of: brute_force | sql_injection | port_scan | malware | dos_attack | privilege_escalation | c2_communication | unauthorized_access | other",
  "source_ip": "IP address string or null",
  "target": "targeted service, port, or resource string or null",
  "severity": "one of: low | medium | high | critical",
  "summary": "one sentence describing what happened"
}}

Log line:
{log_line}

JSON:"""


def call_slm(client: Client, prompt: str) -> dict:
    """
    Send the prompt to Qwen via Ollama and parse the JSON response.
    Falls back to a minimal dict if the model output is not parseable.
    """
    try:
        response = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},   # low temp = more deterministic JSON
        )
        raw = response["message"]["content"].strip()

        # Strip markdown fences if the model wrapped it in ```json ... ```
        raw = re.sub(r"^```(?:json)?", "", raw).strip()
        raw = re.sub(r"```$", "", raw).strip()

        return json.loads(raw)

    except json.JSONDecodeError as e:
        logger.warning(f"SLM returned non-JSON output: {e}")
        return {
            "event_type": "other",
            "source_ip": None,
            "target": None,
            "severity": "low",
            "summary": "Could not parse SLM response.",
        }
    except Exception as e:
        logger.error(f"SLM call failed: {e}")
        return {
            "event_type": "other",
            "source_ip": None,
            "target": None,
            "severity": "low",
            "summary": f"SLM error: {str(e)}",
        }


# ── Main LangGraph node function ─────────────────────────────────────────────

def extractor_node(state: PipelineState) -> PipelineState:
    """
    LangGraph node for Agent 1 — Extractor.

    Input:  state with 'raw_lines' populated (or empty, in which case we load the file)
    Output: state with 'extracted_events' populated
    """
    logger.info("=== Agent 1: Extractor starting ===")

    client = Client(host=OLLAMA_HOST)

    # Step 1: Load logs if not already in state
    raw_lines = state.get("raw_lines") or load_log_file(resolve_log_file())

    # Step 2: Pre-filter to relevant lines only
    relevant_lines = pre_filter(raw_lines)

    # Step 3: For each relevant line, build a structured event
    extracted_events = []

    for i, line in enumerate(relevant_lines):
        logger.info(f"Processing line {i+1}/{len(relevant_lines)} ...")

        # Fast regex pre-parse (no LLM cost)
        timestamp  = parse_timestamp(line)
        log_level  = parse_log_level(line)
        source_ips = extract_ips(line)
        severity_hint = SEVERITY_MAP.get(log_level.lower(), "low")

        # SLM deep extraction
        prompt = build_extraction_prompt(line)
        slm_result = call_slm(client, prompt)

        # Merge regex results with SLM results (regex wins on concrete fields)
        event = {
            "id":         f"evt-{i+1:04d}",
            "timestamp":  timestamp,
            "raw_line":   line,
            "log_level":  log_level,
            "source_ips": source_ips,
            # SLM-extracted fields
            "event_type": slm_result.get("event_type", "other"),
            "source_ip":  slm_result.get("source_ip") or (source_ips[0] if source_ips else None),
            "target":     slm_result.get("target"),
            "severity":   slm_result.get("severity", severity_hint),
            "summary":    slm_result.get("summary", "No summary available."),
        }

        extracted_events.append(event)
        logger.info(f"  → {event['event_type']} | {event['severity']} | {event['summary'][:60]}")

    logger.info(f"=== Extractor done: {len(extracted_events)} events extracted ===")

    # Step 4: Write to shared memory so Agent 2 can read it
    memory.set("extracted_events", extracted_events)
    memory.set("extractor_status", "done")

    # Step 5: Return updated pipeline state
    return {
        **state,
        "raw_lines": raw_lines,
        "extracted_events": extracted_events,
    }


# ── Standalone test (run directly to test without the full pipeline) ─────────

if __name__ == "__main__":
    initial_state: PipelineState = {
        "raw_lines":        [],
        "extracted_events": [],
        "analysis_result":  {},
        "report":           {},
        "actions_taken":    [],
    }

    result = extractor_node(initial_state)

    print("\n── Extracted Events ──────────────────────────")
    for evt in result["extracted_events"]:
        print(f"\n[{evt['id']}] {evt['timestamp']}")
        print(f"  Type    : {evt['event_type']}")
        print(f"  Severity: {evt['severity']}")
        print(f"  Source  : {evt['source_ip']}")
        print(f"  Summary : {evt['summary']}")

    print("\n── Shared Memory Dump ────────────────────────")
    print(memory.dump())