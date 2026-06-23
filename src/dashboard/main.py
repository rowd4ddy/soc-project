import glob
import json
import os
import sys
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Allow importing the rag/ package shared with the main pipeline — the
# dashboard container mounts the same ./src folder, so src/rag is a sibling
# of src/dashboard at runtime.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from rag.feedback_loader import get_feedback_collection, add_feedback
    FEEDBACK_ENABLED = True
except ImportError:
    FEEDBACK_ENABLED = False
    def get_feedback_collection(**kwargs): return None
    def add_feedback(**kwargs): return {}

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(HERE, "index.html")
OUTPUT_DIR = os.path.abspath(os.path.join(HERE, "..", "output"))
AUDIT_FILE = os.path.join(OUTPUT_DIR, "audit_trail.log")
CHROMA_HOST = os.getenv("CHROMA_HOST", "soc-chroma")

app = FastAPI(title="SOC Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FeedbackRequest(BaseModel):
    incident_id: str
    combined_summary: str
    attack_name: str
    mitre_technique_id: str
    verdict: str  # "true_positive" or "false_positive"
    analyst_note: Optional[str] = ""


def get_latest_actions_file() -> str:
    pattern = os.path.join(OUTPUT_DIR, "actions_taken_*.json")
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError("No actions_taken_*.json files found.")
    return max(files, key=os.path.getmtime)


def get_latest_report_file() -> str:
    pattern = os.path.join(OUTPUT_DIR, "report_*.json")
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError("No report_*.json files found.")
    return max(files, key=os.path.getmtime)


def summarize_actions(actions: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    simulated = 0
    executed = 0
    flagged = 0

    for action in actions:
        status = str(action.get("status", "")).lower()
        if status == "simulated":
            simulated += 1
        elif status == "executed":
            executed += 1
        elif status == "flagged":
            flagged += 1

        severity = str(action.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1

    return {"simulated": simulated, "executed": executed, "flagged": flagged, **counts}


@app.get("/")
async def root() -> FileResponse:
    if not os.path.exists(INDEX_FILE):
        raise HTTPException(status_code=404, detail="Dashboard file not found")
    return FileResponse(INDEX_FILE, media_type="text/html")


@app.get("/api/summary")
async def api_summary() -> dict[str, Any]:
    try:
        actions_file = get_latest_actions_file()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    with open(actions_file, "r", encoding="utf-8") as file:
        payload = json.load(file)

    actions = payload.get("actions", [])
    metrics = summarize_actions(actions)
    total_actions = payload.get("total_actions", len(actions))

    return {
        "total_actions": total_actions,
        "simulated": metrics["simulated"],
        "executed": metrics["executed"],
        "flagged": metrics["flagged"],
        "critical": metrics["critical"],
        "high": metrics["high"],
        "medium": metrics["medium"],
        "low": metrics["low"],
        "actions": actions,
    }


@app.get("/api/audit")
async def api_audit() -> list[dict[str, Any]]:
    if not os.path.exists(AUDIT_FILE):
        return []

    with open(AUDIT_FILE, "r", encoding="utf-8") as file:
        lines = [line.strip() for line in file if line.strip()]

    lines = lines[-50:]
    entries: list[dict[str, Any]] = []

    for line in reversed(lines):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"raw": line})

    return entries


@app.get("/api/report")
async def api_report() -> dict[str, Any]:
    """
    Returns the full latest incident report: executive summary, attack
    timeline, per-incident narratives with MITRE mapping, statistics,
    and prioritized recommendations. Produced by Agent 3 (Reporter).
    """
    try:
        report_file = get_latest_report_file()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    with open(report_file, "r", encoding="utf-8") as file:
        return json.load(file)


@app.post("/api/feedback")
async def api_submit_feedback(body: FeedbackRequest) -> dict[str, Any]:
    if not FEEDBACK_ENABLED:
        raise HTTPException(status_code=503, detail="Adaptive learning not available — check feedback_loader.py")
    if body.verdict not in ("true_positive", "false_positive"):
        raise HTTPException(status_code=400, detail="verdict must be 'true_positive' or 'false_positive'")
    try:
        collection = get_feedback_collection(chroma_host=CHROMA_HOST)
        result = add_feedback(
            collection=collection,
            incident_id=body.incident_id,
            combined_summary=body.combined_summary,
            attack_name=body.attack_name,
            mitre_technique_id=body.mitre_technique_id,
            verdict=body.verdict,
            analyst_note=body.analyst_note or "",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store feedback: {exc}")
    return {"status": "stored", **result}


@app.get("/api/feedback/count")
async def api_feedback_count() -> dict[str, int]:
    if not FEEDBACK_ENABLED:
        return {"count": 0}
    try:
        collection = get_feedback_collection(chroma_host=CHROMA_HOST)
        return {"count": collection.count()}
    except Exception:
        return {"count": 0}


@app.delete("/api/clear")
async def api_clear_output() -> dict[str, Any]:
    """
    Delete all generated pipeline output files from src/output/ so the
    dashboard shows a clean slate before the next demo run.

    This only touches files in src/output/ — it does NOT affect:
      - ChromaDB data (MITRE, playbooks, analyst_feedback collections)
      - The pipeline code or configuration
      - Any Docker volumes

    Safe to call at any time; the pipeline regenerates everything on the
    next run. Exists specifically so the demo starts from a visually
    clean state without needing to manually delete files.
    """
    patterns = [
        "report_*.json",
        "incident_report_*.txt",
        "actions_taken_*.json",
        "audit_trail.log",
        "admin_notifications.txt",
    ]
    deleted = []
    for pattern in patterns:
        for path in glob.glob(os.path.join(OUTPUT_DIR, pattern)):
            try:
                os.remove(path)
                deleted.append(os.path.basename(path))
            except OSError:
                pass
    return {"status": "cleared", "deleted": deleted, "count": len(deleted)}