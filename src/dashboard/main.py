import glob
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(HERE, "index.html")
OUTPUT_DIR = os.path.abspath(os.path.join(HERE, "..", "output"))
AUDIT_FILE = os.path.join(OUTPUT_DIR, "audit_trail.log")

app = FastAPI(title="SOC Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_latest_actions_file() -> str:
    pattern = os.path.join(OUTPUT_DIR, "actions_taken_*.json")
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError("No actions_taken_*.json files found.")
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
