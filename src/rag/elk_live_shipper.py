"""
rag/elk_live_shipper.py
-----------------------
Runs as a sidecar alongside the victim container.
Tails the victim's live log files and ships new lines to Elasticsearch
in real time — so Kibana shows the attack traffic as it happens.

This is the "Logstash replacement" for the sandbox:
  victim container generates logs
       ↓
  this script tails them (via shared volume)
       ↓
  Elasticsearch indexes them instantly
       ↓
  Kibana shows live attack activity
       ↓
  Extractor can also query ES (ELK_MODE=true) instead of reading the file

Run automatically as part of the sandbox+elk combined profile:
  docker compose --profile sandbox --profile elk up -d

Or manually:
  docker exec soc-app python src/rag/elk_live_shipper.py
"""

import os
import sys
import time
import json
import re
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ELK_SHIPPER] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

ES_HOST   = os.getenv("ES_HOST",   "http://soc-elasticsearch:9200")
ES_INDEX  = os.getenv("ES_INDEX",  "soc-logs-live")   # separate index from sample data
POLL_INTERVAL = float(os.getenv("SHIP_INTERVAL", "3"))  # seconds between tail polls

# Victim log files — mounted read-only from the victim container volume
VICTIM_LOGS = [
    "/victim-logs/auth.log",
    "/victim-logs/nginx/access.log",
    "/victim-logs/nginx/error.log",
]


def wait_for_elasticsearch(retries: int = 20, delay: float = 5.0) -> bool:
    for i in range(retries):
        try:
            r = httpx.get(f"{ES_HOST}/_cluster/health", timeout=5.0)
            if r.status_code == 200:
                logger.info(f"Elasticsearch ready — {r.json().get('status')}")
                return True
        except Exception:
            pass
        logger.info(f"Waiting for Elasticsearch... ({i+1}/{retries})")
        time.sleep(delay)
    return False


def ensure_index() -> None:
    """Create the live index if it doesn't exist."""
    r = httpx.head(f"{ES_HOST}/{ES_INDEX}", timeout=5.0)
    if r.status_code == 404:
        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "message":    {"type": "text"},
                    "original":   {"type": "keyword"},
                    "log_level":  {"type": "keyword"},
                    "log_file":   {"type": "keyword"},
                    "source":     {"type": "keyword"},
                }
            }
        }
        httpx.put(f"{ES_HOST}/{ES_INDEX}", json=mapping, timeout=10.0)
        logger.info(f"Created index '{ES_INDEX}'")
    else:
        logger.info(f"Index '{ES_INDEX}' already exists")


def parse_line(line: str, source_file: str) -> dict:
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "original":   line,
        "message":    line,
        "log_level":  "INFO",
        "log_file":   Path(source_file).name,
        "source":     "soc-victim-sandbox",
    }
    ts_match = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
    if ts_match:
        try:
            raw = ts_match.group(1).replace(" ", "T")
            dt = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
            doc["@timestamp"] = dt.isoformat()
        except ValueError:
            pass
    level_match = re.search(r"\b(INFO|WARNING|ERROR|CRITICAL|WARN|ERROR)\b", line, re.IGNORECASE)
    if level_match:
        doc["log_level"] = level_match.group(1).upper()
    return doc


def ship_line(line: str, source_file: str) -> bool:
    doc = parse_line(line, source_file)
    try:
        r = httpx.post(
            f"{ES_HOST}/{ES_INDEX}/_doc",
            json=doc,
            timeout=5.0,
        )
        return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"Ship failed: {e}")
        return False


def tail_files() -> None:
    """
    Continuously tail all victim log files and ship new lines to Elasticsearch.
    Tracks file position per file so it only ships genuinely new lines.
    """
    positions: dict[str, int] = {}

    # Initialize positions to current end of each file so we only ship
    # new lines that arrive after the shipper starts
    for path in VICTIM_LOGS:
        if os.path.exists(path):
            positions[path] = os.path.getsize(path)
            logger.info(f"Watching {path} from position {positions[path]}")
        else:
            positions[path] = 0

    shipped_total = 0
    logger.info(f"Shipping new lines to {ES_HOST}/{ES_INDEX} every {POLL_INTERVAL}s")

    while True:
        for path in VICTIM_LOGS:
            if not os.path.exists(path):
                continue
            try:
                current_size = os.path.getsize(path)
                if current_size < positions.get(path, 0):
                    # File was rotated — reset position
                    positions[path] = 0

                if current_size > positions.get(path, 0):
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(positions[path])
                        new_lines = f.readlines()
                    positions[path] = current_size

                    for line in new_lines:
                        line = line.strip()
                        if line:
                            if ship_line(line, path):
                                shipped_total += 1

                    if new_lines:
                        logger.info(f"Shipped {len(new_lines)} new lines from {Path(path).name} (total: {shipped_total})")

            except Exception as e:
                logger.warning(f"Error reading {path}: {e}")

        time.sleep(POLL_INTERVAL)


def main():
    logger.info(f"ELK live shipper starting — ES={ES_HOST}, index={ES_INDEX}")

    if not wait_for_elasticsearch():
        logger.error("Elasticsearch not available — exiting")
        sys.exit(1)

    ensure_index()
    logger.info("Ready — tailing victim logs and shipping to Elasticsearch")
    tail_files()


if __name__ == "__main__":
    main()