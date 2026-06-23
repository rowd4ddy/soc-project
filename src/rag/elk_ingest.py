"""
rag/elk_ingest.py
-----------------
One-time ingestion script: reads sample_logs.log (or a drag-and-drop file
from src/data/incoming/) and bulk-inserts every line into Elasticsearch
as individual log documents.

Run once after starting the ELK stack:
    docker exec soc-app python src/rag/elk_ingest.py

Re-running is safe — it deletes and recreates the index each time so you
always get a clean slate (useful for testing different datasets).

The Extractor queries this index when ELK_MODE=true:
    docker exec -e ELK_MODE=true soc-app python src/main.py --run
"""

import os
import sys
import json
import glob
import logging
from datetime import datetime, timezone

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ELK_INGEST] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

ES_HOST  = os.getenv("ES_HOST",  "http://soc-elasticsearch:9200")
ES_INDEX = os.getenv("ES_INDEX", "soc-logs")

DATA_DIR     = os.path.join(os.path.dirname(__file__), "..", "data")
INCOMING_DIR = os.path.join(DATA_DIR, "incoming")
DEFAULT_LOG  = os.path.join(DATA_DIR, "sample_logs.log")


def resolve_log_file() -> str:
    """Same drag-and-drop logic as the Extractor."""
    candidates = (
        glob.glob(os.path.join(INCOMING_DIR, "*.log")) +
        glob.glob(os.path.join(INCOMING_DIR, "*.txt"))
    )
    if candidates:
        newest = max(candidates, key=os.path.getmtime)
        logger.info(f"Using dropped file: {newest}")
        return newest
    logger.info("No files in incoming/ — using sample_logs.log")
    return DEFAULT_LOG


def wait_for_elasticsearch(retries: int = 12, delay: float = 5.0) -> bool:
    """Poll until Elasticsearch is ready (it takes ~20-30s to start)."""
    import time
    for i in range(retries):
        try:
            r = httpx.get(f"{ES_HOST}/_cluster/health", timeout=5.0)
            if r.status_code == 200:
                status = r.json().get("status", "unknown")
                logger.info(f"Elasticsearch ready — cluster status: {status}")
                return True
        except Exception:
            pass
        logger.info(f"Waiting for Elasticsearch... ({i+1}/{retries})")
        time.sleep(delay)
    return False


def recreate_index() -> None:
    """Delete and recreate the index with a simple mapping."""
    # Delete existing index (ignore 404)
    httpx.delete(f"{ES_HOST}/{ES_INDEX}", timeout=10.0)

    # Create with explicit mapping so @timestamp sorts correctly
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "message":    {"type": "text"},
                "original":   {"type": "keyword"},   # raw log line, unanalyzed
                "log_level":  {"type": "keyword"},
                "source":     {"type": "keyword"},
            }
        }
    }
    r = httpx.put(f"{ES_HOST}/{ES_INDEX}", json=mapping, timeout=10.0)
    r.raise_for_status()
    logger.info(f"Index '{ES_INDEX}' created")


def parse_log_line(line: str) -> dict:
    """
    Extract basic fields from a log line for the ES document.
    The 'original' field preserves the raw line exactly — this is what
    read_from_elasticsearch() in extractor.py reads back.
    """
    import re
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "original":   line,
        "message":    line,
        "log_level":  "UNKNOWN",
        "source":     "soc-logs",
    }

    # Extract timestamp if present (2024-01-15 08:03:45)
    ts_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    if ts_match:
        try:
            dt = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
            doc["@timestamp"] = dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass

    # Extract log level
    level_match = re.search(r"\b(INFO|WARNING|ERROR|CRITICAL)\b", line)
    if level_match:
        doc["log_level"] = level_match.group(1)

    return doc


def bulk_ingest(lines: list[str]) -> int:
    """
    Bulk-insert log lines into Elasticsearch using the _bulk API.
    Returns the number of documents successfully indexed.
    """
    if not lines:
        logger.warning("No lines to ingest")
        return 0

    # Build NDJSON bulk payload
    bulk_body = ""
    for line in lines:
        doc = parse_log_line(line)
        bulk_body += json.dumps({"index": {"_index": ES_INDEX}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"

    r = httpx.post(
        f"{ES_HOST}/_bulk",
        content=bulk_body,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=30.0,
    )
    r.raise_for_status()

    result = r.json()
    errors = [item for item in result.get("items", []) if item.get("index", {}).get("error")]
    indexed = len(result.get("items", [])) - len(errors)

    if errors:
        logger.warning(f"{len(errors)} documents failed to index")
    return indexed


def main():
    logger.info(f"Connecting to Elasticsearch at {ES_HOST}")

    if not wait_for_elasticsearch():
        logger.error("Elasticsearch not available after retries — is soc-elasticsearch running?")
        sys.exit(1)

    log_file = resolve_log_file()
    with open(log_file, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    logger.info(f"Loaded {len(lines)} lines from {log_file}")

    recreate_index()
    indexed = bulk_ingest(lines)
    logger.info(f"✅ Ingested {indexed}/{len(lines)} documents into '{ES_INDEX}'")
    logger.info(f"Run the pipeline with: docker exec -e ELK_MODE=true soc-app python src/main.py --run")


if __name__ == "__main__":
    main()