"""
main.py
-------
Entry point for the SOC multi-agent pipeline.

Currently wired up:
  - Agent 1: Extractor  ✅

Coming soon:
  - Agent 2: Analyzer
  - Agent 3: Reporter
  - Agent 4: Executor

The pipeline runs once on startup, then waits.
This replaces the old one-shot health check and stops Docker's restart loop.
"""

import os
import time
import logging
from langgraph.graph import StateGraph, END

from agents.extractor import extractor_node, PipelineState
from shared.memory import memory

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MAIN] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def build_pipeline() -> StateGraph:
    """
    Build the LangGraph DAG.
    Right now it only has the Extractor node.
    We will add Analyzer, Reporter, Executor here in the coming days.
    """
    graph = StateGraph(PipelineState)

    # Add nodes (one per agent)
    graph.add_node("extractor", extractor_node)
    # graph.add_node("analyzer", analyzer_node)   ← Week 2
    # graph.add_node("reporter", reporter_node)   ← Week 3
    # graph.add_node("executor", executor_node)   ← Week 3

    # Define edges (the DAG flow)
    graph.set_entry_point("extractor")
    graph.add_edge("extractor", END)
    # graph.add_edge("extractor", "analyzer")     ← uncomment when Analyzer is ready
    # graph.add_edge("analyzer",  "reporter")
    # graph.add_edge("reporter",  "executor")
    # graph.add_edge("executor",  END)

    return graph.compile()


def run_pipeline():
    """Run the full agent pipeline once and log the result."""
    logger.info("════════════════════════════════════════")
    logger.info("  SOC Multi-Agent Pipeline starting     ")
    logger.info("════════════════════════════════════════")

    pipeline = build_pipeline()

    initial_state: PipelineState = {
        "raw_lines":        [],
        "extracted_events": [],
        "analysis_result":  {},
        "report":           {},
        "actions_taken":    [],
    }

    result = pipeline.invoke(initial_state)

    events = result.get("extracted_events", [])
    logger.info(f"Pipeline complete — {len(events)} events extracted")

    # Quick severity summary
    severities = {}
    for e in events:
        s = e.get("severity", "unknown")
        severities[s] = severities.get(s, 0) + 1

    logger.info(f"Severity breakdown: {severities}")
    logger.info("Shared memory written — ready for Agent 2 (Analyzer)")


def main():
    """
    Keeps the container alive permanently.
    Run the pipeline manually with:
        docker exec soc-app python src/main.py --run
    """
    import sys
    if "--run" in sys.argv:
        run_pipeline()
        logger.info("Pipeline finished. Container staying alive.")
    else:
        logger.info("SOC container ready. Waiting for instructions...")

    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()