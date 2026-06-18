"""
main.py
-------
Entry point for the SOC multi-agent pipeline.

Currently wired up:
  - Agent 1: Extractor  ✅
  - Agent 2: Analyzer   ✅

Coming soon:
  - Agent 3: Reporter
  - Agent 4: Executor
"""

import os
import sys
import time
import logging
from langgraph.graph import StateGraph, END

from agents.extractor import extractor_node, PipelineState
from agents.analyzer  import analyzer_node
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
    Add nodes here as each agent is completed.
    """
    graph = StateGraph(PipelineState)

    # ── Nodes ──────────────────────────────────────────
    graph.add_node("extractor", extractor_node)
    graph.add_node("analyzer",  analyzer_node)
    # graph.add_node("reporter", reporter_node)   ← Week 3
    # graph.add_node("executor", executor_node)   ← Week 3

    # ── Edges (DAG flow) ───────────────────────────────
    graph.set_entry_point("extractor")
    graph.add_edge("extractor", "analyzer")     # Agent 1 → Agent 2
    graph.add_edge("analyzer",  END)
    # graph.add_edge("analyzer",  "reporter")   ← uncomment when Reporter ready
    # graph.add_edge("reporter",  "executor")
    # graph.add_edge("executor",  END)

    return graph.compile()


def run_pipeline():
    """Run the full agent pipeline once and print a summary."""
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

    # ── Print final summary ────────────────────────────
    analysis = result.get("analysis_result", {})
    logger.info("════════════════════════════════════════")
    logger.info(f"  PIPELINE COMPLETE")
    logger.info(f"  Overall threat : {analysis.get('overall_threat_level', 'unknown').upper()}")
    logger.info(f"  Incidents found: {analysis.get('total_incidents', 0)}")
    logger.info(f"  Confirmed attacks: {analysis.get('confirmed_attacks', 0)}")
    logger.info("════════════════════════════════════════")

    for inc in analysis.get("incidents", []):
        if inc.get("confirmed_attack"):
            logger.info(
                f"  ⚠  {inc.get('attack_name')} | "
                f"{inc.get('mitre_technique_id')} | "
                f"threat={inc.get('threat_level')} | "
                f"src={inc.get('source_ip')}"
            )


def main():
    """
    Long-running entry point.
    Pass --run to execute the pipeline.
    Without --run the container just stays alive for VS Code attachment.
    """
    if "--run" in sys.argv:
        try:
            run_pipeline()
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
        logger.info("Pipeline finished. Container staying alive.")
    else:
        logger.info("SOC container ready. Run with --run to start the pipeline.")

    # Keep container alive without burning CPU
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()