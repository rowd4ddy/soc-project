"""
main.py
-------
Entry point for the SOC multi-agent pipeline.

Currently wired up:
  - Agent 1: Extractor  ✅
  - Agent 2: Analyzer   ✅
  - Agent 3: Reporter   ✅

Coming soon:
  - Agent 4: Executor
"""

import os
import sys
import time
import logging
from langgraph.graph import StateGraph, END

from agents.extractor import extractor_node, PipelineState
from agents.analyzer  import analyzer_node
from agents.reporter  import reporter_node
from shared.memory    import memory

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MAIN] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def build_pipeline():
    graph = StateGraph(PipelineState)

    graph.add_node("extractor", extractor_node)
    graph.add_node("analyzer",  analyzer_node)
    graph.add_node("reporter",  reporter_node)
    # graph.add_node("executor", executor_node)  ← next

    graph.set_entry_point("extractor")
    graph.add_edge("extractor", "analyzer")
    graph.add_edge("analyzer",  "reporter")
    graph.add_edge("reporter",  END)
    # graph.add_edge("reporter", "executor")   ← uncomment when Executor ready
    # graph.add_edge("executor", END)

    return graph.compile()


def run_pipeline():
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

    # ── Summary ───────────────────────────────────────
    analysis = result.get("analysis_result", {})
    report   = result.get("report", {})

    logger.info("════════════════════════════════════════")
    logger.info("  PIPELINE COMPLETE")
    logger.info(f"  Overall threat   : {analysis.get('overall_threat_level', 'unknown').upper()}")
    logger.info(f"  Confirmed attacks: {analysis.get('confirmed_attacks', 0)}")
    logger.info(f"  Report ID        : {report.get('report_id', 'N/A')}")
    logger.info(f"  Report saved to  : src/output/incident_report.txt")
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
    if "--run" in sys.argv:
        try:
            run_pipeline()
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
        logger.info("Pipeline finished. Container staying alive.")
    else:
        logger.info("SOC container ready. Run with --run to start the pipeline.")

    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()