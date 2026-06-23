"""
rag/feedback_loader.py
-----------------------
Adaptive learning extension (pawn-test).

Stores analyst feedback (true positive / false positive verdicts on
confirmed incidents) in its own ChromaDB collection, and lets the
Analyzer query it the same way it already queries the MITRE ATT&CK
collection in rag/mitre_loader.py.

How this differs from mitre_loader.py:
  - MITRE techniques are a fixed, pre-curated list loaded once at startup.
  - Analyst feedback starts EMPTY and grows one entry at a time, every
    time an analyst marks an incident via the dashboard. There is no
    bulk load step — only add_feedback() (called per-verdict) and
    query_feedback() (called per-incident during analysis).

How it plugs into the existing pipeline:
  1. Dashboard POSTs a verdict for a confirmed incident (see dashboard
     wiring in main.py) -> add_feedback() embeds and stores it here.
  2. On the NEXT Analyzer run, query_feedback() is called alongside the
     existing query_techniques() call in analyzer.py, using the same
     incident['combined_summary'] text already used for the MITRE query.
  3. If a semantically similar past incident was marked a false positive,
     that context is injected into the SLM analysis prompt, directly
     influencing the returned confidence/threat_level — the model is
     told "a similar event was previously reviewed and marked X."

This is the same Retrieval-Augmented-Generation pattern already proven
twice in this codebase (MITRE technique collection, playbook collection)
— same ChromaDB client, same get_or_create_collection / query shape.
"""

import logging
from datetime import datetime, timezone

import chromadb

logger = logging.getLogger(__name__)

COLLECTION_NAME = "analyst_feedback"
VALID_VERDICTS = {"true_positive", "false_positive"}


def get_chroma_client(host: str = "soc-chroma", port: int = 8000) -> chromadb.HttpClient:
    """Connect to the ChromaDB container. Same client pattern as mitre_loader.py."""
    return chromadb.HttpClient(host=host, port=port)


def get_feedback_collection(chroma_host: str = "soc-chroma") -> chromadb.Collection:
    """
    Return the analyst_feedback collection, creating it if it doesn't exist yet.

    Unlike load_mitre_knowledge_base(), this does NOT bulk-load anything —
    the collection starts empty and is populated incrementally via
    add_feedback() as analysts review incidents over time.

    Idempotent and safe to call on every pipeline run, same as the
    MITRE and playbook loaders.
    """
    client = get_chroma_client(host=chroma_host)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"description": "Analyst true/false-positive verdicts on past incidents, used to inform future Analyzer confidence"},
    )
    return collection


def add_feedback(
    collection: chromadb.Collection,
    incident_id: str,
    combined_summary: str,
    attack_name: str,
    mitre_technique_id: str,
    verdict: str,
    analyst_note: str = "",
) -> dict:
    """
    Store one analyst verdict on a confirmed incident.

    Args:
        collection:          the analyst_feedback collection (from get_feedback_collection)
        incident_id:         the original incident's ID, for traceability
        combined_summary:    the same text used for the original MITRE RAG query —
                              this is what future incidents get semantically compared against
        attack_name:         the attack name the Analyzer originally assigned
        mitre_technique_id:  the MITRE technique ID originally assigned
        verdict:             "true_positive" or "false_positive"
        analyst_note:        optional free-text reason from the analyst

    Returns the stored record as a dict (for logging / dashboard confirmation).
    """
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"verdict must be one of {VALID_VERDICTS}, got: {verdict!r}")

    # Use a unique, sortable ID so repeated feedback on the same incident_id
    # (e.g. corrected later) doesn't silently overwrite the earlier entry.
    timestamp = datetime.now(timezone.utc).isoformat()
    feedback_id = f"fb-{incident_id}-{int(datetime.now(timezone.utc).timestamp())}"

    metadata = {
        "incident_id":        incident_id,
        "attack_name":        attack_name,
        "mitre_technique_id": mitre_technique_id,
        "verdict":            verdict,
        "analyst_note":       analyst_note,
        "timestamp":          timestamp,
    }

    collection.upsert(
        ids=[feedback_id],
        documents=[combined_summary],   # embedded for future semantic queries
        metadatas=[metadata],
    )

    logger.info(f"Stored analyst feedback: {incident_id} -> {verdict} ({attack_name})")
    return {"feedback_id": feedback_id, **metadata}


def query_feedback(collection: chromadb.Collection, query_text: str, n_results: int = 2) -> list[dict]:
    """
    Find past analyst feedback semantically similar to a new incident's summary.

    Mirrors query_techniques() in mitre_loader.py exactly — same call shape,
    same relevance-score calculation — so analyzer.py can call both in the
    same way and merge their results into one prompt.

    Returns an empty list (not an error) if the collection has no entries
    yet, which is the expected state until the first analyst verdict is
    submitted via the dashboard.
    """
    if collection.count() == 0:
        return []

    results = collection.query(
        query_texts=[query_text],
        n_results=min(n_results, collection.count()),
    )

    feedback = []
    for i, doc in enumerate(results["documents"][0]):
        meta = results["metadatas"][0][i]
        feedback.append({
            "incident_id":        meta.get("incident_id"),
            "attack_name":        meta.get("attack_name"),
            "mitre_technique_id": meta.get("mitre_technique_id"),
            "verdict":            meta.get("verdict"),
            "analyst_note":       meta.get("analyst_note", ""),
            "relevance":          round(1 - results["distances"][0][i], 3),
        })

    return feedback