"""
rag/mitre_loader.py
-------------------
Loads a curated set of MITRE ATT&CK technique descriptions into ChromaDB.

How RAG works in this project:
  1. This loader runs ONCE at startup and fills ChromaDB with technique descriptions.
  2. When the Analyzer agent sees suspicious events, it queries ChromaDB:
       "find me the techniques most similar to these events"
  3. ChromaDB returns the closest matches (by vector similarity).
  4. Those matches are injected into the SLM prompt as context.
  5. The SLM can now name specific ATT&CK techniques it would otherwise not know.

This is the "R" and "A" in RAG:
  - Retrieval  → ChromaDB finds relevant technique descriptions
  - Augmented  → those descriptions are added to the prompt
  - Generation → the SLM generates its analysis using that context
"""

import logging
import chromadb
from chromadb.config import Settings

logger = logging.getLogger(__name__)

# ── Curated MITRE ATT&CK techniques relevant to SOC log analysis ─────────────
# Each entry: technique ID, name, and a description written in log-observable terms
# so ChromaDB can match them to real log events via semantic similarity.

MITRE_TECHNIQUES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "description": (
            "Adversaries attempt to gain access by systematically trying many passwords. "
            "Observable in logs as repeated failed authentication attempts (Failed password, "
            "Invalid user) from the same source IP, often targeting SSH port 22, RDP port 3389, "
            "or web login endpoints. A successful login after many failures is a strong indicator."
        ),
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery / Port Scanning",
        "description": (
            "Adversaries probe a network to discover which services are running. "
            "Observable as firewall BLOCK entries for multiple different destination ports "
            "(22, 23, 80, 139, 445, 3389) from the same source IP in rapid succession. "
            "UFW BLOCK, iptables DROP, or IDS alerts for port scan signatures."
        ),
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": (
            "Adversaries exploit vulnerabilities in internet-facing applications. "
            "Observable as mod_security alerts, WAF blocks, HTTP 403 or 400 errors with "
            "patterns like SQL injection (union select, 1=1, drop table), "
            "command injection, or path traversal in web server logs."
        ),
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": (
            "Adversaries use scripting interpreters to execute commands. "
            "Observable as audit logs showing execve calls for shells (sh, bash, python) "
            "from unexpected parent processes, especially web server processes (httpd_t context). "
            "Execution from /tmp or hidden directories is highly suspicious."
        ),
    },
    {
        "id": "T1014",
        "name": "Rootkit",
        "description": (
            "Adversaries use rootkits to hide their presence on a compromised system. "
            "Observable as SELinux/auditd AVC denials for execve from hidden directories "
            "like /tmp/.hidden, unusual kernel module loads, or processes with names "
            "masquerading as system processes."
        ),
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol / C2 Communication",
        "description": (
            "Adversaries communicate with compromised systems using standard protocols "
            "to blend in with normal traffic. Observable as DNS queries to known malicious "
            "domains, connections to unusual external IPs on standard ports, or "
            "DNS resolver logs showing 'query denied' for suspicious domains."
        ),
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "description": (
            "Adversaries flood a target with traffic to deny legitimate access. "
            "Observable as kernel SYN flood warnings, connection table exhaustion, "
            "unusually high traffic volume from many source IPs, or ICMP flood entries "
            "in firewall logs."
        ),
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism / Privilege Escalation",
        "description": (
            "Adversaries attempt to gain higher-level permissions. "
            "Observable as sudo commands run by unexpected users, SELinux AVC denials "
            "for write access to sensitive files like /etc/passwd, su attempts, "
            "or processes running as root that should not be."
        ),
    },
    {
        "id": "T1078",
        "name": "Valid Accounts / Credential Use",
        "description": (
            "Adversaries use legitimate credentials to authenticate, often after stealing them. "
            "Observable as successful logins following brute force attempts, logins at "
            "unusual hours, logins from new geographic locations, or use of service accounts "
            "for interactive sessions."
        ),
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "description": (
            "Adversaries create accounts to maintain persistent access. "
            "Observable as useradd or adduser commands in audit logs, new entries in "
            "/etc/passwd, or new user sessions appearing for accounts that did not "
            "previously have login activity."
        ),
    },
]


def get_chroma_client(host: str = "soc-chroma", port: int = 8000):
    return chromadb.HttpClient(host=host, port=port)


def load_mitre_knowledge_base(chroma_host: str = "soc-chroma") -> chromadb.Collection:
    """
    Load MITRE ATT&CK techniques into ChromaDB and return the collection.

    This function is idempotent — safe to call multiple times.
    ChromaDB uses 'get_or_create_collection' so it won't duplicate entries
    if the collection already exists from a previous run.

    Returns the collection object so the Analyzer can query it directly.
    """
    logger.info("Connecting to ChromaDB...")
    client = get_chroma_client(host=chroma_host)

    # get_or_create means this is safe to call on every startup
    collection = client.get_or_create_collection(
        name="mitre_attack",
        metadata={"description": "MITRE ATT&CK technique descriptions for SOC RAG"},
    )

    # Check if already populated — avoid re-inserting on every startup
    existing_count = collection.count()
    if existing_count >= len(MITRE_TECHNIQUES):
        logger.info(f"ChromaDB already has {existing_count} techniques — skipping load")
        return collection

    logger.info(f"Loading {len(MITRE_TECHNIQUES)} MITRE ATT&CK techniques into ChromaDB...")

    # ChromaDB expects parallel lists: ids, documents, metadatas
    ids       = [t["id"] for t in MITRE_TECHNIQUES]
    documents = [t["description"] for t in MITRE_TECHNIQUES]  # these get embedded
    metadatas = [{"name": t["name"], "id": t["id"]} for t in MITRE_TECHNIQUES]

    # upsert = insert or update — safe if some entries already exist
    collection.upsert(
        ids=ids,
        documents=documents,
        metadatas=metadatas,
    )

    logger.info(f"✅ ChromaDB loaded — {collection.count()} techniques ready for retrieval")
    return collection


def query_techniques(collection: chromadb.Collection, query_text: str, n_results: int = 3) -> list[dict]:
    """
    Find the MITRE ATT&CK techniques most semantically similar to the query text.

    ChromaDB converts the query_text to a vector embedding and finds the
    nearest technique descriptions by cosine similarity. This is the
    Retrieval step of RAG.

    Args:
        collection:  the ChromaDB collection (returned by load_mitre_knowledge_base)
        query_text:  a description of what we observed (e.g. event summaries)
        n_results:   how many techniques to return

    Returns:
        list of dicts with keys: id, name, description, relevance_score
    """
    results = collection.query(
        query_texts=[query_text],
        n_results=min(n_results, collection.count()),
    )

    techniques = []
    for i, doc in enumerate(results["documents"][0]):
        techniques.append({
            "id":          results["metadatas"][0][i]["id"],
            "name":        results["metadatas"][0][i]["name"],
            "description": doc,
            # distance → similarity: lower distance = more similar
            "relevance":   round(1 - results["distances"][0][i], 3),
        })

    return techniques