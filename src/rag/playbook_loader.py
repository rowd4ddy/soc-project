"""
rag/playbook_loader.py
----------------------
Loads SOC remediation playbooks into ChromaDB for RAG retrieval by Agent 3.

Each playbook describes:
  - What the attack is
  - Immediate containment steps
  - Investigation steps
  - Long-term hardening recommendations

When Agent 3 generates a report for a confirmed attack, it queries this
collection to retrieve the correct playbook and injects it into the SLM
prompt. This ensures recommendations are grounded in real procedures,
not just the model guessing.

Same RAG pattern as mitre_loader.py — this is the second knowledge base.
"""

import logging
import chromadb

logger = logging.getLogger(__name__)

# ── SOC Remediation Playbooks ─────────────────────────────────────────────────
# Each entry maps to one or more MITRE ATT&CK technique IDs.
# Written as step-by-step procedures an analyst would actually follow.

PLAYBOOKS = [
    {
        "id":   "playbook-brute-force",
        "tags": "T1110 brute force ssh rdp login failed password",
        "title": "Brute Force Attack Response",
        "content": (
            "IMMEDIATE: Block the source IP at the firewall using iptables or UFW. "
            "Command: iptables -A INPUT -s <SOURCE_IP> -j DROP. "
            "INVESTIGATE: Check if any login succeeded after the failed attempts. "
            "Run: grep 'Accepted' /var/log/auth.log | grep <SOURCE_IP>. "
            "If successful login found, treat as compromised account — disable immediately. "
            "HARDEN: Enable fail2ban to auto-block IPs after N failed attempts. "
            "Enforce MFA on all SSH and RDP access. Disable root SSH login in sshd_config. "
            "NOTIFY: Alert the security team if root account was targeted."
        ),
    },
    {
        "id":   "playbook-port-scan",
        "tags": "T1046 port scan network discovery UFW BLOCK firewall",
        "title": "Port Scan / Network Discovery Response",
        "content": (
            "IMMEDIATE: Block the scanning IP at the perimeter firewall. "
            "Document all ports probed — this reveals attacker's target services. "
            "INVESTIGATE: Correlate the scanning IP with other log sources. "
            "Check if the scanner subsequently attempted exploitation of discovered ports. "
            "Cross-reference IP against threat intelligence feeds. "
            "HARDEN: Close all non-essential ports. Implement port knocking for SSH. "
            "Enable IDS signatures for port scan patterns (nmap, masscan). "
            "NOTIFY: Flag the IP for monitoring across all systems."
        ),
    },
    {
        "id":   "playbook-sql-injection",
        "tags": "T1190 sql injection web application union select drop table mod_security WAF",
        "title": "SQL Injection Attempt Response",
        "content": (
            "IMMEDIATE: Verify WAF/mod_security blocks are active and the requests were denied. "
            "If any request returned 200 OK instead of 403, treat as potential breach. "
            "INVESTIGATE: Review full web server access logs for the attacking IP. "
            "Check database logs for any unexpected queries or schema changes. "
            "Dump and review all recent database transactions. "
            "HARDEN: Ensure all database queries use parameterized statements. "
            "Update WAF ruleset to latest version. Enable rate limiting on web endpoints. "
            "NOTIFY: If data may have been accessed, initiate data breach response protocol."
        ),
    },
    {
        "id":   "playbook-malware-rootkit",
        "tags": "T1014 T1059 rootkit malware execve hidden tmp SELinux AVC denied",
        "title": "Malware / Rootkit Detection Response",
        "content": (
            "IMMEDIATE: ISOLATE the affected machine from the network immediately. "
            "Do not attempt to clean in place — assume full compromise. "
            "Command: ifconfig eth0 down OR disconnect the network cable. "
            "INVESTIGATE: Take a memory dump before shutdown for forensic analysis. "
            "Identify the malware path (/tmp/.hidden or similar) and hash the file. "
            "Check persistence mechanisms: crontab, systemd services, ~/.bashrc, /etc/rc.local. "
            "Review all processes that were spawned by web server (httpd_t context). "
            "REMEDIATE: Restore from last known-good backup. "
            "Rebuild the system if no clean backup is available. "
            "NOTIFY: This is a critical incident — escalate to incident response team immediately."
        ),
    },
    {
        "id":   "playbook-c2-communication",
        "tags": "T1071 C2 command control DNS query malicious domain evil",
        "title": "C2 Communication Detection Response",
        "content": (
            "IMMEDIATE: Block the malicious domain at the DNS resolver and firewall. "
            "Add domain to DNS blacklist/sinkhole. "
            "INVESTIGATE: Identify which internal host made the DNS query. "
            "Check that host for malware, unauthorized processes, and outbound connections. "
            "Review all DNS queries from that host for other suspicious domains. "
            "Check firewall logs for any successful outbound connections to the C2 IP. "
            "HARDEN: Implement DNS filtering (Pi-hole, Cisco Umbrella). "
            "Block outbound connections to non-whitelisted destinations. "
            "NOTIFY: C2 communication implies an active compromise — escalate immediately."
        ),
    },
    {
        "id":   "playbook-dos-syn-flood",
        "tags": "T1498 SYN flood denial of service DoS DDoS port 80 kernel cookies",
        "title": "Denial of Service / SYN Flood Response",
        "content": (
            "IMMEDIATE: Enable SYN cookies if not already active: "
            "sysctl -w net.ipv4.tcp_syncookies=1. "
            "Rate-limit incoming SYN packets: iptables -A INPUT -p tcp --syn -m limit "
            "--limit 1/s --limit-burst 3 -j ACCEPT. "
            "INVESTIGATE: Identify if attack is from single IP (DoS) or multiple (DDoS). "
            "For single source: block the IP immediately. "
            "For distributed: contact upstream ISP for traffic scrubbing. "
            "HARDEN: Deploy a CDN or DDoS mitigation service (Cloudflare, AWS Shield). "
            "Tune kernel TCP parameters for better SYN flood resilience. "
            "NOTIFY: Alert infrastructure team — service availability may be impacted."
        ),
    },
    {
        "id":   "playbook-privilege-escalation",
        "tags": "T1548 T1078 privilege escalation root sudo passwd unauthorized access valid accounts",
        "title": "Privilege Escalation Response",
        "content": (
            "IMMEDIATE: If unauthorized root access confirmed, lock the account: "
            "passwd -l root. Revoke any active sessions: pkill -u root. "
            "INVESTIGATE: Review sudo logs and auth.log for all privilege escalation events. "
            "Check for new accounts created, SSH keys added, or crontabs modified. "
            "Review /etc/sudoers and /etc/passwd for unauthorized changes. "
            "Audit all files modified in the last 24 hours: find / -mtime -1 -type f. "
            "HARDEN: Apply principle of least privilege — remove unnecessary sudo rights. "
            "Enable auditd rules for privilege escalation monitoring. "
            "NOTIFY: Escalate to incident response — assume lateral movement may have occurred."
        ),
    },
]


def load_playbook_knowledge_base(chroma_host: str = "soc-chroma") -> chromadb.Collection:
    """
    Load SOC remediation playbooks into ChromaDB.
    Uses a separate collection from MITRE ATT&CK so the two knowledge bases
    don't interfere with each other.

    Returns the collection for querying.
    """
    client = chromadb.HttpClient(host=chroma_host, port=8000)

    collection = client.get_or_create_collection(
        name="soc_playbooks",
        metadata={"description": "SOC remediation playbooks for incident response"},
    )

    existing = collection.count()
    if existing >= len(PLAYBOOKS):
        logger.info(f"Playbook collection already has {existing} entries — skipping load")
        return collection

    logger.info(f"Loading {len(PLAYBOOKS)} remediation playbooks into ChromaDB...")

    # ChromaDB embeds the 'tags' field for semantic search
    # because tags contain the key terms the Analyzer output will match against
    collection.upsert(
        ids       = [p["id"] for p in PLAYBOOKS],
        documents = [p["tags"] for p in PLAYBOOKS],   # embedded for similarity search
        metadatas = [{"title": p["title"], "content": p["content"]} for p in PLAYBOOKS],
    )

    logger.info(f"✅ Playbooks loaded — {collection.count()} playbooks ready")
    return collection


def query_playbook(collection: chromadb.Collection, query_text: str) -> dict | None:
    """
    Find the most relevant remediation playbook for a given incident description.

    Args:
        collection:  the ChromaDB playbook collection
        query_text:  description of the incident (e.g. attack name + MITRE ID)

    Returns:
        dict with 'title' and 'content', or None if nothing relevant found
    """
    results = collection.query(
        query_texts=[query_text],
        n_results=1,
    )

    if not results["metadatas"][0]:
        return None

    meta = results["metadatas"][0][0]
    return {
        "title":   meta["title"],
        "content": meta["content"],
    }