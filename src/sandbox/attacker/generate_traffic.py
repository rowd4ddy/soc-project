"""
attacker/generate_traffic.py
----------------------------
Runs inside soc-attacker. Generates realistic attack traffic against
soc-victim so the SOC pipeline has real log entries to detect.

All attacks are harmless and contained to the sandbox network.
"""

import os
import random
import subprocess
import time
from datetime import datetime

VICTIM_HOST   = os.getenv("VICTIM_HOST", "soc-victim")
SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", "90"))


def log(msg: str):
    print(f"[{datetime.now().isoformat(timespec='seconds')}] [attacker] {msg}", flush=True)


def ssh_brute_force():
    """
    Failed SSH logins — generates 'Failed password' / 'Invalid user' entries
    in the victim's auth.log. Uses ssh directly with a bad password via
    StrictHostKeyChecking=no and BatchMode=no so PAM logs the failure.
    """
    log("running SSH brute force pattern...")
    users = ["root", "admin", "test", "guest", "oracle", "ubuntu"]
    for _ in range(random.randint(5, 9)):
        user = random.choice(users)
        # ssh with wrong password — will fail but sshd logs the attempt
        subprocess.run([
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=3",
            "-o", "BatchMode=no",
            "-o", "PasswordAuthentication=yes",
            "-o", "PreferredAuthentications=password",
            "-p", "22",
            f"{user}@{VICTIM_HOST}",
            "exit"
        ], input=b"wrongpassword\n",
           stdout=subprocess.DEVNULL,
           stderr=subprocess.DEVNULL,
           timeout=5)
        time.sleep(0.8)
    log("SSH brute force done")


def sql_injection_attempt():
    """
    SQL injection GET requests — payloads appear in nginx access.log
    using curl with --path-as-is so special characters aren't stripped.
    """
    log("running SQL injection pattern...")
    payloads = [
        "/index.php?id=1'+OR+'1'='1",
        "/search?q=1+UNION+SELECT+username,password+FROM+users--",
        "/login?user=admin'--",
        "/page?id=1;+DROP+TABLE+users;--",
        "/api?query='+OR+1=1+--",
    ]
    for payload in payloads:
        subprocess.run([
            "curl", "-s", "-o", "/dev/null",
            "--path-as-is",
            "-A", "sqlmap/1.7",
            f"http://{VICTIM_HOST}{payload}"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        time.sleep(0.3)
    log("SQL injection done")


def port_scan():
    """Nmap scan — generates connection attempts across multiple ports."""
    log("running port scan pattern...")
    subprocess.run([
        "nmap", "-Pn", "--open",
        "-p", "21,22,23,25,80,443,445,3306,3389,8080",
        VICTIM_HOST
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    log("port scan done")


def connection_burst():
    """Rapid connection attempts — simulates DoS/flood behavior."""
    log("running connection burst pattern...")
    for _ in range(20):
        subprocess.run([
            "curl", "-s", "-o", "/dev/null",
            "--max-time", "1",
            "--connect-timeout", "1",
            f"http://{VICTIM_HOST}/"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log("connection burst done")


def directory_traversal():
    """
    Path traversal attempts — generates 404/403 entries in nginx error/access log.
    The 404 keyword is caught by the pre-filter.
    """
    log("running directory traversal pattern...")
    paths = [
        "/../../../etc/passwd",
        "/.env",
        "/admin/config.php",
        "/.git/config",
        "/wp-admin/",
        "/phpmyadmin/",
    ]
    for path in paths:
        subprocess.run([
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}",
            f"http://{VICTIM_HOST}{path}"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        time.sleep(0.2)
    log("directory traversal done")


ATTACK_PATTERNS = [
    ssh_brute_force,
    sql_injection_attempt,
    port_scan,
    connection_burst,
    directory_traversal,
]


def main():
    log(f"attack generator starting — target={VICTIM_HOST}, interval={SLEEP_SECONDS}s")
    log("waiting 15s for victim services to come up...")
    time.sleep(15)

    while True:
        pattern = random.choice(ATTACK_PATTERNS)
        try:
            pattern()
        except Exception as e:
            log(f"pattern failed (non-fatal): {e}")
        log(f"sleeping {SLEEP_SECONDS}s until next pattern...")
        time.sleep(SLEEP_SECONDS)


if __name__ == "__main__":
    main()