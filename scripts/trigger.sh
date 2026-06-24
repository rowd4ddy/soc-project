#!/bin/bash
# trigger.sh — fire a specific attack pattern on demand during a demo.
#
# Usage:
#   ./scripts/trigger.sh brute_force
#   ./scripts/trigger.sh sqli
#   ./scripts/trigger.sh port_scan
#   ./scripts/trigger.sh burst
#   ./scripts/trigger.sh traversal

PATTERN=$1

case "$PATTERN" in
  brute_force)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.ssh_brute_force()"
    ;;
  sqli)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.sql_injection_attempt()"
    ;;
  port_scan)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.port_scan()"
    ;;
  burst)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.connection_burst()"
    ;;
  traversal)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.directory_traversal()"
    ;;
  *)
    echo "Usage: ./scripts/trigger.sh [brute_force|sqli|port_scan|burst|traversal]"
    exit 1
    ;;
esac

echo ""
echo "Attack triggered: $PATTERN"
echo "Now run the pipeline in live mode:"
echo "  docker exec -e LIVE_MODE=true -e EXECUTOR_LIVE_MODE=true soc-app python src/main.py --run"

#   "Watch — I'm going to run a brute force right now, then show you
#    the pipeline detect and respond to it within a minute."
#
# Usage (from your Windows host, via PowerShell):
#   docker exec soc-attacker python3 -c "import generate_traffic as g; g.ssh_brute_force()"
#   docker exec soc-attacker python3 -c "import generate_traffic as g; g.port_scan()"
#   docker exec soc-attacker python3 -c "import generate_traffic as g; g.sql_injection_attempt()"
#   docker exec soc-attacker python3 -c "import generate_traffic as g; g.syn_burst()"
#
# Or simply run this script with a pattern name as the argument:
#   ./trigger.sh brute_force
#   ./trigger.sh port_scan
#   ./trigger.sh sqli
#   ./trigger.sh burst

PATTERN=$1

case "$PATTERN" in
  brute_force)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.ssh_brute_force()"
    ;;
  port_scan)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.port_scan()"
    ;;
  sqli)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.sql_injection_attempt()"
    ;;
  burst)
    docker exec soc-attacker python3 -c "import generate_traffic as g; g.syn_burst()"
    ;;
  *)
    echo "Usage: ./trigger.sh [brute_force|port_scan|sqli|burst]"
    exit 1
    ;;
esac

echo "Triggered: $PATTERN"
echo "Run the pipeline now to see it detected:"
echo "  docker exec soc-app-live python src/main.py --run"