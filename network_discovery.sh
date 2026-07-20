#!/bin/bash
# network_discovery.sh - Based on NIST SP 800-115 Section 4.1 (Network Discovery)
# Performs safe active discovery of live hosts. Uses rate-limited scans.
# Avoids aggressive options that could trigger IDS or cause DoS.
# Output: live_hosts.txt, discovery_report.txt, XML for further parsing.

set -euo pipefail
IFS=$'\n\t'

TARGET="${1:-}"
OUTPUT_DIR="discovery_$(date +%Y%m%d_%H%M%S)"
USAGE="Usage: $0 <target CIDR or IP range>  (e.g. 192.168.1.0/24 or 10.0.0.1-50)"

if [[ -z "$TARGET" ]] || [[ "$TARGET" == "-h" ]]; then
  echo "$USAGE"
  echo "NIST-aligned: Safe ping sweep combining ICMP, TCP, and ARP probes."
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
LOG="$OUTPUT_DIR/discovery.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== NIST SP 800-115 Network Discovery ==="
echo "Target: $TARGET"
echo "Start: $(date)"
echo "Output directory: $OUTPUT_DIR"
echo "WARNING: Ensure you have explicit authorization before scanning."

# Safe active discovery (ICMP echo + TCP probes, rate limited)
echo "Running safe host discovery (nmap -sn with safe timing)..."
nmap -sn -PE -PP -PS22,80,443 --reason -T2 --max-rate 1000 \
     -oN "$OUTPUT_DIR/live_hosts.txt" \
     -oX "$OUTPUT_DIR/live_hosts.xml" "$TARGET"

HOSTS_FOUND=$(grep -c "Nmap scan report" "$OUTPUT_DIR/live_hosts.txt" || echo 0)
echo "Hosts discovered: $HOSTS_FOUND"

# Generate report
{
  echo "=== Discovery Report ==="
  echo "NIST SP 800-115 Section 4.1 - Network Discovery"
  echo "Target: $TARGET"
  echo "Date: $(date)"
  echo "Hosts Found: $HOSTS_FOUND"
  echo ""
  cat "$OUTPUT_DIR/live_hosts.txt"
} > "$OUTPUT_DIR/discovery_report.txt"

echo "Discovery complete. Review $OUTPUT_DIR/discovery_report.txt"
echo "Next step per NIST: Proceed to port/service identification on live hosts."
