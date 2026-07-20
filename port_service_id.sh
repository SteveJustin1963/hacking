#!/bin/bash
# port_service_id.sh - NIST SP 800-115 Section 4.2 (Network Port and Service Identification)
# Comprehensive version detection + safe service enumeration. Uses version scanning (-sV).
# Includes OS fingerprinting. Rate-limited (-T3, --max-rate). Requires root for SYN scan.

set -euo pipefail
TARGET="${1:-}"
PORTS="${2:-1-10000}"
OUTPUT_DIR="portscan_$(date +%Y%m%d_%H%M%S)"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target> [port range]"
  echo "  e.g. $0 192.168.1.1 1-65535"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
LOG="$OUTPUT_DIR/portscan.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== NIST SP 800-115 Port & Service Identification ==="
echo "Target: $TARGET  Ports: $PORTS"
echo "Start: $(date)"

nmap -sS -sV -O -sC --version-intensity 7 -T3 --max-rate 500 --reason \
     -p "$PORTS" \
     -oN "$OUTPUT_DIR/port_service_report.txt" \
     -oX "$OUTPUT_DIR/port_service.xml" "$TARGET"

echo "Results saved to $OUTPUT_DIR/"
echo "Key NIST outputs: open ports, service versions, OS details, NSE script results."
echo "Review for unauthorized services (e.g., telnet on 23, SMBv1 on 445)."
