#!/bin/bash
# os_fingerprint.sh - NIST SP 800-115 Section 4.1/4.2 (OS Fingerprinting)
# Uses nmap's active OS detection with multiple probes. Requires root.

set -euo pipefail
TARGET="${1:-}"
OUTPUT_DIR="os_fingerprint_$(date +%Y%m%d_%H%M%S)"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target IP or range>"
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Warning: OS fingerprinting (-O) requires root privileges."
fi

mkdir -p "$OUTPUT_DIR"

echo "=== NIST SP 800-115 OS Fingerprinting ==="
echo "Target: $TARGET"

nmap -O -sV --osscan-guess -T3 --max-rate 300 \
     -oN "$OUTPUT_DIR/os_fingerprint.txt" \
     -oX "$OUTPUT_DIR/os_fingerprint.xml" "$TARGET"

echo ""
echo "Summary:"
grep -E "OS details|Aggressive OS guesses|Running:" "$OUTPUT_DIR/os_fingerprint.txt" || echo "(No OS details found)"
echo ""
echo "Full report: $OUTPUT_DIR/os_fingerprint.txt"
