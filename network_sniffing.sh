#!/bin/bash
# network_sniffing.sh - NIST SP 800-115 Section 3.5 (Network Sniffing)
# Passive capture with tcpdump; optional tshark analysis. Non-intrusive (no injection).
# Filters noisy protocols to keep captures useful. Requires root.

set -euo pipefail
INTERFACE="${1:-eth0}"
DURATION="${2:-60}"  # seconds
OUTPUT_DIR="sniff_$(date +%Y%m%d_%H%M%S)"
CAPTURE_FILE="$OUTPUT_DIR/capture.pcap"

if [[ -z "$1" ]]; then
  echo "Usage: $0 <interface> [duration_seconds]"
  echo "  e.g. $0 eth0 120"
  echo "  e.g. $0 ens33 30"
  echo ""
  echo "Available interfaces:"
  ip -o link show | awk '{print $2}' | tr -d ':'
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Error: tcpdump packet capture requires root."
  exit 1
fi

# Validate interface exists
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
  echo "Error: Interface '$INTERFACE' not found."
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
echo "=== NIST SP 800-115 Network Sniffing (Section 3.5) ===" | tee "$OUTPUT_DIR/sniff.log"
echo "Interface: $INTERFACE  Duration: ${DURATION}s" | tee -a "$OUTPUT_DIR/sniff.log"
echo "Start: $(date)" | tee -a "$OUTPUT_DIR/sniff.log"
echo "Capturing passively (no injection). Filtering: TCP/UDP, excluding noise (DNS, ARP, ICMP)." | tee -a "$OUTPUT_DIR/sniff.log"

# Passive capture
# Filter: TCP/UDP only, skip ARP/ICMP/DNS(53) to reduce noise
timeout "${DURATION}" tcpdump -i "$INTERFACE" -w "$CAPTURE_FILE" -s 0 \
  'not (port 53 or icmp or arp) and (tcp or udp)' 2>> "$OUTPUT_DIR/sniff.log" || true

CAPTURE_SIZE=$(du -h "$CAPTURE_FILE" 2>/dev/null | cut -f1 || echo "0")
echo "Capture saved: $CAPTURE_FILE ($CAPTURE_SIZE)" | tee -a "$OUTPUT_DIR/sniff.log"

# tshark analysis if available
if command -v tshark >/dev/null 2>&1; then
  echo "" | tee -a "$OUTPUT_DIR/sniff.log"
  echo "=== Protocol Distribution ===" | tee -a "$OUTPUT_DIR/sniff.log"
  tshark -r "$CAPTURE_FILE" -T fields -e _ws.col.Protocol 2>/dev/null \
    | sort | uniq -c | sort -nr | head -15 | tee -a "$OUTPUT_DIR/sniff.log" || true

  echo "" | tee -a "$OUTPUT_DIR/sniff.log"
  echo "=== Top Conversations (src -> dst) ===" | tee -a "$OUTPUT_DIR/sniff.log"
  tshark -r "$CAPTURE_FILE" -T fields -e ip.src -e ip.dst 2>/dev/null \
    | sort | uniq -c | sort -nr | head -15 | tee -a "$OUTPUT_DIR/sniff.log" || true

  echo "" | tee -a "$OUTPUT_DIR/sniff.log"
  echo "=== Cleartext Sensitive Protocols (HTTP, FTP, Telnet) ===" | tee -a "$OUTPUT_DIR/sniff.log"
  tshark -r "$CAPTURE_FILE" -Y "http or ftp or telnet" \
    -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null \
    | head -30 | tee -a "$OUTPUT_DIR/sniff.log" || echo "  (none found)" | tee -a "$OUTPUT_DIR/sniff.log"
else
  echo "tshark not installed. Install: sudo apt install tshark" | tee -a "$OUTPUT_DIR/sniff.log"
  echo "Open $CAPTURE_FILE in Wireshark for analysis." | tee -a "$OUTPUT_DIR/sniff.log"
fi

echo "" | tee -a "$OUTPUT_DIR/sniff.log"
echo "Sniffing complete. Results in $OUTPUT_DIR/" | tee -a "$OUTPUT_DIR/sniff.log"
echo "NIST notes:"
echo "  - Look for cleartext credentials (HTTP Basic, FTP, Telnet)."
echo "  - Flag unauthorized protocols (e.g., Telnet, rsh, unencrypted SNMP v1/v2)."
echo "  - Correlate with discovery scans to identify unknown hosts."
