#!/bin/bash
# wireless_scan.sh - NIST SP 800-115 Section 4.4 (Wireless Scanning - Passive)
# Passive monitoring with airodump-ng. Identifies APs, clients, encryption types.
# Requires monitor mode interface. Use: sudo airmon-ng start wlan0 first.
# IMPORTANT: Only use on networks you are authorized to test.

set -euo pipefail
INTERFACE="${1:-wlan0mon}"
DURATION="${2:-30}"  # seconds to scan
CHANNEL="${3:-}"     # optional specific channel number
OUTPUT_DIR="wireless_$(date +%Y%m%d_%H%M%S)"

if [[ -z "$1" ]]; then
  echo "Usage: $0 <monitor_interface> [duration_seconds] [channel]"
  echo "  e.g. $0 wlan0mon 60"
  echo "  e.g. $0 wlan0mon 30 6"
  echo ""
  echo "Setup: sudo airmon-ng start wlan0"
  exit 1
fi

# Check interface exists
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
  echo "Error: Interface '$INTERFACE' not found."
  echo "Available interfaces:"
  ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | tr -d ':'
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
echo "=== NIST SP 800-115 Wireless Scanning (Passive) ===" | tee "$OUTPUT_DIR/wireless.log"
echo "Interface: $INTERFACE  Duration: ${DURATION}s" | tee -a "$OUTPUT_DIR/wireless.log"
echo "Start: $(date)" | tee -a "$OUTPUT_DIR/wireless.log"

# Build airodump-ng arguments conditionally
AIRODUMP_ARGS=(
  --output-format csv,cap
  --write "$OUTPUT_DIR/wireless_scan"
)

# Only add --channel if a specific channel was given
if [[ -n "$CHANNEL" ]]; then
  AIRODUMP_ARGS+=(--channel "$CHANNEL")
fi

AIRODUMP_ARGS+=("$INTERFACE")

echo "Running airodump-ng for ${DURATION}s..." | tee -a "$OUTPUT_DIR/wireless.log"
timeout "${DURATION}" airodump-ng "${AIRODUMP_ARGS[@]}" 2>&1 | tee -a "$OUTPUT_DIR/airodump_raw.log" || true

echo "Scan complete." | tee -a "$OUTPUT_DIR/wireless.log"

# Summarize CSV if it exists
CSV_FILE=$(ls "$OUTPUT_DIR"/wireless_scan-*.csv 2>/dev/null | head -1 || true)
if [[ -n "$CSV_FILE" && -s "$CSV_FILE" ]]; then
  echo "" | tee -a "$OUTPUT_DIR/wireless.log"
  echo "=== Access Points Found ===" | tee -a "$OUTPUT_DIR/wireless.log"
  # CSV format: BSSID,First time,Last time,channel,Speed,Privacy,Cipher,Authentication,Power,#beacons,#IV,LAN IP,ID-length,ESSID,Key
  awk -F',' 'NR>2 && $14 ~ /[^[:space:]]/ {printf "BSSID: %-20s Chan: %-4s Enc: %-8s ESSID: %s\n", $1,$4,$6,$14}' "$CSV_FILE" | tee -a "$OUTPUT_DIR/wireless.log" || true
fi

echo "" | tee -a "$OUTPUT_DIR/wireless.log"
echo "Output files in $OUTPUT_DIR/"
echo "PCAP capture: $OUTPUT_DIR/wireless_scan-*.cap  (open in Wireshark)"
echo "CSV summary:  $OUTPUT_DIR/wireless_scan-*.csv"
echo ""
echo "NIST notes:"
echo "  - Flag APs with WEP encryption (insecure)."
echo "  - Flag open (no encryption) APs."
echo "  - Look for rogue APs (unexpected SSIDs or duplicate SSIDs with different BSSIDs)."
echo "  - For WPA handshake capture: airodump-ng --bssid <AP_MAC> -c <channel> -w handshake <iface>"
echo "  - To crack WPA handshake: aircrack-ng handshake.cap -w wordlist.txt"
