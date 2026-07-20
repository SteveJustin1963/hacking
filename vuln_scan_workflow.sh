#!/bin/bash
# vuln_scan_workflow.sh - NIST SP 800-115 Section 4.3 (Vulnerability Scanning)
# Full workflow: discovery → port scan → NSE vuln scan → optional nuclei.
# Safe options throughout; rate-limited. Requires root for SYN scan.

set -euo pipefail
TARGET="${1:-}"
OUTPUT_DIR="vuln_workflow_$(date +%Y%m%d_%H%M%S)"
HOSTS_FILE=""

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target CIDR or IP>"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
HOSTS_FILE="$OUTPUT_DIR/live_hosts.gnmap"

echo "=== NIST SP 800-115 Vulnerability Scanning Workflow ===" | tee "$OUTPUT_DIR/workflow.log"
echo "Target: $TARGET" | tee -a "$OUTPUT_DIR/workflow.log"

# Step 1: Discovery
echo "Step 1/4: Network Discovery..." | tee -a "$OUTPUT_DIR/workflow.log"
nmap -sn -T2 "$TARGET" -oG "$HOSTS_FILE"

LIVE_IPS="$OUTPUT_DIR/live_ips.txt"
grep "Status: Up" "$HOSTS_FILE" | awk '{print $2}' > "$LIVE_IPS" || true

if [[ ! -s "$LIVE_IPS" ]]; then
  echo "No live hosts found. Exiting." | tee -a "$OUTPUT_DIR/workflow.log"
  exit 0
fi
echo "Live hosts: $(wc -l < "$LIVE_IPS")" | tee -a "$OUTPUT_DIR/workflow.log"

# Step 2: Port/Service ID + Version
echo "Step 2/4: Port & Service Identification..." | tee -a "$OUTPUT_DIR/workflow.log"
nmap -sV -O -T3 --max-rate 400 \
     -iL "$LIVE_IPS" \
     -oX "$OUTPUT_DIR/services.xml" \
     -oN "$OUTPUT_DIR/services.txt"

# Step 3: Vulnerability Scan via NSE
echo "Step 3/4: Vulnerability Scanning (NSE safe+vuln scripts)..." | tee -a "$OUTPUT_DIR/workflow.log"
nmap --script "vuln,safe" -sV -T3 --max-rate 200 \
     -iL "$LIVE_IPS" \
     -oN "$OUTPUT_DIR/vuln_nmap.txt" \
     -oX "$OUTPUT_DIR/vuln_nmap.xml"

# Step 4: Optional nuclei (modern lightweight vuln scanner)
if command -v nuclei >/dev/null 2>&1; then
  echo "Step 4/4: Running nuclei (critical/high severity)..." | tee -a "$OUTPUT_DIR/workflow.log"
  nuclei -l "$LIVE_IPS" -severity critical,high -o "$OUTPUT_DIR/nuclei_findings.txt"
else
  echo "Step 4/4: nuclei not found, skipping." | tee -a "$OUTPUT_DIR/workflow.log"
fi

echo "Workflow complete. Findings in $OUTPUT_DIR/" | tee -a "$OUTPUT_DIR/workflow.log"
echo "Per NIST: Validate findings; correlate with log review; prioritize by risk."
