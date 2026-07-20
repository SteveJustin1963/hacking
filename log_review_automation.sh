#!/bin/bash
# log_review_automation.sh - NIST SP 800-115 Section 3.2 (Log Review)
# Automates parsing of auth, syslog, firewall logs for anomalies, failed logins, etc.
# Works on Debian/Ubuntu (auth.log) and RHEL/CentOS (secure). Extend paths as needed.

set -euo pipefail
LOG_DIR="${1:-/var/log}"
OUTPUT_DIR="log_review_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

REPORT="$OUTPUT_DIR/summary_report.txt"
{
  echo "=== NIST SP 800-115 Log Review Automation (Section 3.2) ==="
  echo "Log directory: $LOG_DIR"
  echo "Date: $(date)"
  echo ""
} > "$REPORT"

# Detect auth log path (Debian/Ubuntu vs RHEL/CentOS)
AUTH_LOG=""
for candidate in "$LOG_DIR/auth.log" "$LOG_DIR/secure"; do
  if ls "${candidate}"* > /dev/null 2>&1; then
    AUTH_LOG="$candidate"
    break
  fi
done

# --- Authentication failures ---
echo "=== Authentication Failures ===" >> "$REPORT"
if [[ -n "$AUTH_LOG" ]]; then
  grep -hE "Failed password|authentication failure|Invalid user" "${AUTH_LOG}"* 2>/dev/null \
    | tail -100 > "$OUTPUT_DIR/failed_logins.txt" || true
  COUNT=$(wc -l < "$OUTPUT_DIR/failed_logins.txt")
  echo "Failed login events (last 100): $COUNT" >> "$REPORT"

  echo "" >> "$REPORT"
  echo "Top source IPs for failed logins:" >> "$REPORT"
  grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$OUTPUT_DIR/failed_logins.txt" 2>/dev/null \
    | awk '{print $2}' | sort | uniq -c | sort -nr | head -10 >> "$REPORT" || echo "  (none)" >> "$REPORT"
else
  echo "Auth log not found in $LOG_DIR (checked auth.log, secure)" >> "$REPORT"
fi

# --- Successful logins ---
echo "" >> "$REPORT"
echo "=== Successful Logins (last 20) ===" >> "$REPORT"
if [[ -n "$AUTH_LOG" ]]; then
  grep -hE "Accepted (password|publickey)" "${AUTH_LOG}"* 2>/dev/null \
    | tail -20 > "$OUTPUT_DIR/successful_logins.txt" || true
  cat "$OUTPUT_DIR/successful_logins.txt" >> "$REPORT"
fi

# --- Sudo usage ---
echo "" >> "$REPORT"
echo "=== Sudo Usage (last 20) ===" >> "$REPORT"
if [[ -n "$AUTH_LOG" ]]; then
  grep -hE "sudo:" "${AUTH_LOG}"* 2>/dev/null | tail -20 > "$OUTPUT_DIR/sudo_usage.txt" || true
  cat "$OUTPUT_DIR/sudo_usage.txt" >> "$REPORT"
fi

# --- Firewall drops/rejects ---
echo "" >> "$REPORT"
echo "=== Top Firewall Drop Sources ===" >> "$REPORT"
KERN_LOG=""
for candidate in "$LOG_DIR/kern.log" "$LOG_DIR/messages"; do
  if ls "${candidate}"* > /dev/null 2>&1; then
    KERN_LOG="$candidate"
    break
  fi
done
if [[ -n "$KERN_LOG" ]]; then
  grep -hE "DROP|REJECT" "${KERN_LOG}"* 2>/dev/null \
    | grep -oE "SRC=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk -F= '{print $2}' \
    | sort | uniq -c | sort -nr | head -10 >> "$REPORT" || echo "  (none)" >> "$REPORT"
else
  echo "Kernel log not found in $LOG_DIR" >> "$REPORT"
fi

# --- Syslog anomalies (cron, services) ---
echo "" >> "$REPORT"
echo "=== Syslog: Errors and Warnings (last 20) ===" >> "$REPORT"
for syslog in "$LOG_DIR/syslog" "$LOG_DIR/messages"; do
  if ls "${syslog}"* > /dev/null 2>&1; then
    grep -hE "error|WARN|critical|panic" "${syslog}"* 2>/dev/null \
      | grep -viE "gpg|apt|unattended" | tail -20 >> "$OUTPUT_DIR/syslog_errors.txt" || true
    head -20 "$OUTPUT_DIR/syslog_errors.txt" >> "$REPORT" || true
    break
  fi
done

echo "" >> "$REPORT"
echo "=== Log Review Complete ===" >> "$REPORT"
echo "Files in: $OUTPUT_DIR/"

cat "$REPORT"
echo ""
echo "NIST guidance: Correlate findings with vulnerability scan results."
echo "Look for policy violations, repeated failures, unexpected root access."
