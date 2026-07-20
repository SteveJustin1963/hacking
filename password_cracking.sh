#!/bin/bash
# password_cracking.sh - NIST SP 800-115 Section 5.1 (Password Cracking)
# Handles common hash types using John the Ripper and Hashcat.
# John auto-detects format; Hashcat requires explicit mode (-m). See usage notes.
# Non-destructive (read-only on hash files).

set -euo pipefail
HASHFILE="${1:-}"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"
HASHCAT_MODE="${3:-}"  # e.g. 0=MD5, 1000=NTLM, 1800=sha512crypt, 500=md5crypt
OUTPUT_DIR="password_crack_$(date +%Y%m%d_%H%M%S)"

USAGE="Usage: $0 <hashfile> [wordlist] [hashcat_mode]
  Common hashcat modes:
    0     = MD5
    100   = SHA-1
    1000  = NTLM
    1800  = sha512crypt (Linux shadow \$6\$)
    500   = md5crypt   (Linux shadow \$1\$)
    1500  = DES (crypt)
    3200  = bcrypt
  Example: $0 hashes.txt /usr/share/wordlists/rockyou.txt 1000"

if [[ -z "$HASHFILE" ]]; then
  echo "$USAGE"
  exit 1
fi

if [[ ! -f "$HASHFILE" ]]; then
  echo "Error: Hash file not found: $HASHFILE"
  exit 1
fi

if [[ ! -f "$WORDLIST" ]]; then
  echo "Warning: Wordlist not found: $WORDLIST"
  echo "Install with: sudo apt install wordlists && gunzip /usr/share/wordlists/rockyou.txt.gz"
fi

mkdir -p "$OUTPUT_DIR"
echo "=== NIST SP 800-115 Password Cracking (Section 5.1) ===" | tee "$OUTPUT_DIR/cracking.log"
echo "Hash file: $HASHFILE" | tee -a "$OUTPUT_DIR/cracking.log"
echo "Wordlist:  $WORDLIST" | tee -a "$OUTPUT_DIR/cracking.log"

# --- John the Ripper (CPU-based, auto-detects hash format) ---
if command -v john >/dev/null 2>&1; then
  echo "Running John the Ripper (wordlist + best64 rules, auto format detection)..." | tee -a "$OUTPUT_DIR/cracking.log"
  # No --format flag: John auto-detects. Add --format=<type> to override.
  john --wordlist="$WORDLIST" --rules=best64 "$HASHFILE" 2>&1 | tee -a "$OUTPUT_DIR/john.log"
  john --show "$HASHFILE" > "$OUTPUT_DIR/john_cracked.txt"
  echo "John cracked: $(wc -l < "$OUTPUT_DIR/john_cracked.txt") password(s)" | tee -a "$OUTPUT_DIR/cracking.log"
else
  echo "john not found. Install: sudo apt install john" | tee -a "$OUTPUT_DIR/cracking.log"
fi

# --- Hashcat (GPU-accelerated) ---
if command -v hashcat >/dev/null 2>&1; then
  if [[ -z "$HASHCAT_MODE" ]]; then
    echo "Skipping hashcat: no mode specified. Provide mode as 3rd argument." | tee -a "$OUTPUT_DIR/cracking.log"
    echo "Run: $0 $HASHFILE $WORDLIST <mode>" | tee -a "$OUTPUT_DIR/cracking.log"
  else
    echo "Running Hashcat (mode $HASHCAT_MODE, wordlist + best64 rules)..." | tee -a "$OUTPUT_DIR/cracking.log"
    hashcat -m "$HASHCAT_MODE" -a 0 \
            "$HASHFILE" "$WORDLIST" \
            -r /usr/share/hashcat/rules/best64.rule \
            --outfile "$OUTPUT_DIR/hashcat_cracked.txt" 2>&1 | tee -a "$OUTPUT_DIR/hashcat.log"
    echo "Hashcat cracked: $(wc -l < "$OUTPUT_DIR/hashcat_cracked.txt" 2>/dev/null || echo 0) password(s)" | tee -a "$OUTPUT_DIR/cracking.log"
  fi
else
  echo "hashcat not found. Install: sudo apt install hashcat" | tee -a "$OUTPUT_DIR/cracking.log"
fi

echo "Done. Results in $OUTPUT_DIR/"
echo "NIST recommendation: Enforce strong password policy (min length 12+, complexity, no reuse)."
