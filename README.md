# NIST SP 800-115 Pentest Toolkit

A collection of bash scripts implementing the techniques and methodology defined in
[NIST Special Publication 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
*Technical Guide to Information Security Testing and Assessment* (2008).

> **Authorization required.** These tools perform active scanning, packet capture, and
> credential testing. Only use them against systems you are explicitly authorized to test.

---

## Files

| File | NIST Section | Description |
|------|-------------|-------------|
| `nistspecialpublication800-115.pdf` | — | Source document (methodology reference, no code) |
| `nist.txt` | — | Plain-text notes/excerpts from the PDF |
| `network_discovery.sh` | §4.1 | Live host discovery via rate-limited ICMP/TCP/ARP probes |
| `port_service_id.sh` | §4.2 | SYN scan + version detection + OS fingerprinting on a target |
| `os_fingerprint.sh` | §4.1–4.2 | Focused active OS fingerprinting with nmap `-O` |
| `vuln_scan_workflow.sh` | §4.3 | End-to-end workflow: discovery → ports → NSE vuln scan → nuclei |
| `password_cracking.sh` | §5.1 | Wordlist attacks with John the Ripper and Hashcat |
| `wireless_scan.sh` | §4.4 | Passive wireless monitoring with airodump-ng |
| `log_review_automation.sh` | §3.2 | Auth log, sudo, firewall drop, and syslog anomaly parsing |
| `network_sniffing.sh` | §3.5 | Passive tcpdump capture with optional tshark analysis |
| `chat-log.md` | — | Session history and notes from development |

---

## Script Usage

### `network_discovery.sh`
Ping sweep combining ICMP echo, TCP SYN probes (22, 80, 443), and ARP.
Rate-limited to avoid IDS triggering. Outputs `live_hosts.txt` and XML.

```bash
./network_discovery.sh 192.168.1.0/24
./network_discovery.sh 10.0.0.1-50
```

### `port_service_id.sh`
SYN scan with version detection (`-sV`), OS detection (`-O`), and default NSE scripts.
Requires root. Output: open ports, service versions, NSE results.

```bash
sudo ./port_service_id.sh 192.168.1.5
sudo ./port_service_id.sh 192.168.1.5 1-65535
```

### `os_fingerprint.sh`
Dedicated OS fingerprinting scan using nmap's `-O --osscan-guess`.
Requires root.

```bash
sudo ./os_fingerprint.sh 192.168.1.5
sudo ./os_fingerprint.sh 192.168.1.0/24
```

### `vuln_scan_workflow.sh`
Full four-step pipeline:
1. Host discovery (grepable output)
2. Port/service/OS scan on live hosts
3. NSE `vuln,safe` script scan
4. nuclei (critical/high severity) if installed

Requires root.

```bash
sudo ./vuln_scan_workflow.sh 192.168.1.0/24
```

### `password_cracking.sh`
Runs John the Ripper (auto format detection, best64 rules) and optionally Hashcat
(GPU-accelerated, explicit mode required). Non-destructive — read-only on the hash file.

```bash
./password_cracking.sh hashes.txt
./password_cracking.sh hashes.txt /usr/share/wordlists/rockyou.txt 1000
```

Common Hashcat modes: `0` MD5 · `100` SHA-1 · `1000` NTLM · `1800` sha512crypt · `500` md5crypt · `3200` bcrypt

### `wireless_scan.sh`
Passive airodump-ng scan. Identifies APs, clients, encryption types.
Put the interface into monitor mode first.

```bash
sudo airmon-ng start wlan0
sudo ./wireless_scan.sh wlan0mon 60        # 60-second scan, all channels
sudo ./wireless_scan.sh wlan0mon 30 6      # channel 6 only
```

Flags WEP, open APs, and potential rogue APs. Saves `.cap` for Wireshark.

### `log_review_automation.sh`
Parses system logs for: failed logins (top source IPs), successful logins, sudo usage,
firewall drops, and syslog errors/warnings. Works on Debian/Ubuntu (`auth.log`) and
RHEL/CentOS (`secure`).

```bash
./log_review_automation.sh            # defaults to /var/log
./log_review_automation.sh /var/log
```

### `network_sniffing.sh`
Passive tcpdump capture filtered to TCP/UDP (no ARP/ICMP/DNS noise). Optional tshark
post-processing: protocol distribution, top conversations, cleartext protocol detection
(HTTP, FTP, Telnet). Requires root.

```bash
sudo ./network_sniffing.sh eth0 120
sudo ./network_sniffing.sh ens33 30
```

---

## Dependencies

| Tool | Scripts | Install |
|------|---------|---------|
| `nmap` | discovery, port scan, OS, vuln workflow | `sudo apt install nmap` |
| `nuclei` | vuln workflow (optional) | https://github.com/projectdiscovery/nuclei |
| `john` | password cracking | `sudo apt install john` |
| `hashcat` | password cracking | `sudo apt install hashcat` |
| `aircrack-ng` suite | wireless scan | `sudo apt install aircrack-ng` |
| `tcpdump` | network sniffing | `sudo apt install tcpdump` |
| `tshark` | network sniffing (optional) | `sudo apt install tshark` |

---

## Output

Each script creates a timestamped output directory (e.g., `discovery_20260720_143000/`)
containing raw scan files, parsed summaries, and a log. Nothing is written in-place.

---

## NIST Workflow Order

Per SP 800-115 methodology:

```
Log Review (§3.2)  →  Network Discovery (§4.1)  →  Port/Service ID (§4.2)
       ↓                                                      ↓
Network Sniffing (§3.5)              OS Fingerprinting (§4.1–4.2)
                                                              ↓
                                           Vulnerability Scanning (§4.3)
                                                              ↓
                                     Password Cracking (§5.1) / Wireless (§4.4)
```

The `vuln_scan_workflow.sh` script automates steps 2–4 in a single run.
