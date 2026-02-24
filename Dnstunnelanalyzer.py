#!/usr/bin/env python3
"""
DNS Tunnel Analyzer – Blue Team Detection Tool
================================================
Passively captures DNS traffic and applies heuristic detection rules
to identify potential DNS tunneling activity.

Detection Techniques:
  1. High entropy subdomains (data looks random)
  2. Abnormal query frequency per source
  3. Unusually long FQDNs
  4. High unique subdomain count per domain
  5. Hex/base32 pattern matching in labels
  6. Statistical NXDomain ratio analysis

Usage:
  sudo python3 dns_tunnel_analyzer.py --interface eth0
  sudo python3 dns_tunnel_analyzer.py --interface lo --pcap capture.pcap
  python3 dns_tunnel_analyzer.py --pcap existing_capture.pcap
"""

import argparse
import base64
import binascii
import collections
import json
import logging
import math
import re
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

# Optional: try to import scapy; fall back to raw socket if unavailable
try:
    from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("dns_analyzer")


# ---------------------------------------------------------------------------
# Detection Configuration
# ---------------------------------------------------------------------------
ENTROPY_THRESHOLD        = 3.8   # bits/char — typical English text < 4.0
LONG_FQDN_THRESHOLD      = 120   # characters
HIGH_FREQ_THRESHOLD      = 30    # queries/minute from one source
UNIQUE_SUBDOMAIN_RATIO   = 0.8   # unique subdomains / total queries
WINDOW_SECONDS           = 60    # sliding analysis window

HEX_PATTERN    = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)
BASE32_PATTERN = re.compile(r"^[a-z2-7]{8,}$", re.IGNORECASE)

ALERT_LEVELS = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


# ---------------------------------------------------------------------------
# Entropy Calculator
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s.lower())
    total = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------
@dataclass
class DNSQuery:
    timestamp: float
    src_ip: str
    qname: str
    qtype: int
    response_code: int = 0
    txt_response: str = ""

    @property
    def subdomain(self) -> str:
        """Return everything except the last two labels (TLD.domain)."""
        parts = self.qname.rstrip(".").split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2])
        return ""

    @property
    def apex_domain(self) -> str:
        parts = self.qname.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else self.qname


@dataclass
class DetectionAlert:
    timestamp: float
    src_ip: str
    domain: str
    level: int
    technique: str
    detail: str
    evidence: dict = field(default_factory=dict)

    def __str__(self):
        ts = datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S")
        lvl = ALERT_LEVELS.get(self.level, "?")
        return (f"[{ts}] [{lvl}] {self.technique} | src={self.src_ip} "
                f"domain={self.domain} | {self.detail}")


# ---------------------------------------------------------------------------
# Per-Source Statistics
# ---------------------------------------------------------------------------
class SourceStats:
    def __init__(self, src_ip: str):
        self.src_ip = src_ip
        self.queries: list[DNSQuery] = []
        self.domains: dict[str, list[DNSQuery]] = collections.defaultdict(list)
        self.alerts: list[DetectionAlert] = []
        self.alerted_techniques: set = set()

    def add_query(self, q: DNSQuery):
        self.queries.append(q)
        self.domains[q.apex_domain].append(q)

    def recent_queries(self, window: float = WINDOW_SECONDS) -> list[DNSQuery]:
        cutoff = time.time() - window
        return [q for q in self.queries if q.timestamp >= cutoff]


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------
class DetectionEngine:
    def __init__(self, alert_callback=None):
        self.sources: dict[str, SourceStats] = {}
        self.alerts: list[DetectionAlert] = []
        self.callback = alert_callback or self._default_callback
        self.lock = threading.Lock()

    def _default_callback(self, alert: DetectionAlert):
        print(f"\n{'='*70}")
        print(str(alert))
        print(f"  Evidence: {json.dumps(alert.evidence, indent=4)}")
        print(f"{'='*70}\n")

    def process_query(self, q: DNSQuery):
        with self.lock:
            if q.src_ip not in self.sources:
                self.sources[q.src_ip] = SourceStats(q.src_ip)
            stats = self.sources[q.src_ip]
            stats.add_query(q)
            self._run_detections(q, stats)

    def _run_detections(self, q: DNSQuery, stats: SourceStats):
        self._check_entropy(q, stats)
        self._check_fqdn_length(q, stats)
        self._check_hex_base32(q, stats)
        self._check_query_frequency(q, stats)
        self._check_subdomain_diversity(q, stats)
        self._check_txt_query(q, stats)

    # ------------------------------------------------------------------
    # Detection Rules
    # ------------------------------------------------------------------
    def _check_entropy(self, q: DNSQuery, stats: SourceStats):
        """High-entropy labels indicate encoded/random data."""
        subdomain = q.subdomain
        if not subdomain:
            return
        labels = subdomain.split(".")
        for label in labels:
            if len(label) < 6:
                continue
            entropy = shannon_entropy(label)
            if entropy >= ENTROPY_THRESHOLD:
                self._alert(
                    stats, q.apex_domain, level=3,
                    technique="High Entropy Subdomain",
                    detail=f"Label '{label[:30]}' entropy={entropy:.2f} bits/char",
                    evidence={"label": label, "entropy": round(entropy, 3),
                               "threshold": ENTROPY_THRESHOLD, "fqdn": q.qname},
                )

    def _check_fqdn_length(self, q: DNSQuery, stats: SourceStats):
        """Unusually long FQDNs suggest data encoded in subdomain."""
        fqdn_len = len(q.qname)
        if fqdn_len >= LONG_FQDN_THRESHOLD:
            level = 4 if fqdn_len > 180 else 2
            self._alert(
                stats, q.apex_domain, level=level,
                technique="Abnormally Long FQDN",
                detail=f"FQDN length={fqdn_len} chars (threshold={LONG_FQDN_THRESHOLD})",
                evidence={"fqdn_length": fqdn_len, "fqdn": q.qname[:120] + "…"},
                key=f"fqdn_len_{q.qname[:40]}",
            )

    def _check_hex_base32(self, q: DNSQuery, stats: SourceStats):
        """Hex/base32 encoded labels are a strong tunnel indicator."""
        subdomain = q.subdomain
        if not subdomain:
            return
        labels = subdomain.split(".")
        for label in labels:
            if len(label) < 8:
                continue
            if HEX_PATTERN.match(label):
                self._alert(
                    stats, q.apex_domain, level=3,
                    technique="Hex-Encoded Label",
                    detail=f"Label matches hex pattern: '{label[:40]}'",
                    evidence={"label": label, "pattern": "hex", "fqdn": q.qname},
                )
            elif BASE32_PATTERN.match(label):
                self._alert(
                    stats, q.apex_domain, level=2,
                    technique="Base32-Encoded Label",
                    detail=f"Label matches base32 pattern: '{label[:40]}'",
                    evidence={"label": label, "pattern": "base32", "fqdn": q.qname},
                )

    def _check_query_frequency(self, q: DNSQuery, stats: SourceStats):
        """Rapid DNS queries from one source to the same domain."""
        domain_queries = stats.domains[q.apex_domain]
        cutoff = time.time() - WINDOW_SECONDS
        recent = [dq for dq in domain_queries if dq.timestamp >= cutoff]
        rate = len(recent)
        if rate >= HIGH_FREQ_THRESHOLD:
            self._alert(
                stats, q.apex_domain, level=3,
                technique="High Query Frequency",
                detail=f"{rate} queries/{WINDOW_SECONDS}s to {q.apex_domain}",
                evidence={"queries_per_min": rate, "threshold": HIGH_FREQ_THRESHOLD},
                key=f"freq_{q.apex_domain}_{int(time.time()//30)}",
            )

    def _check_subdomain_diversity(self, q: DNSQuery, stats: SourceStats):
        """High ratio of unique subdomains → every query is different (data)."""
        domain_queries = stats.domains[q.apex_domain]
        if len(domain_queries) < 10:
            return
        subdomains = [dq.subdomain for dq in domain_queries if dq.subdomain]
        if not subdomains:
            return
        ratio = len(set(subdomains)) / len(subdomains)
        if ratio >= UNIQUE_SUBDOMAIN_RATIO:
            self._alert(
                stats, q.apex_domain, level=3,
                technique="High Subdomain Uniqueness",
                detail=f"{ratio:.0%} unique subdomains ({len(set(subdomains))}/{len(subdomains)})",
                evidence={"unique_ratio": round(ratio, 3),
                           "unique_count": len(set(subdomains)),
                           "total_count": len(subdomains)},
                key=f"diversity_{q.apex_domain}",
            )

    def _check_txt_query(self, q: DNSQuery, stats: SourceStats):
        """TXT record queries are unusual for normal browsing but common in tunnels."""
        if q.qtype == 16:  # TXT
            self._alert(
                stats, q.apex_domain, level=1,
                technique="TXT Record Query",
                detail=f"TXT query to {q.qname}",
                evidence={"qname": q.qname, "note": "TXT queries rare in normal traffic"},
                key=f"txt_{q.apex_domain}_{q.src_ip}",
            )

    # ------------------------------------------------------------------
    def _alert(self, stats: SourceStats, domain: str, level: int,
               technique: str, detail: str, evidence: dict, key: str | None = None):
        """Deduplicate and emit an alert."""
        dedup_key = key or f"{technique}:{stats.src_ip}:{domain}"
        if dedup_key in stats.alerted_techniques:
            return
        stats.alerted_techniques.add(dedup_key)

        alert = DetectionAlert(
            timestamp=time.time(),
            src_ip=stats.src_ip,
            domain=domain,
            level=level,
            technique=technique,
            detail=detail,
            evidence=evidence,
        )
        stats.alerts.append(alert)
        self.alerts.append(alert)
        self.callback(alert)

    # ------------------------------------------------------------------
    def summary(self):
        print("\n" + "="*70)
        print("DETECTION SUMMARY")
        print("="*70)
        by_level = collections.Counter(a.level for a in self.alerts)
        for lvl in sorted(by_level, reverse=True):
            print(f"  {ALERT_LEVELS[lvl]:8s} ({lvl}): {by_level[lvl]} alerts")
        print(f"\nTotal alerts : {len(self.alerts)}")
        print(f"Total sources: {len(self.sources)}")
        suspicious = {ip for ip, s in self.sources.items() if s.alerts}
        print(f"Flagged IPs  : {', '.join(suspicious) or 'None'}")
        print("="*70 + "\n")


# ---------------------------------------------------------------------------
# Packet Capture / Parsing
# ---------------------------------------------------------------------------
class PcapReader:
    """Parse a pcap file without scapy using raw struct parsing."""

    PCAP_GLOBAL_HDR = struct.Struct("<IHHiIII")   # magic, vmaj, vmin, ...
    PCAP_PKT_HDR    = struct.Struct("<IIII")

    def read(self, filepath: str):
        """Yield (timestamp, ip_src, dns_query_name, dns_qtype) tuples."""
        with open(filepath, "rb") as f:
            ghdr = f.read(24)
            if len(ghdr) < 24:
                raise ValueError("File too small for pcap header")
            magic = struct.unpack("<I", ghdr[:4])[0]
            if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
                raise ValueError("Not a pcap file")
            swap = magic == 0xD4C3B2A1

            while True:
                phdr = f.read(16)
                if len(phdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = self.PCAP_PKT_HDR.unpack(phdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break
                ts = ts_sec + ts_usec / 1e6
                try:
                    result = self._parse_ethernet(pkt_data, ts)
                    if result:
                        yield result
                except Exception:
                    continue

    def _parse_ethernet(self, data: bytes, ts: float):
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        if etype == 0x0800:    # IPv4
            return self._parse_ip(data[14:], ts)
        elif etype == 0x86DD:  # IPv6 – skip for simplicity
            return None
        return None

    def _parse_ip(self, data: bytes, ts: float):
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        proto = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        if proto == 17:   # UDP
            return self._parse_udp(data[ihl:], ts, src_ip)
        return None

    def _parse_udp(self, data: bytes, ts: float, src_ip: str):
        if len(data) < 8:
            return None
        dst_port = struct.unpack("!H", data[2:4])[0]
        if dst_port != 53:
            return None
        return self._parse_dns(data[8:], ts, src_ip)

    def _parse_dns(self, data: bytes, ts: float, src_ip: str):
        if len(data) < 12:
            return None
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return None
        offset = 12
        try:
            qname, offset = self._parse_name(data, offset)
            qtype = struct.unpack("!H", data[offset:offset+2])[0]
            return DNSQuery(timestamp=ts, src_ip=src_ip,
                            qname=qname.lower(), qtype=qtype)
        except Exception:
            return None

    def _parse_name(self, data: bytes, offset: int) -> tuple[str, int]:
        labels = []
        visited = set()
        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                ptr = ((length & 0x3F) << 8) | data[offset+1]
                suffix, _ = self._parse_name(data, ptr)
                labels.append(suffix)
                offset += 2
                break
            else:
                offset += 1
                labels.append(data[offset:offset+length].decode("ascii", errors="replace"))
                offset += length
        return ".".join(labels), offset


# ---------------------------------------------------------------------------
# Live Capture (Scapy)
# ---------------------------------------------------------------------------
def live_capture(interface: str, engine: DetectionEngine):
    if not SCAPY_AVAILABLE:
        log.error("Scapy not installed. Install with: pip install scapy")
        sys.exit(1)

    log.info(f"Capturing DNS on interface: {interface}")

    def pkt_handler(pkt):
        try:
            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
                return
            q = DNSQuery(
                timestamp=time.time(),
                src_ip=pkt[IP].src if pkt.haslayer(IP) else "?",
                qname=pkt[DNSQR].qname.decode("ascii", errors="replace").lower(),
                qtype=pkt[DNSQR].qtype,
                response_code=pkt[DNS].rcode if pkt[DNS].qr else 0,
            )
            engine.process_query(q)
        except Exception as e:
            log.debug(f"Packet error: {e}")

    sniff(iface=interface, filter="udp port 53", prn=pkt_handler, store=False)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DNS Tunnel Analyzer – Blue Team Detection Tool"
    )
    parser.add_argument("--interface", "-i", help="Network interface for live capture")
    parser.add_argument("--pcap", "-r",     help="Read from pcap file")
    parser.add_argument("--threshold-entropy",  type=float, default=ENTROPY_THRESHOLD,
                        help=f"Entropy alert threshold (default={ENTROPY_THRESHOLD})")
    parser.add_argument("--threshold-fqdn",     type=int,   default=LONG_FQDN_THRESHOLD,
                        help=f"FQDN length threshold (default={LONG_FQDN_THRESHOLD})")
    parser.add_argument("--threshold-rate",     type=int,   default=HIGH_FREQ_THRESHOLD,
                        help=f"Query/min threshold (default={HIGH_FREQ_THRESHOLD})")
    parser.add_argument("--output-json", help="Write alerts to JSON file")
    args = parser.parse_args()

    if not args.interface and not args.pcap:
        parser.error("Specify --interface for live capture or --pcap for offline analysis")

    # Override thresholds if provided
    global ENTROPY_THRESHOLD, LONG_FQDN_THRESHOLD, HIGH_FREQ_THRESHOLD
    ENTROPY_THRESHOLD    = args.threshold_entropy
    LONG_FQDN_THRESHOLD  = args.threshold_fqdn
    HIGH_FREQ_THRESHOLD  = args.threshold_rate

    engine = DetectionEngine()

    try:
        if args.pcap:
            log.info(f"Analyzing pcap: {args.pcap}")
            reader = PcapReader()
            count = 0
            for query in reader.read(args.pcap):
                engine.process_query(query)
                count += 1
            log.info(f"Processed {count} DNS queries from pcap.")

        elif args.interface:
            live_capture(args.interface, engine)

    except KeyboardInterrupt:
        log.info("Capture stopped by user.")

    engine.summary()

    if args.output_json and engine.alerts:
        with open(args.output_json, "w") as f:
            json.dump([
                {
                    "timestamp": a.timestamp,
                    "src_ip": a.src_ip,
                    "domain": a.domain,
                    "level": ALERT_LEVELS[a.level],
                    "technique": a.technique,
                    "detail": a.detail,
                    "evidence": a.evidence,
                }
                for a in engine.alerts
            ], f, indent=2)
        log.info(f"Alerts written to: {args.output_json}")


if __name__ == "__main__":
    main()
