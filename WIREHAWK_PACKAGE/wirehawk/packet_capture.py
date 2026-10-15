"""
packet_capture.py
Sniffs packets on the interface and maintains live per-device
statistics: bandwidth, protocols, ports, and a timestamped history of
hostnames visited — resolved via DNS queries and, for HTTPS traffic,
via the TLS SNI field (sent in cleartext before encryption, the same
way a browser shows "connecting to <host>").
"""

import threading
import time
from collections import defaultdict, Counter, deque
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw

# Common port -> service name mapping (extend as needed)
COMMON_PORTS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 110: "POP3", 143: "IMAP", 3389: "RDP", 123: "NTP",
}

HISTORY_MAX_PER_DEVICE = 200  # bounded so long sessions stay memory-stable


class PacketStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.devices = defaultdict(lambda: {
            "bytes_sent": 0,
            "bytes_recv": 0,
            "protocols": Counter(),
            "ports": Counter(),
            # dict used as an insertion-ordered, bounded set: lets us
            # evict the OLDEST hostname once at capacity (unlike a plain
            # set, which has no order to evict by) — so a long session
            # with thousands of distinct hosts stays memory-stable
            # instead of growing forever, and dedup stays correct even
            # past that point (an evicted name is correctly treated as
            # "new" again if it reappears, rather than silently
            # flooding history with repeats).
            "hostnames_seen": {},
            "history": deque(maxlen=HISTORY_MAX_PER_DEVICE),  # (timestamp, hostname, proto)
            "last_seen": 0,
        })
        self.start_time = time.time()

    def record(self, src_ip, dst_ip, size, proto_name, port=None, hostname=None,
               local_ips=()):
        with self._lock:
            now = time.time()
            if src_ip in local_ips:
                d = self.devices[src_ip]
                d["bytes_sent"] += size
                d["last_seen"] = now
                d["protocols"][proto_name] += 1
                if port:
                    d["ports"][port] += 1
                if hostname:
                    seen = d["hostnames_seen"]
                    is_new = hostname not in seen
                    if is_new:
                        seen[hostname] = now
                        if len(seen) > HISTORY_MAX_PER_DEVICE:
                            oldest = next(iter(seen))  # insertion order -> oldest first
                            del seen[oldest]
                        d["history"].append((now, hostname, proto_name))
            if dst_ip in local_ips:
                d = self.devices[dst_ip]
                d["bytes_recv"] += size
                d["last_seen"] = now
                d["protocols"][proto_name] += 1
                if port:
                    d["ports"][port] += 1

    def snapshot(self):
        """Return a shallow copy safe for rendering."""
        with self._lock:
            return {
                ip: {
                    "bytes_sent": d["bytes_sent"],
                    "bytes_recv": d["bytes_recv"],
                    "protocols": dict(d["protocols"]),
                    "ports": dict(d["ports"]),
                    "hostnames": [h for _, h, _ in list(d["history"])[-5:]][::-1],
                    "last_seen": d["last_seen"],
                }
                for ip, d in self.devices.items()
            }

    def device_history(self, ip):
        """Returns the full timestamped (timestamp, hostname, protocol)
        history for one device — used by the 'view history' feature,
        as opposed to snapshot()'s truncated top-5 list meant for the
        live table."""
        with self._lock:
            if ip not in self.devices:
                return []
            return list(self.devices[ip]["history"])


def _proto_name(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IP):
        return f"IP-{pkt[IP].proto}"
    return "OTHER"


def _extract_dns_hostname(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            return pkt[DNSQR].qname.decode().rstrip(".")
        except Exception:
            return None
    return None


def _extract_sni_hostname(pkt):
    """
    Best-effort extraction of the SNI (Server Name Indication) hostname
    from a TLS ClientHello, via manual byte parsing of the handshake —
    no extra dependencies needed. This is the same hostname a browser
    shows when it says "connecting to...", sent in cleartext as part of
    the TLS handshake before encryption begins. Safely returns None on
    anything that isn't a well-formed ClientHello.
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return None
    try:
        payload = bytes(pkt[Raw].load)
        if len(payload) < 6 or payload[0] != 0x16:  # TLS handshake record
            return None
        if payload[5] != 0x01:  # ClientHello
            return None

        pos = 5 + 4 + 2 + 32  # record hdr + handshake hdr + version + random
        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return None
        cipher_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_total_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        end = pos + ext_total_len

        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            ext_data_start = pos + 4
            if ext_type == 0x00:  # server_name extension
                sp = ext_data_start + 2 + 1  # list_len(2) + name_type(1)
                if sp + 2 <= len(payload):
                    name_len = int.from_bytes(payload[sp:sp + 2], "big")
                    name_start = sp + 2
                    if name_start + name_len <= len(payload):
                        return payload[name_start:name_start + name_len].decode(
                            "ascii", errors="ignore"
                        )
            pos = ext_data_start + ext_len
        return None
    except Exception:
        return None


def make_packet_handler(stats: PacketStats, local_ips):
    """Returns a callback function for scapy's sniff()."""

    def handler(pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        size = len(pkt)
        proto = _proto_name(pkt)

        port = None
        if pkt.haslayer(TCP):
            # For incoming traffic (dst is local), the *remote* side's
            # port is sport — that's the meaningful service port (e.g.
            # 443 for HTTPS). For outgoing traffic, it's dport instead.
            port = pkt[TCP].sport if dst_ip in local_ips else pkt[TCP].dport
        elif pkt.haslayer(UDP):
            port = pkt[UDP].sport if dst_ip in local_ips else pkt[UDP].dport

        if port in COMMON_PORTS:
            proto = COMMON_PORTS[port]

        hostname = _extract_dns_hostname(pkt) or _extract_sni_hostname(pkt)

        stats.record(src_ip, dst_ip, size, proto, port, hostname, local_ips)

    return handler


def start_capture(iface, stats: PacketStats, local_ips, stop_event: threading.Event):
    """
    Runs sniff() in a loop that checks stop_event periodically. Both
    the per-packet handler and the sniff() call itself are guarded:
    one malformed or unusual packet should never be able to kill the
    whole capture thread, and if the interface itself drops mid-
    session, that fails quietly rather than dumping a raw traceback
    into a live full-screen terminal dashboard.
    """
    raw_handler = make_packet_handler(stats, local_ips)

    def safe_handler(pkt):
        try:
            raw_handler(pkt)
        except Exception:
            pass  # never let one bad packet kill the capture loop

    def should_stop(_pkt):
        return stop_event.is_set()

    try:
        sniff(iface=iface, prn=safe_handler, store=False, stop_filter=should_stop)
    except Exception:
        pass  # interface dropped or similar — thread ends quietly
