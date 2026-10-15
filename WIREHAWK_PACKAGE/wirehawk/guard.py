"""
guard.py
Defensive security features, the mirror image of what the rest of
WireHawk does offensively:

  1. check_own_security() — a one-shot report on how exposed THIS
     device is: the security of the Wi-Fi it's connected to, which
     network ports are listening and whether they're exposed to the
     whole LAN or just localhost, and whether a firewall is active.

  2. ArpWatcher — passively watches ARP traffic (no spoofing, no
     interception) for the classic signature of someone else running
     an ARP spoofing / MITM attack against THIS device: an IP —
     especially the gateway — suddenly being claimed by a new MAC
     address after a baseline was established.
"""

import re
import subprocess
import threading
import time
from collections import defaultdict

from scapy.all import sniff, ARP

from wirehawk.wifi_scan import get_active_network_security


# ---------- Self-security check (one-shot, read-only) ----------

def check_open_ports():
    """Lists listening TCP/UDP ports via `ss` (falls back to `netstat`),
    flagging ones exposed to the whole network (bound to 0.0.0.0/::)
    versus localhost-only (127.0.0.1). Returns None if neither tool is
    available, so callers can distinguish "checked, found nothing" from
    "couldn't check"."""
    output = None
    for cmd in (["ss", "-tulnp"], ["netstat", "-tulnp"]):
        try:
            output = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=5,
            ).decode()
            break
        except Exception:
            continue
    if output is None:
        return None

    ports = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if not proto.startswith(("TCP", "UDP")):
            continue

        local_addr = None
        for p in parts:
            if ":" in p and not p.lower().startswith("users"):
                local_addr = p
                break
        if not local_addr or ":" not in local_addr:
            continue

        addr, _, port = local_addr.rpartition(":")
        addr = addr.strip("[]") or "*"
        if not port.isdigit():
            continue
        exposed = addr in ("0.0.0.0", "*", "::")

        process = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            process = m.group(1)

        ports.append({
            "proto": proto, "address": addr, "port": port,
            "exposed": exposed, "process": process,
        })

    seen = set()
    unique = []
    for p in ports:
        key = (p["proto"], p["port"], p["exposed"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    return unique


def check_firewall():
    """Returns 'active', 'inactive', or 'unknown' (ufw not installed or
    couldn't be checked)."""
    try:
        output = subprocess.check_output(
            ["ufw", "status"], stderr=subprocess.DEVNULL, timeout=5,
        ).decode()
    except Exception:
        return "unknown"
    if "Status: active" in output:
        return "active"
    if "Status: inactive" in output:
        return "inactive"
    return "unknown"


def check_own_security():
    """Runs all one-shot self-security checks and returns a combined
    dict. Safe to call anytime — every sub-check degrades gracefully
    (returns None/'unknown') rather than raising if a tool is missing."""
    return {
        "wifi": get_active_network_security(),
        "open_ports": check_open_ports(),
        "firewall": check_firewall(),
    }


# ---------- Live ARP spoofing / MITM detector ----------

class ArpWatcher:
    """
    Passively watches ARP traffic on the interface — purely listening,
    never sending anything — and flags the classic signature of an ARP
    spoofing attack against this device: an IP (especially the
    gateway) suddenly being claimed by a NEW MAC address after a
    baseline mapping was already established. This is deliberately the
    same technique WireHawk's own `run` command performs offensively,
    detected here defensively instead.
    """

    MAX_TRACKED_IPS = 500   # bound memory on large/noisy networks
    MAX_ALERTS = 50

    def __init__(self, gateway_ip=None):
        self.gateway_ip = gateway_ip
        self._lock = threading.Lock()
        self.ip_macs = defaultdict(dict)  # ip -> {mac: first_seen_ts}
        self.alerts = []                   # list of (time_str, severity, message)
        self.packet_count = 0
        self.start_time = time.time()

    def _add_alert(self, severity, message):
        ts = time.strftime("%H:%M:%S")
        with self._lock:
            self.alerts.append((ts, severity, message))
            if len(self.alerts) > self.MAX_ALERTS:
                self.alerts = self.alerts[-self.MAX_ALERTS:]

    def handle_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        if arp.op != 2:  # only ARP replies ("is-at"), not requests
            return

        ip, mac = arp.psrc, arp.hwsrc
        if not ip or not mac or ip == "0.0.0.0":
            return

        with self._lock:
            if len(self.ip_macs) >= self.MAX_TRACKED_IPS and ip not in self.ip_macs:
                return  # bounded — ignore brand-new IPs once at capacity
            self.packet_count += 1
            known_macs = self.ip_macs[ip]
            is_new_mac = mac not in known_macs
            had_prior_mac = len(known_macs) > 0
            known_macs[mac] = time.time()

        if is_new_mac and had_prior_mac:
            is_gateway = ip == self.gateway_ip
            severity = "high" if is_gateway else "medium"
            target = "YOUR GATEWAY" if is_gateway else f"device {ip}"
            self._add_alert(
                severity,
                f"{target} ({ip}) is now claimed by a NEW MAC ({mac}) — "
                f"possible ARP spoofing / MITM attack in progress.",
            )

    def snapshot(self):
        with self._lock:
            table = {ip: dict(macs) for ip, macs in self.ip_macs.items()}
            alerts = list(self.alerts)
            count = self.packet_count
        return table, alerts, count


def run_arp_watcher(iface, watcher: ArpWatcher, stop_event: threading.Event):
    """Runs sniff() in a loop that checks stop_event periodically. Wrapped
    in try/except so a dropped interface doesn't silently kill the
    thread without any way for the caller to know."""

    def handler(pkt):
        try:
            watcher.handle_packet(pkt)
        except Exception:
            pass  # never let a single malformed packet kill the watcher

    def should_stop(_pkt):
        return stop_event.is_set()

    try:
        sniff(iface=iface, filter="arp", prn=handler, store=False, stop_filter=should_stop)
    except Exception as e:
        watcher._add_alert("high", f"ARP watcher stopped unexpectedly: {e}")
