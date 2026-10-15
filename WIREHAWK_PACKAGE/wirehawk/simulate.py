"""
simulate.py
Generates realistic-looking fake traffic data so the dashboard always
has something to show — used as a fallback when no other devices are
found on the network, or explicitly via --demo, so the interface never
just exits with "no targets found."
"""

import random
import threading
import time

FAKE_DEVICES = [
    {"ip": "192.168.1.10", "hostnames": ["netflix.com", "youtube.com"], "weight": 3.0},
    {"ip": "192.168.1.15", "hostnames": ["instagram.com", "example.com"], "weight": 1.0},
    {"ip": "192.168.1.22", "hostnames": ["api.spotify.com"], "weight": 0.4},
]

PROTOCOLS = ["HTTPS", "HTTP", "DNS", "TCP", "UDP"]


def run_simulation(stats, stop_event, tick_seconds=1.0):
    """
    Continuously feeds fake but plausible traffic data into the shared
    PacketStats object, using the same .record() interface real packet
    capture uses, so the dashboard code needs zero changes.
    """
    local_ips = [d["ip"] for d in FAKE_DEVICES]

    while not stop_event.is_set():
        for device in FAKE_DEVICES:
            ip = device["ip"]
            weight = device["weight"]

            sent = int(random.uniform(200, 2000) * weight)
            recv = int(random.uniform(2000, 20000) * weight)
            proto = random.choice(PROTOCOLS)
            port = random.choice([443, 80, 53, 22])
            hostname = random.choice(device["hostnames"]) if random.random() < 0.3 else None

            stats.record(
                src_ip=ip, dst_ip="8.8.8.8", size=sent,
                proto_name=proto, port=port, hostname=hostname,
                local_ips=local_ips,
            )
            stats.record(
                src_ip="8.8.8.8", dst_ip=ip, size=recv,
                proto_name=proto, port=port, hostname=None,
                local_ips=local_ips,
            )

        time.sleep(tick_seconds)


def fake_device_names():
    return {d["ip"]: d["ip"] for d in FAKE_DEVICES}
