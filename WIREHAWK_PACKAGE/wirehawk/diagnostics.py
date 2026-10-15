"""
diagnostics.py
Figures out *why* no devices could be reached — distinguishing AP/client
isolation from a basic connectivity problem — and returns structured
data so both the terminal and the live dashboard can display it.
"""

import subprocess


def ping_host(ip, count=2, timeout=2):
    """Best-effort ICMP ping check. Returns True if the host replies."""
    if not ip:
        return False
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def diagnose(gateway_ip):
    """
    Runs quick checks and returns a structured diagnosis:
        {
            "status": "no_gateway" | "isolated_or_empty",
            "headline": short one-line reason (for the dashboard header),
            "details": list of strings (full explanation, multi-line),
        }
    """
    gateway_reachable = ping_host(gateway_ip)

    if not gateway_reachable:
        return {
            "status": "no_gateway",
            "headline": "BLOCKED: can't reach gateway — check connection",
            "details": [
                "Can't reach the gateway/router itself.",
                "Likely causes:",
                "  - Not actually connected to this network",
                "  - Network has a captive portal login you haven't completed",
                "  - A local firewall is blocking outbound ICMP",
                f"Try manually: ping {gateway_ip}" if gateway_ip else
                "Could not determine a gateway IP at all.",
            ],
        }

    return {
        "status": "isolated_or_empty",
        "headline": "BLOCKED: likely AP/client isolation on this network",
        "details": [
            "Gateway responds fine, but no other devices were found.",
            "Most likely causes:",
            "  1. AP / Client isolation is enabled on this network.",
            "     Common on phone hotspots & enterprise/public Wi-Fi —",
            "     deliberately blocks devices from seeing each other.",
            "     This is a security feature of the access point —",
            "     there is no client-side fix for it.",
            "  2. No other devices are actually connected right now.",
            "To tell which: ping another device's IP directly. 100%",
            "packet loss on that too confirms isolation (#1).",
        ],
    }


def diagnose_no_devices(gateway_ip, iface):
    """Terminal-printing wrapper around diagnose(), used by `wirehawk scan`."""
    print("[!] No other devices found on the network.")
    print("[*] Running quick diagnostics to figure out why...")
    result = diagnose(gateway_ip)
    print()
    print(f"    DIAGNOSIS: {result['headline']}")
    for line in result["details"]:
        print(f"    {line}")
    return result["status"]
