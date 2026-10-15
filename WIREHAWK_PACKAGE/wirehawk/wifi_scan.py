"""
wifi_scan.py
Scans for nearby Wi-Fi networks (SSIDs) visible to this machine's
wireless radio, and classifies each by security type. This is purely
passive — it only reads public beacon broadcasts every Wi-Fi device
already receives, no traffic interception involved.

Requires NetworkManager (nmcli), which ships by default on most
desktop Ubuntu installs. On minimal/server installs, install with:
    sudo apt install network-manager
"""

import re
import subprocess


def _parse_nmcli_line(line):
    """nmcli's terse (-t) output separates fields with ':', but escapes
    literal colons inside a field (like a BSSID/MAC) as '\\:'. A plain
    split(':') would incorrectly break a MAC address apart, so split
    only on unescaped colons, then unescape."""
    parts = re.split(r"(?<!\\):", line)
    return [p.replace("\\:", ":") for p in parts]


def classify_security(security_str):
    """Turns nmcli's raw security string into a clear, judged label."""
    s = (security_str or "").upper()
    if not s or "NONE" in s:
        return "OPEN — insecure", "danger"
    if "WEP" in s:
        return "WEP — weak/insecure", "danger"
    if "WPA3" in s:
        return "WPA3 — secure", "safe"
    if "WPA2" in s:
        return "WPA2 — secure", "safe"
    if "WPA" in s:
        return "WPA — outdated", "warn"
    return s, "warn"


def scan_wifi_networks(rescan=True):
    """
    Returns a list of dicts: [{ssid, signal, security, security_level,
    channel, bssid}, ...], sorted by signal strength (strongest first).
    Returns None if nmcli isn't available at all (distinct from an
    empty list, which means it ran fine but found nothing).
    """
    cmd = ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,CHAN,BSSID", "dev", "wifi", "list"]
    if rescan:
        cmd += ["--rescan", "yes"]

    try:
        output = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=15,
        ).decode()
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError:
        return None
    except subprocess.TimeoutExpired:
        return None

    seen = set()
    networks = []
    for line in output.strip().splitlines():
        if not line:
            continue
        parts = _parse_nmcli_line(line)
        if len(parts) < 5:
            continue
        ssid, signal, security, chan, bssid = parts[:5]
        ssid = ssid or "(hidden network)"

        key = (ssid, bssid)
        if key in seen:
            continue
        seen.add(key)

        label, level = classify_security(security)
        networks.append({
            "ssid": ssid,
            "signal": signal,
            "security": label,
            "security_level": level,
            "channel": chan,
            "bssid": bssid,
        })

    networks.sort(key=lambda n: int(n["signal"]) if n["signal"].isdigit() else 0, reverse=True)
    return networks


def get_active_network_security():
    """
    Returns {ssid, security, security_level} for the Wi-Fi network this
    device is currently connected to right now, or None if not
    connected via Wi-Fi (e.g. on Ethernet) or it can't be determined.
    Used for 'how secure is my own connection', as opposed to
    scan_wifi_networks() which lists everything nearby.
    """
    try:
        output = subprocess.check_output(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi", "list"],
            stderr=subprocess.DEVNULL, timeout=10,
        ).decode()
    except Exception:
        return None

    for line in output.strip().splitlines():
        if not line:
            continue
        parts = _parse_nmcli_line(line)
        if len(parts) < 3:
            continue
        active, ssid, security = parts[:3]
        if active.lower() == "yes":
            label, level = classify_security(security)
            return {"ssid": ssid or "(hidden network)", "security": label, "security_level": level}
    return None
