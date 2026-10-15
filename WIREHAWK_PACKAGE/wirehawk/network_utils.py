"""
network_utils.py
Device discovery, MAC/gateway resolution, and interface auto-detection.
Works identically whether the active connection is Wi-Fi or Ethernet —
detection follows the OS's actual default route, not an interface name
pattern, so it's connection-type agnostic.
"""

import os
import subprocess
import socket
from scapy.all import ARP, Ether, srp, conf


def get_own_ip():
    """Get this machine's IP address on the active interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def get_default_iface():
    """
    Auto-detect the interface currently used for internet traffic by
    reading the default route. Works the same for Ethernet (eth0,
    enpXsY) and Wi-Fi (wlan0, wlpXsY) — whichever is actually active,
    since it just follows the kernel's own routing decision.
    """
    try:
        output = subprocess.check_output(
            ["ip", "route", "show", "default"]
        ).decode()
        # Example: "default via 192.168.1.1 dev wlp4s0 proto dhcp ..."
        parts = output.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def get_iface_type(iface):
    """Best-effort guess at whether an interface is Wi-Fi or Ethernet,
    for display purposes only — doesn't affect functionality."""
    try:
        with open(f"/sys/class/net/{iface}/wireless", "r"):
            return "Wi-Fi"
    except (FileNotFoundError, IsADirectoryError, OSError):
        pass
    if iface.startswith(("wl",)):
        return "Wi-Fi"
    if iface.startswith(("en", "eth")):
        return "Ethernet"
    return "Unknown"


def get_gateway_ip():
    """Parse the default gateway IP from the routing table."""
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"]).decode()
        return output.split("via ")[1].split(" ")[0]
    except Exception as e:
        raise RuntimeError(f"Could not determine gateway IP: {e}")


def get_mac(ip, iface=None, timeout=2):
    """Resolve a device's MAC address using an ARP request."""
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=timeout, iface=iface, verbose=False)[0]
    if result:
        return result[0][1].hwsrc
    return None


def scan_network(ip_range, iface=None, timeout=3):
    """
    Scan the local network for live devices using ARP requests.
    Works over Ethernet or Wi-Fi identically — ARP itself is a
    link-layer protocol common to both.
    """
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=timeout, iface=iface, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices


def get_local_subnet(own_ip):
    """Guess a /24 subnet string from this machine's own IP, e.g.
    192.168.1.0/24."""
    parts = own_ip.split(".")
    parts[-1] = "0"
    return ".".join(parts) + "/24"


_VPN_IFACE_PREFIXES = ("tun", "tap", "wg", "ppp", "ipsec", "nordlynx", "utun")


def is_vpn_interface(iface):
    """Best-effort check: does this interface name look like a VPN
    tunnel (OpenVPN/WireGuard/PPP/etc.) rather than a real Wi-Fi or
    Ethernet adapter? ARP spoofing operates at the LAN link layer and
    fundamentally doesn't work over a VPN tunnel, so this matters."""
    if not iface:
        return False
    return iface.lower().startswith(_VPN_IFACE_PREFIXES)


def list_vpn_interfaces():
    """Returns every currently present interface name that looks like
    a VPN tunnel, even ones not currently selected as the active
    interface — so a background VPN can still be flagged as a heads-up."""
    try:
        names = os.listdir("/sys/class/net")
    except Exception:
        return []
    return [n for n in names if is_vpn_interface(n)]


def get_own_mac(iface):
    """Get this machine's MAC address on the given interface. Tries the
    sysfs path first (fastest, most reliable), falls back to parsing
    'ip link show' if that's unavailable (e.g. some virtual interfaces),
    then finally to scapy's own interface table."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip()
            if mac and mac != "00:00:00:00:00:00":
                return mac
    except Exception:
        pass

    try:
        output = subprocess.check_output(["ip", "link", "show", iface]).decode()
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("link/ether"):
                return line.split()[1]
    except Exception:
        pass

    try:
        return conf.ifaces.dev_from_name(iface).mac
    except Exception:
        return None


def list_all_interfaces():
    """
    Lists every network interface on this machine with a best-effort
    type label (Wi-Fi/Ethernet/VPN/Loopback/Unknown), its MAC address,
    and whether it currently has an IP assigned. Used by `wirehawk
    interfaces` for a quick system overview, similar in spirit to `ip a`
    but filtered to what's actually relevant for picking an interface.
    """
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except Exception:
        return []

    default = get_default_iface()
    results = []
    for name in names:
        if name == "lo":
            iface_type = "Loopback"
        elif is_vpn_interface(name):
            iface_type = "VPN"
        else:
            iface_type = get_iface_type(name)

        mac = get_own_mac(name) or "-"

        has_ip = False
        try:
            output = subprocess.check_output(
                ["ip", "-4", "addr", "show", name], stderr=subprocess.DEVNULL,
            ).decode()
            has_ip = "inet " in output
        except Exception:
            pass

        results.append({
            "name": name,
            "type": iface_type,
            "mac": mac,
            "has_ip": has_ip,
            "is_default": name == default,
        })
    return results
