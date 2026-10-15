#!/usr/bin/env python3
"""
cli.py
The wirehawk command-line interface. After installing this package,
you get three short commands instead of long python invocations:

    sudo wirehawk run --scan-all
    sudo wirehawk run --targets 192.168.1.10,192.168.1.15
    sudo wirehawk scan
    sudo wirehawk demo

IMPORTANT: Only use `wirehawk run` on networks/devices you own or have
explicit permission to monitor — it performs ARP spoofing, a traffic
interception technique. See the README for the full responsible-use
policy.
"""

import argparse
import subprocess
import threading
import time

from scapy.all import conf

from wirehawk.import __version__
from wirehawk.network_utils import (
    get_own_ip, get_gateway_ip, get_mac, scan_network, get_local_subnet,
    get_default_iface, get_iface_type, get_own_mac,
    is_vpn_interface, list_vpn_interfaces, list_all_interfaces,
)
from wirehawk.arp_spoof import ARPSpoofer
from wirehawk.packet_capture import PacketStats, start_capture
from wirehawk.dashboard import run_dashboard
from wirehawk.simulate import run_simulation, fake_device_names
from wirehawk.diagnostics import diagnose, diagnose_no_devices
from wirehawk.wifi_scan import scan_wifi_networks
from wirehawk.csv_logger import run_csv_logger
from wirehawk.guard import check_own_security, ArpWatcher, run_arp_watcher
from wirehawk.history_reader import read_device_history, list_logged_devices
from wirehawk.device_aliases import apply_aliases


def set_ip_forwarding(enabled: bool):
    """Enable/disable IP forwarding. Writes directly to /proc first
    (fast, no subprocess, works even without sysctl installed); falls
    back to the sysctl command if that's not accessible for some reason."""
    value = "1" if enabled else "0"
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(value)
    except (PermissionError, OSError):
        subprocess.run(
            ["sysctl", "-w", f"net.ipv4.ip_forward={value}"],
            check=True, stdout=subprocess.DEVNULL,
        )


def resolve_iface(args_iface):
    iface = args_iface or get_default_iface() or conf.iface
    iface_type = get_iface_type(iface)
    return iface, iface_type


def run_demo_mode(iface, iface_type, diagnosis_lines=None, empty_reason=None,
                   log_path=None, focus_ip=None):
    print("[*] Running in DEMO mode — showing simulated traffic data.")
    print("[*] (No real devices are being monitored or spoofed.)")
    time.sleep(1)

    stats = PacketStats()
    stop_event = threading.Event()
    device_names = apply_aliases(fake_device_names())

    sim_thread = threading.Thread(
        target=run_simulation, args=(stats, stop_event), daemon=True,
    )
    sim_thread.start()

    log_thread = None
    if log_path:
        print(f"[*] Logging traffic to {log_path} every 5s...")
        log_thread = threading.Thread(
            target=run_csv_logger, args=(stats, device_names, log_path, stop_event),
            daemon=True,
        )
        log_thread.start()

    try:
        run_dashboard(
            stats, device_names, stop_event, iface=iface, iface_type=iface_type,
            mode_label="DEMO", diagnosis_lines=diagnosis_lines, empty_reason=empty_reason,
            focus_ip=focus_ip,
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        sim_thread.join(timeout=3)
        if log_thread:
            log_thread.join(timeout=3)
            print(f"[*] Log saved to {log_path}")
        print("\n[*] Demo stopped. No network changes were made.")


def cmd_demo(args):
    """Demo mode always runs a real (harmless) diagnosis check too —
    just pings the gateway, touches nothing else — so the 'WHY NO REAL
    DEVICES?' panel is visible as a default part of the interface,
    without needing a full `wirehawk run` attempt to trigger it."""
    iface, iface_type = resolve_iface(args.iface)
    try:
        gateway_ip = get_gateway_ip()
    except Exception:
        gateway_ip = None
    diag = diagnose(gateway_ip)
    run_demo_mode(iface, iface_type, diagnosis_lines=diag["details"],
                  empty_reason=diag["headline"], log_path=args.log, focus_ip=args.focus)


def cmd_scan(args):
    """Read-only discovery — lists devices without spoofing anything.
    Supports --json for piping into scripts/other tools."""
    iface, iface_type = resolve_iface(args.iface)
    own_ip = get_own_ip()
    try:
        gateway_ip = get_gateway_ip()
    except Exception:
        gateway_ip = None

    if not args.json:
        print(f"[*] Interface: {iface} ({iface_type})")
        print(f"[*] Own IP: {own_ip}")

    subnet = get_local_subnet(own_ip)
    if not args.json:
        print(f"[*] Scanning subnet {subnet} ...")
    devices = scan_network(subnet, iface=iface)

    if args.json:
        import json
        print(json.dumps({
            "interface": iface, "interface_type": iface_type, "own_ip": own_ip,
            "gateway_ip": gateway_ip, "subnet": subnet, "devices": devices,
        }, indent=2))
        return

    if not devices:
        diagnose_no_devices(gateway_ip, iface)
        return

    print(f"[*] Found {len(devices)} device(s):")
    for d in devices:
        print(f"    {d['ip']:<16} {d['mac']}")


def cmd_wifi(args):
    """Scans for nearby Wi-Fi networks and shows their security type.
    Purely passive — reads public beacon broadcasts, no interception."""
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    if not args.json:
        console.print("[bold bright_red]\\[*] Scanning for nearby Wi-Fi networks...[/bold bright_red]")

    networks = scan_wifi_networks(rescan=not args.no_rescan)

    if args.json:
        import json
        print(json.dumps({"networks": networks if networks is not None else []}, indent=2))
        return

    if networks is None:
        console.print("[bold red]\\[!] nmcli not found.[/bold red]")
        console.print("    Install NetworkManager to use this feature:")
        console.print("        sudo apt install network-manager")
        return

    if not networks:
        console.print("[yellow]\\[!] No Wi-Fi networks found.[/yellow]")
        console.print("    Check that your Wi-Fi radio is on, or that you have a")
        console.print("    wireless adapter at all (this won't find anything over")
        console.print("    a pure Ethernet-only connection).")
        return

    table = Table(
        title=f"Nearby Wi-Fi Networks ({len(networks)} found)",
        header_style="bold bright_red", border_style="dark_red",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("SSID", style="bright_red", no_wrap=True, overflow="ellipsis")
    table.add_column("SIGNAL", justify="right")
    table.add_column("SECURITY")
    table.add_column("CHANNEL", justify="right")
    table.add_column("BSSID", style="dark_red")

    level_style = {"safe": "bright_red", "warn": "yellow", "danger": "bold red"}

    for n in networks:
        style = level_style.get(n["security_level"], "red")
        table.add_row(
            n["ssid"],
            f"{n['signal']}%" if n["signal"].isdigit() else n["signal"],
            f"[{style}]{n['security']}[/{style}]",
            n["channel"],
            n["bssid"],
        )

    console.print(table)
    open_count = sum(1 for n in networks if n["security_level"] == "danger")
    if open_count:
        console.print(
            f"[bold yellow]\\[!] {open_count} network(s) above are open or use weak "
            f"encryption (WEP) — avoid sending sensitive data on those.[/bold yellow]"
        )


def cmd_guard(args):
    """Defensive mode: checks how exposed THIS device is, then watches
    ARP traffic live for signs someone is running the same kind of
    attack against you that `wirehawk run` performs against others."""
    from rich.console import Console, Group
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich import box

    console = Console()
    iface, iface_type = resolve_iface(args.iface)

    console.print(f"[bold bright_red]\\[*] Checking your own device's security...[/bold bright_red]")
    sec = check_own_security()

    level_style = {"safe": "bright_red", "warn": "yellow", "danger": "bold red"}

    if sec["wifi"]:
        w = sec["wifi"]
        style = level_style.get(w["security_level"], "red")
        console.print(f"  Connected Wi-Fi: [bold]{w['ssid']}[/bold] — [{style}]{w['security']}[/{style}]")
    else:
        console.print("  Connected Wi-Fi: not on Wi-Fi, or couldn't determine (fine if you're on Ethernet)")

    fw = sec["firewall"]
    fw_style = {"active": "bright_red", "inactive": "bold red", "unknown": "yellow"}.get(fw, "red")
    fw_label = {"active": "ENABLED", "inactive": "DISABLED — consider enabling with 'sudo ufw enable'",
                "unknown": "not detected (ufw not installed)"}.get(fw, fw)
    console.print(f"  Firewall (ufw): [{fw_style}]{fw_label}[/{fw_style}]")

    ports = sec["open_ports"]
    if ports is None:
        console.print("  Listening ports: could not check (ss/netstat not available)")
    else:
        exposed = [p for p in ports if p["exposed"]]
        console.print(
            f"  Listening ports: {len(ports)} total, "
            f"[bold yellow]{len(exposed)} exposed to the network[/bold yellow] "
            f"(bound to 0.0.0.0, reachable by other devices — not just this machine)"
        )
        if exposed:
            ptable = Table(header_style="bold bright_red", border_style="dark_red", box=box.SIMPLE_HEAVY)
            ptable.add_column("PROTO")
            ptable.add_column("PORT")
            ptable.add_column("PROCESS")
            for p in exposed[:15]:
                ptable.add_row(p["proto"], p["port"], p["process"] or "?")
            console.print(ptable)

    console.print()
    console.print("[bold bright_red]\\[*] Watching for suspicious ARP activity (ARP spoofing / MITM attempts)...[/bold bright_red]")
    console.print("[dark_red]    Passive only — this does not spoof or intercept anything, just listens.[/dark_red]")
    console.print("[dark_red]    Press Ctrl+C to stop.[/dark_red]\n")
    time.sleep(1.5)

    try:
        gateway_ip = get_gateway_ip()
    except Exception:
        gateway_ip = None

    watcher = ArpWatcher(gateway_ip=gateway_ip)
    stop_event = threading.Event()
    watch_thread = threading.Thread(
        target=run_arp_watcher, args=(iface, watcher, stop_event), daemon=True,
    )
    watch_thread.start()

    def build_view():
        table_data, alerts, count = watcher.snapshot()
        elapsed = time.time() - watcher.start_time

        table = Table(
            title=f"ARP activity — {count} reply packet(s) seen, {int(elapsed)}s elapsed",
            header_style="bold bright_red", border_style="dark_red",
            box=box.SIMPLE_HEAVY, expand=True,
        )
        table.add_column("IP")
        table.add_column("MAC(S) SEEN")
        table.add_column("STATUS")
        for ip, macs in sorted(table_data.items()):
            mac_list = ", ".join(macs.keys())
            is_gateway = ip == gateway_ip
            flagged = len(macs) > 1
            if flagged:
                status = "[bold red]\u26a0 MULTIPLE MACS[/bold red]"
            elif is_gateway:
                status = "[bright_red]gateway, OK[/bright_red]"
            else:
                status = "[red]OK[/red]"
            label = f"{ip} (gateway)" if is_gateway else ip
            table.add_row(label, mac_list, status)

        if not table_data:
            table.add_row("[dim]-- no ARP traffic observed yet --[/dim]", "", "")

        alert_lines = []
        for ts, sev, msg in alerts[-8:]:
            color = "bold red" if sev == "high" else "yellow"
            alert_lines.append(f"[{color}][{ts}] {msg}[/{color}]")
        alert_panel = Panel(
            "\n".join(alert_lines) if alert_lines else "[dim]No suspicious activity detected yet.[/dim]",
            title="[bold bright_red]ALERTS[/bold bright_red]",
            border_style="dark_red", box=box.HEAVY,
        )

        return Group(table, alert_panel)

    try:
        with Live(refresh_per_second=2, screen=True) as live:
            while not stop_event.is_set():
                live.update(build_view())
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        watch_thread.join(timeout=3)
        console.print("\n[*] Guard mode stopped.")


def cmd_history(args):
    """Reads a previously saved --log CSV file and reports on one
    device's history — the file-based, after-the-fact counterpart to
    the live --focus view (since each `wirehawk` invocation is a
    separate process with no memory of a prior session)."""
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()

    try:
        devices_in_log = list_logged_devices(args.log)
    except FileNotFoundError:
        console.print(f"[bold red]\\[!] Log file not found: {args.log}[/bold red]")
        return
    except Exception as e:
        console.print(f"[bold red]\\[!] Could not read log file: {e}[/bold red]")
        return

    if args.device not in devices_in_log:
        console.print(f"[bold yellow]\\[!] '{args.device}' not found in this log.[/bold yellow]")
        if devices_in_log:
            console.print("    Devices present in this log:")
            for d in devices_in_log:
                console.print(f"      {d}")
        else:
            console.print("    This log file appears to be empty.")
        return

    rows = read_device_history(args.log, args.device)
    console.print(f"[bold bright_red]\\[*] History for {args.device}[/bold bright_red] "
                  f"({len(rows)} logged entries, from {args.log})\n")

    table = Table(header_style="bold bright_red", border_style="dark_red", box=box.SIMPLE_HEAVY)
    table.add_column("TIMESTAMP", no_wrap=True)
    table.add_column("TOTAL", justify="right")
    table.add_column("RATE (B/s)", justify="right")
    table.add_column("PROTO")
    table.add_column("HOSTNAME")

    for row in rows:
        table.add_row(
            row.get("timestamp", ""),
            row.get("total_bytes", ""),
            row.get("rate_bytes_per_sec", ""),
            row.get("top_protocol", ""),
            row.get("hostname", "") or "-",
        )
    console.print(table)


def cmd_info(args):
    """A quick system/network report: own IP, gateway, interface,
    connected Wi-Fi security, firewall status, and VPN presence — the
    'what am I working with' overview, similar in spirit to `ifconfig`
    but curated for what actually matters here."""
    from rich.console import Console
    from rich import box
    from rich.table import Table

    console = Console()
    iface, iface_type = resolve_iface(args.iface)

    console.print(f"[bold bright_red]WIREHAWK v{__version__}[/bold bright_red] — system info\n")

    table = Table(show_header=False, border_style="dark_red", box=box.SIMPLE_HEAVY)
    table.add_column(style="red")
    table.add_column(style="bright_red")

    table.add_row("Interface", f"{iface} ({iface_type})")
    try:
        table.add_row("Own IP", get_own_ip())
    except Exception:
        table.add_row("Own IP", "[yellow]could not determine[/yellow]")

    try:
        gw = get_gateway_ip()
        table.add_row("Gateway IP", gw)
    except Exception:
        gw = None
        table.add_row("Gateway IP", "[yellow]could not determine[/yellow]")

    mac = get_own_mac(iface)
    table.add_row("Own MAC", mac or "[yellow]unknown[/yellow]")

    other_vpns = list_vpn_interfaces()
    if is_vpn_interface(iface):
        table.add_row("VPN status", "[bold red]WARNING: active iface IS a VPN tunnel[/bold red]")
    elif other_vpns:
        table.add_row("VPN status", f"[yellow]active in background: {', '.join(other_vpns)}[/yellow]")
    else:
        table.add_row("VPN status", "none detected")

    sec = check_own_security()
    if sec["wifi"]:
        w = sec["wifi"]
        level_style = {"safe": "bright_red", "warn": "yellow", "danger": "bold red"}
        style = level_style.get(w["security_level"], "red")
        table.add_row("Connected Wi-Fi", f"{w['ssid']} — [{style}]{w['security']}[/{style}]")
    else:
        table.add_row("Connected Wi-Fi", "not on Wi-Fi / undetermined")

    fw = sec["firewall"]
    fw_label = {"active": "[bright_red]enabled[/bright_red]",
                "inactive": "[bold red]disabled[/bold red]",
                "unknown": "[yellow]not detected (ufw not installed)[/yellow]"}.get(fw, fw)
    table.add_row("Firewall (ufw)", fw_label)

    console.print(table)


def cmd_interfaces(args):
    """Lists every network interface on this machine with its type
    (Wi-Fi/Ethernet/VPN/Loopback), MAC, and whether it's the one
    auto-detected as the default — similar to `tshark -D`, scoped to
    what matters for picking an --iface value."""
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    interfaces = list_all_interfaces()

    if not interfaces:
        console.print("[yellow]\\[!] No interfaces found (or /sys/class/net unavailable).[/yellow]")
        return

    table = Table(
        title=f"Network Interfaces ({len(interfaces)} found)",
        header_style="bold bright_red", border_style="dark_red", box=box.SIMPLE_HEAVY,
    )
    table.add_column("NAME", style="bright_red", no_wrap=True)
    table.add_column("TYPE")
    table.add_column("MAC")
    table.add_column("HAS IP")
    table.add_column("DEFAULT")

    for iface_info in interfaces:
        type_style = {"VPN": "bold yellow", "Wi-Fi": "bright_red", "Ethernet": "bright_red"}.get(
            iface_info["type"], "dark_red"
        )
        table.add_row(
            iface_info["name"],
            f"[{type_style}]{iface_info['type']}[/{type_style}]",
            iface_info["mac"],
            "yes" if iface_info["has_ip"] else "-",
            "[bold bright_red]\u2713[/bold bright_red]" if iface_info["is_default"] else "",
        )
    console.print(table)


def cmd_run(args):
    iface, iface_type = resolve_iface(args.iface)

    if is_vpn_interface(iface):
        print(f"[!] '{iface}' is a VPN tunnel interface, not a real LAN adapter.")
        print("    ARP spoofing operates at the local network link layer and")
        print("    cannot work over a VPN tunnel — there's no LAN to spoof on")
        print("    the other side of it.")
        print("    Pick your actual Wi-Fi/Ethernet interface instead, e.g.:")
        print("        sudo wirehawk run --iface wlan0 --scan-all")
        print("    Run 'ip a' to see your real interface names.")
        return

    other_vpns = list_vpn_interfaces()
    if other_vpns:
        print(f"[!] Note: a VPN interface is also active on this system ({', '.join(other_vpns)}).")
        print("    Monitoring other devices on the LAN should still work normally,")
        print("    but YOUR OWN device's traffic may route through the VPN and")
        print("    not appear accurately in these results.")
        print()

    print(f"[*] Using interface: {iface} ({iface_type})")
    own_ip = get_own_ip()
    print(f"[*] Own IP: {own_ip}")

    gateway_ip = get_gateway_ip()
    print(f"[*] Gateway IP: {gateway_ip}")

    print("[*] Resolving gateway MAC...")
    gateway_mac = get_mac(gateway_ip, iface=iface)
    if not gateway_mac:
        print("[!] Could not resolve gateway MAC address. Falling back to demo mode.")
        diag = diagnose(gateway_ip)
        run_demo_mode(iface, iface_type, diagnosis_lines=diag["details"],
                      empty_reason=diag["headline"], log_path=args.log, focus_ip=args.focus)
        return
    print(f"[*] Gateway MAC: {gateway_mac}")

    own_mac = get_own_mac(iface)

    targets = {}
    if args.targets:
        for ip in args.targets.split(","):
            ip = ip.strip()
            mac = get_mac(ip, iface=iface)
            if mac:
                targets[ip] = mac
            else:
                print(f"[!] Could not resolve MAC for {ip}, skipping.")
    elif args.scan_all:
        subnet = get_local_subnet(own_ip)
        print(f"[*] Scanning subnet {subnet} for devices...")
        devices = scan_network(subnet, iface=iface)
        for d in devices:
            if d["ip"] not in (own_ip, gateway_ip):
                targets[d["ip"]] = d["mac"]
        print(f"[*] Found {len(targets)} device(s) to monitor.")
    else:
        print("[!] Specify --targets <ips> or --scan-all. Falling back to demo mode.")
        run_demo_mode(iface, iface_type, log_path=args.log, focus_ip=args.focus)
        return

    if not targets:
        print()
        diag = diagnose(gateway_ip)
        print(f"    DIAGNOSIS: {diag['headline']}")
        for line in diag["details"]:
            print(f"    {line}")
        print()
        print("[!] Falling back to demo mode — the same reason will be shown")
        print("    on the dashboard itself, not just here in the terminal.")
        run_demo_mode(iface, iface_type, diagnosis_lines=diag["details"],
                      empty_reason=diag["headline"], log_path=args.log, focus_ip=args.focus)
        return

    device_names = apply_aliases({ip: ip for ip in targets})

    spoofer = ARPSpoofer(
        own_mac=own_mac, gateway_ip=gateway_ip, gateway_mac=gateway_mac,
        iface=iface, interval=args.interval,
    )
    for ip, mac in targets.items():
        spoofer.add_target(ip, mac)

    stats = PacketStats()
    stop_event = threading.Event()

    print("[*] Enabling IP forwarding...")
    set_ip_forwarding(True)

    print("[*] Starting ARP spoofing...")
    spoofer.start()

    print("[*] Starting packet capture...")
    local_ips = set(targets.keys())
    capture_thread = threading.Thread(
        target=start_capture,
        args=(iface, stats, local_ips, stop_event),
        daemon=True,
    )
    capture_thread.start()

    log_thread = None
    if args.log:
        print(f"[*] Logging traffic to {args.log} every 5s...")
        log_thread = threading.Thread(
            target=run_csv_logger, args=(stats, device_names, args.log, stop_event),
            daemon=True,
        )
        log_thread.start()

    time.sleep(1)

    if args.focus and args.focus not in targets:
        print(f"[!] Note: --focus {args.focus} isn't among the monitored targets;")
        print("    the focus panel will show 'no traffic observed yet' until/unless")
        print("    that device appears.")

    try:
        run_dashboard(
            stats, device_names, stop_event, iface=iface, iface_type=iface_type,
            mode_label="ACTIVE", focus_ip=args.focus,
        )
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Shutting down... restoring ARP tables, this may take a few seconds.")
        stop_event.set()
        spoofer.stop_and_restore()
        set_ip_forwarding(False)
        capture_thread.join(timeout=3)
        if log_thread:
            log_thread.join(timeout=3)
            print(f"[*] Log saved to {args.log}")
        print("[*] Cleanup complete. Network restored to normal.")


EPILOG = """\
examples:
  sudo wirehawk run --scan-all                    monitor every device found on the LAN
  sudo wirehawk run --targets 192.168.1.10         monitor one specific device
  sudo wirehawk run --scan-all --focus 192.168.1.10
                                                    live deep-dive into one device's traffic
  sudo wirehawk run --scan-all --log session.csv   also log periodic snapshots to CSV
  sudo wirehawk scan                               list devices on the LAN, read-only
  sudo wirehawk scan --json                        same, as machine-readable JSON
  sudo wirehawk demo                               see the dashboard with simulated data
  sudo wirehawk wifi                               list nearby Wi-Fi networks + security
  sudo wirehawk guard                              check your own exposure + watch for attacks on you
  sudo wirehawk history 192.168.1.10 --log session.csv
                                                    review one device's history from a saved log
  sudo wirehawk interfaces                         list network interfaces and pick one to use
  sudo wirehawk info                               quick system/network summary

Only use `run` and `guard`'s ARP features on networks/devices you own
or have explicit permission to monitor. See the README for the full
responsible-use policy.
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wirehawk",
        description="WIREHAWK — per-device network traffic analyzer, no router access required.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"wirehawk {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_run = subparsers.add_parser("run", help="Monitor real devices (ARP spoofing + live dashboard)")
    p_run.add_argument("--iface", default=None, help="Network interface (auto-detected if omitted)")
    p_run.add_argument("--targets", default=None, help="Comma-separated target IPs")
    p_run.add_argument("--scan-all", action="store_true", help="Auto-discover and monitor all devices")
    p_run.add_argument("--interval", type=float, default=2.0, help="ARP spoof re-send interval (seconds)")
    p_run.add_argument("--log", default=None, metavar="PATH",
                        help="Append periodic traffic snapshots to a CSV file (every 5s) for later review")
    p_run.add_argument("--focus", default=None, metavar="IP",
                        help="Live deep-dive view into one device's traffic and hostname history")
    p_run.set_defaults(func=cmd_run)

    p_scan = subparsers.add_parser("scan", help="Read-only device discovery, no spoofing")
    p_scan.add_argument("--iface", default=None, help="Network interface (auto-detected if omitted)")
    p_scan.add_argument("--json", action="store_true", help="Output as JSON instead of plain text")
    p_scan.set_defaults(func=cmd_scan)

    p_demo = subparsers.add_parser("demo", help="Show the dashboard with simulated traffic data")
    p_demo.add_argument("--iface", default=None, help="Network interface (auto-detected if omitted)")
    p_demo.add_argument("--log", default=None, metavar="PATH",
                         help="Append periodic traffic snapshots to a CSV file (every 5s) for later review")
    p_demo.add_argument("--focus", default=None, metavar="IP",
                         help="Live deep-dive view into one simulated device")
    p_demo.set_defaults(func=cmd_demo)

    p_wifi = subparsers.add_parser("wifi", help="Scan for nearby Wi-Fi networks and their security type")
    p_wifi.add_argument("--no-rescan", action="store_true",
                         help="Use cached scan results instead of triggering a fresh scan (faster)")
    p_wifi.add_argument("--json", action="store_true", help="Output as JSON instead of a table")
    p_wifi.set_defaults(func=cmd_wifi)

    p_guard = subparsers.add_parser(
        "guard", help="Check your own device's security + watch for ARP spoofing attacks against you"
    )
    p_guard.add_argument("--iface", default=None, help="Network interface (auto-detected if omitted)")
    p_guard.set_defaults(func=cmd_guard)

    p_history = subparsers.add_parser(
        "history", help="Review one device's history from a saved --log CSV file"
    )
    p_history.add_argument("device", help="The device's IP address, as it appears in the log")
    p_history.add_argument("--log", required=True, metavar="PATH", help="Path to a CSV file saved via --log")
    p_history.set_defaults(func=cmd_history)

    p_info = subparsers.add_parser("info", help="Quick system/network summary")
    p_info.add_argument("--iface", default=None, help="Network interface (auto-detected if omitted)")
    p_info.set_defaults(func=cmd_info)

    p_interfaces = subparsers.add_parser(
        "interfaces", help="List network interfaces on this machine (Wi-Fi/Ethernet/VPN)"
    )
    p_interfaces.set_defaults(func=cmd_interfaces)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
