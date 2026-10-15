# WIREHAWK — Network Traffic Analyzer (v2.1)

Per-device network bandwidth and protocol monitoring for any LAN —
Wi-Fi or Ethernet — without needing router/admin access.

## ⚠️ Responsible use

This tool works by **ARP spoofing**: it redirects traffic from target
devices through this machine so it can be inspected before being
forwarded on normally. This is a legitimate network diagnostics
technique, but it's also a form of traffic interception, so:

- Only run this on **your own network**, with **your own devices or
  devices you have explicit permission to monitor**.
- Never run it on a network you don't control or administer (public
  Wi-Fi, a library, a school, a workplace you don't manage, etc.).
- The tool restores ARP tables and disables IP forwarding automatically
  on exit (including Ctrl+C), so it shouldn't leave the network in a
  broken state.

## What's new in v2.1 (red theme, on-screen diagnosis, WireHawk rename)

- **Installed as a real CLI** — `wirehawk run`, `wirehawk scan`, `wirehawk demo`
  instead of long `python3 main.py --flag` invocations.
- **Works over Ethernet or Wi-Fi automatically** — interface detection
  follows the OS's actual default route, not a name pattern, so it
  doesn't matter which connection type is active.
- **`wirehawk scan`** — a new read-only discovery command; lists devices
  without spoofing anything.
- **Built-in diagnostics** — when no devices are found, it actually
  explains why (AP/client isolation vs. a basic connectivity problem)
  instead of a bare "0 devices" message.
- **Demo mode fallback** — if no real targets are found, or you run
  `wirehawk demo` directly, it shows the full dashboard with realistic
  simulated traffic. Nothing ever just exits with an error.
- **Multi-panel dashboard** — live throughput graph (smooth braille-dot
  rendering, not blocky), a traffic table with per-device trend
  sparklines, and a summary sidebar with session totals and a live
  protocol breakdown.

## Setup

```bash
sudo apt update
sudo apt install -y python3-pip python3-dev libpcap-dev tcpdump
cd wirehawk
sudo pip3 install -e . --break-system-packages
```

This installs the `wirehawk` command system-wide (editable install — any
changes to the source files take effect immediately, no reinstall
needed).

## Usage

```bash
sudo wirehawk demo                                # simulated data, always works
sudo wirehawk scan                                # read-only device discovery
sudo wirehawk run --scan-all                      # monitor every device found
sudo wirehawk run --targets 192.168.1.10,1.15     # monitor specific devices
sudo wirehawk run --iface virbr0 --scan-all       # target a specific interface
                                                 # (e.g. a KVM/VirtualBox virtual network)
```

Interface is auto-detected by default — you only need `--iface` to
override it (e.g. for a virtual lab network, or if you have multiple
active connections and want a specific one).

Press **Ctrl+C** to stop `run` — it restores ARP tables and disables IP
forwarding before exiting. `scan` and `demo` make no network changes at
all, so there's nothing to restore.

## Troubleshooting: "0 devices found"

As of v2.1, the tool diagnoses this itself and prints the likely cause.
In short:

- **Gateway doesn't respond to ping** → basic connectivity problem —
  check you're actually connected, or the network has a captive portal.
- **Gateway responds, but nothing else found** → almost always either
  (a) **AP/client isolation** on the access point (common on phone
  hotspots and enterprise/public Wi-Fi — this is a deliberate security
  feature with no client-side fix), or (b) there genuinely aren't any
  other devices connected right now.

Home broadband routers rarely have AP isolation on by default; phone
hotspots and enterprise networks often do.

## Testing safely without touching anyone else's privacy

If you don't have a second real device to test with, or don't want to
risk any real-world privacy concerns during development, use an
isolated virtual lab instead:

- Install QEMU/KVM + virt-manager (or VirtualBox)
- Create 2 lightweight VMs on an isolated virtual network
  (`virbr0` for KVM, a Host-Only network for VirtualBox)
- Run `sudo wirehawk run --iface virbr0 --scan-all` and generate traffic
  inside the VMs (`ping`, `curl`, etc.)

This gives fully real, reproducible ARP spoofing and packet capture
with zero dependency on real-world network conditions or other
people's devices.

## Project structure

```
wirehawk/
├── setup.py
├── requirements.txt
└── wirehawk/
    ├── __init__.py
    ├── cli.py              # wirehawk run / scan / demo entry point
    ├── network_utils.py    # discovery, gateway/MAC resolution, iface auto-detect
    ├── arp_spoof.py         # ARP spoofing engine + safe restore
    ├── packet_capture.py   # packet sniffing + per-device stats
    ├── dashboard.py         # multi-panel live terminal dashboard
    ├── diagnostics.py       # explains why 0 devices were found
    └── simulate.py          # fake traffic generator for demo mode
```

## Known limitations

- **AP/client isolation** blocks this technique entirely — no
  client-side workaround exists, since it's enforced at the access
  point itself.
- **HTTPS content** is never visible — you can see *that* a device is
  talking HTTPS to a host (via SNI/DNS), never the encrypted content
  itself. This is expected and a good thing for everyone's privacy.
- **Device names** currently show as IPs. A nice extension: MAC vendor
  (OUI) lookup, or letting the user assign friendly names.
- **Stats reset** when the program stops. Logging to CSV/SQLite for
  historical analysis would be a good next step.

## License

This project is licensed under the MIT License — see the `LICENSE` file
for the full text. In short: you're free to use, modify, and
redistribute this code, including commercially, as long as the
copyright notice is kept.

**Note on dependencies:** WireHawk uses Scapy, which is licensed under
the GPLv2. Since Scapy is used here as an external dependency (imported
via `pip`, not bundled or modified as part of this repository), this
project's own code can remain under MIT — GPLv2 only applies to
Scapy's own source, not to code that merely imports it as a library.
If you fork this project and bundle Scapy's source directly rather
than depending on it externally, that would change the licensing
situation — worth keeping in mind if you go that route.

## Responsible disclosure

If you find a security issue with this tool's *own* code (not the ARP
spoofing technique itself, which is inherently a network-interception
method by design), please open an issue or reach out directly rather
than a public exploit writeup, so it can be addressed first.
