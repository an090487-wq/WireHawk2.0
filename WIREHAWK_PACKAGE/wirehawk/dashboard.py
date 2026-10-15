"""
dashboard.py
Full-screen, multi-panel terminal dashboard: a live throughput graph,
a traffic table with per-device sparkline trends, a summary sidebar,
and — when relevant — a diagnosis panel explaining exactly why no
devices could be reached (AP isolation, no gateway, etc.) instead of
just showing an empty table.
"""

import time
import sys
import os
import select
import shutil
import threading
from collections import deque, Counter
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console, Group
from rich.text import Text
from rich.align import Align
from rich import box

try:
    import termios
    import tty
    _HAS_TTY_SUPPORT = True
except ImportError:
    _HAS_TTY_SUPPORT = False

SPARK_BLOCKS = " \u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
BAR_BLOCKS = "\u2588"
HISTORY_LEN = 60
SPARK_LEN = 12

# Hand-built pixel-font banner for WIREHAWK (no figlet dependency).
BANNER = r"""
█   █   █ █████ ████  █████ █   █  ███  █   █   █ █  █
█   █   █   █   █   █ █     █   █ █   █ █   █   █ █ █
█ █ █ █ █   █   ████  ████  █████ █████ █ █ █ █ █ ██
██  █  ██   █   █  █  █     █   █ █   █ ██  █  ██ █ █
█       █ █████ █   █ █████ █   █ █   █ █       █ █  █
"""


class ScrollState:
    """Tracks how far the device table is scrolled, thread-safe since
    the render loop and the keyboard listener both touch it."""

    def __init__(self):
        self.offset = 0
        self.max_offset = 0
        self.lock = threading.Lock()

    def scroll(self, delta):
        with self.lock:
            self.offset = max(0, min(self.offset + delta, self.max_offset))

    def set_max(self, max_offset):
        with self.lock:
            self.max_offset = max(0, max_offset)
            self.offset = min(self.offset, self.max_offset)

    def get(self):
        with self.lock:
            return self.offset, self.max_offset


def _read_key(fd, timeout=0.1):
    """Reads a single keypress or mouse-wheel event. Resolves arrow-key
    escape sequences (ESC [ A / ESC [ B) into 'up'/'down', and SGR mouse
    wheel escape sequences (ESC [ < 64/65 ; x ; y M) into 'mouse_up' /
    'mouse_down'. Returns None if nothing was pressed within the
    timeout."""
    ready, _, _ = select.select([fd], [], [], timeout)
    if not ready:
        return None
    ch = os.read(fd, 1).decode(errors="ignore")
    if ch == "\x1b":
        ready2, _, _ = select.select([fd], [], [], 0.01)
        if not ready2:
            return None
        ch2 = os.read(fd, 1).decode(errors="ignore")
        if ch2 != "[":
            return None
        ready3, _, _ = select.select([fd], [], [], 0.01)
        if not ready3:
            return None
        ch3 = os.read(fd, 1).decode(errors="ignore")
        if ch3 == "A":
            return "up"
        if ch3 == "B":
            return "down"
        if ch3 == "<":
            # SGR mouse sequence: "<Cb;Cx;Cy" followed by 'M' or 'm'
            seq = ""
            while True:
                ready4, _, _ = select.select([fd], [], [], 0.05)
                if not ready4:
                    break
                c = os.read(fd, 1).decode(errors="ignore")
                if c in ("M", "m"):
                    break
                seq += c
            try:
                button_code = int(seq.split(";")[0])
            except (ValueError, IndexError):
                return None
            if button_code & 64:  # wheel event bit
                return "mouse_down" if button_code & 1 else "mouse_up"
        return None
    return ch


_MOUSE_TRACKING_ON = "\x1b[?1000h\x1b[?1006h"
_MOUSE_TRACKING_OFF = "\x1b[?1006l\x1b[?1000l"


def run_key_listener(scroll_state: ScrollState, stop_event: threading.Event):
    """Background thread: puts the terminal in cbreak mode so keys are
    read immediately (no Enter needed), enables mouse-wheel reporting,
    listens for arrow keys, j/k, or the mouse wheel to scroll the
    dashboard, and always restores the terminal's original settings and
    disables mouse tracking on exit — even if the program crashes."""
    if not _HAS_TTY_SUPPORT or not sys.stdin.isatty():
        return  # not a real interactive terminal — nothing to listen to

    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        return

    try:
        tty.setcbreak(fd)
        sys.stdout.write(_MOUSE_TRACKING_ON)
        sys.stdout.flush()
        while not stop_event.is_set():
            key = _read_key(fd, timeout=0.15)
            if key in ("up", "k", "mouse_up"):
                scroll_state.scroll(-3 if key == "mouse_up" else -1)
            elif key in ("down", "j", "mouse_down"):
                scroll_state.scroll(3 if key == "mouse_down" else 1)
    finally:
        sys.stdout.write(_MOUSE_TRACKING_OFF)
        sys.stdout.flush()
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def format_bytes(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def sparkline(values, width=SPARK_LEN):
    vals = list(values)[-width:]
    if not vals:
        return " " * width
    vmax = max(vals) or 1
    chars = []
    for v in vals:
        idx = min(int((v / vmax) * (len(SPARK_BLOCKS) - 1)), len(SPARK_BLOCKS) - 1)
        chars.append(SPARK_BLOCKS[idx])
    return "".join(chars).rjust(width)


def proportional_bar(fraction, width=14):
    filled = max(0, min(width, round(fraction * width)))
    return BAR_BLOCKS * filled + " " * (width - filled)


def build_header(iface, iface_type, elapsed, device_count, mode_label="ACTIVE"):
    banner_text = Text(BANNER, style="bold bright_red", justify="left")
    status = Text.assemble(
        ("[*] ", "bright_red"),
        (f"iface: {iface} ({iface_type})", "red"),
        ("  ::  ", "dark_red"), ("status: ", "red"), (mode_label, "bold bright_red"),
        ("  ::  ", "dark_red"), (f"devices: {device_count}", "red"),
        ("  ::  ", "dark_red"),
        (f"uptime: {int(elapsed // 60):02d}:{int(elapsed % 60):02d}", "red"),
    )
    return Panel(
        Align.left(banner_text.append("\n").append(status)),
        border_style="dark_red", box=box.HEAVY,
        title="[bold bright_red]WIREHAWK[/bold bright_red]",
        subtitle="[dark_red]network traffic analyzer[/dark_red]",
        title_align="left", subtitle_align="right", padding=(0, 1),
    )


def build_diagnosis_panel(diagnosis_lines):
    """Shown when real device discovery found nothing — explains the
    actual reason (AP isolation, no gateway, etc.) directly on the
    dashboard, instead of silently switching to demo mode with no
    explanation visible once the screen takes over."""
    body = Text()
    for i, line in enumerate(diagnosis_lines):
        style = "bold yellow" if i == 0 else "yellow"
        body.append(line, style=style)
        if i != len(diagnosis_lines) - 1:
            body.append("\n")
    return Panel(
        body, border_style="yellow", box=box.HEAVY,
        title="[bold yellow]WHY NO REAL DEVICES?[/bold yellow]",
        title_align="left", padding=(0, 1),
    )


# Braille dot-bit mapping (2 columns x 4 rows per character cell) —
# gives 8x finer resolution than solid block characters, producing a
# smooth curve instead of a blocky stair-step look.
_BRAILLE_BITS = {
    (0, 0): 0x01, (0, 1): 0x02, (0, 2): 0x04, (0, 3): 0x40,
    (1, 0): 0x08, (1, 1): 0x10, (1, 2): 0x20, (1, 3): 0x80,
}


def _resample(vals, n):
    """Linearly interpolate vals to exactly n points, for smooth curves
    regardless of how much history data exists yet."""
    if not vals:
        return [0] * n
    if len(vals) == 1:
        return vals * n
    if len(vals) == n:
        return list(vals)
    out = []
    last = len(vals) - 1
    for i in range(n):
        pos = i * last / (n - 1)
        lo = int(pos)
        hi = min(lo + 1, last)
        frac = pos - lo
        out.append(vals[lo] * (1 - frac) + vals[hi] * frac)
    return out


def render_area_graph(history, width=64, height=6):
    """
    Renders a smooth braille-dot area graph (like plotext/asciichart),
    not a blocky stair-step. Each character cell holds a 2x4 dot grid,
    so the effective resolution is width*2 x height*4 points — this is
    what gives it a clean curved silhouette instead of chunky steps.
    """
    vals = list(history)
    vmax = max(vals) if vals and max(vals) > 0 else 1

    dot_w = width * 2
    dot_h = height * 4
    samples = _resample(vals, dot_w)
    filled_dots = [min(max(int(round((v / vmax) * dot_h)), 0), dot_h) for v in samples]

    rows = []
    for cell_row in range(height):
        row_text = Text()
        for cell_col in range(width):
            bits = 0
            for dx in range(2):
                dot_x = cell_col * 2 + dx
                col_filled = filled_dots[dot_x] if dot_x < dot_w else 0
                for dy in range(4):
                    dot_y = cell_row * 4 + dy  # 0 = top of graph
                    if dot_y >= (dot_h - col_filled):
                        bits |= _BRAILLE_BITS[(dx, dy)]
            if bits:
                ch = chr(0x2800 + bits)
                style = "bright_red" if cell_row <= height // 3 else "red"
                row_text.append(ch, style=style)
            else:
                row_text.append(" ")
        rows.append(row_text)

    top_label = format_bytes(vmax) + "/s"
    zero_label = "0"
    axis_width = max(len(top_label), len(zero_label)) + 1

    graph = Text()
    for i, row in enumerate(rows):
        if i == 0:
            label = top_label.rjust(axis_width - 1) + "\u2524"
        elif i == height - 1:
            label = zero_label.rjust(axis_width - 1) + "\u2524"
        else:
            label = " " * (axis_width - 1) + "\u2502"
        graph.append(label, style="dark_red")
        graph.append(row)
        if i != height - 1:
            graph.append("\n")

    return graph


def build_graph(agg_history, current_rate, peak_rate):
    graph = render_area_graph(agg_history, width=64, height=6)
    label = Text.assemble(
        ("  now: ", "red"), (f"{format_bytes(current_rate)}/s", "bold bright_red"),
        ("    peak: ", "red"), (f"{format_bytes(peak_rate)}/s", "bold bright_red"),
    )
    body = Text.assemble(graph, "\n", label)
    return Panel(
        body, border_style="dark_red", box=box.HEAVY,
        title="[bold bright_red]THROUGHPUT[/bold bright_red]",
        title_align="left", padding=(0, 1),
    )


def build_table(stats_snapshot, device_names, elapsed, rate_history, empty_reason=None):
    table = Table(
        show_header=True, header_style="bold bright_red",
        border_style="dark_red", box=box.SIMPLE_HEAVY,
        expand=True, padding=(0, 1),
    )
    table.add_column("TARGET", no_wrap=True, overflow="ellipsis", ratio=2)
    table.add_column("TREND", no_wrap=True, ratio=2)
    table.add_column("TX", justify="right", no_wrap=True, ratio=1)
    table.add_column("RX", justify="right", no_wrap=True, ratio=1)
    table.add_column("RATE (up/down)", justify="right", no_wrap=True, ratio=2)
    table.add_column("PROTO", no_wrap=True, overflow="ellipsis", ratio=2)
    table.add_column("HOST", no_wrap=True, overflow="ellipsis", ratio=2)

    all_rows = sorted(
        stats_snapshot.items(),
        key=lambda kv: kv[1]["bytes_sent"] + kv[1]["bytes_recv"],
        reverse=True,
    )

    if not all_rows:
        placeholder = empty_reason or "-- awaiting traffic --"
        table.add_row(f"[dim]{placeholder}[/dim]", "", "", "", "", "", "")

    for rank, (ip, d) in enumerate(all_rows):
        name = device_names.get(ip, ip)
        up_speed = d["bytes_sent"] / elapsed if elapsed > 0 else 0
        down_speed = d["bytes_recv"] / elapsed if elapsed > 0 else 0
        top_protocols = " ".join(
            f"{p}x{c}" for p, c in
            sorted(d["protocols"].items(), key=lambda x: -x[1])[:2]
        )
        hosts = ", ".join(d["hostnames"][:1]) or "-"
        trend = sparkline(rate_history.get(ip, []))

        # Every device row uses the same shade — only the sort order
        # (busiest first) indicates rank, not a fading color.
        shade = "bright_red"
        table.add_row(
            f"[{shade}]\u25b8 {name}[/{shade}]",
            f"[{shade}]{trend}[/{shade}]",
            f"[{shade}]{format_bytes(d['bytes_sent'])}[/{shade}]",
            f"[{shade}]{format_bytes(d['bytes_recv'])}[/{shade}]",
            f"[{shade}]{format_bytes(up_speed)}/s / {format_bytes(down_speed)}/s[/{shade}]",
            f"[{shade}]{top_protocols}[/{shade}]",
            f"[{shade}]{hosts}[/{shade}]",
        )

    return Panel(
        table, border_style="dark_red", box=box.HEAVY,
        title="[bold bright_red]LIVE TRAFFIC[/bold bright_red]",
        title_align="left", padding=(0, 0),
    )


def build_summary(stats_snapshot, elapsed, device_count, total_bytes_session):
    lines = []
    lines.append(Text.assemble(("DEVICES SEEN     ", "red"), (f"{device_count}", "bold bright_red")))
    lines.append(Text.assemble(("SESSION TOTAL    ", "red"), (f"{format_bytes(total_bytes_session)}", "bold bright_red")))
    avg_rate = total_bytes_session / elapsed if elapsed > 0 else 0
    lines.append(Text.assemble(("AVG THROUGHPUT   ", "red"), (f"{format_bytes(avg_rate)}/s", "bold bright_red")))

    if stats_snapshot:
        busiest_ip, busiest_d = max(
            stats_snapshot.items(),
            key=lambda kv: kv[1]["bytes_sent"] + kv[1]["bytes_recv"],
        )
        busiest_total = busiest_d["bytes_sent"] + busiest_d["bytes_recv"]
        lines.append(Text(""))
        lines.append(Text("TOP CONSUMER", style="bold bright_red"))
        lines.append(Text.assemble(("  ", ""), (busiest_ip, "bright_red")))
        lines.append(Text.assemble(("  ", ""), (format_bytes(busiest_total), "red")))

    proto_totals = Counter()
    for d in stats_snapshot.values():
        for p, c in d["protocols"].items():
            proto_totals[p] += c
    total_proto = sum(proto_totals.values()) or 1

    if proto_totals:
        lines.append(Text(""))
        lines.append(Text("PROTOCOL MIX", style="bold bright_red"))
        for proto, count in proto_totals.most_common(5):
            frac = count / total_proto
            bar = proportional_bar(frac, width=12)
            lines.append(Text.assemble(
                (f"{proto:<6}", "red"), (bar, "bright_red"), (f" {frac*100:>4.0f}%", "dark_red"),
            ))

    grouped = Text()
    for i, line in enumerate(lines):
        grouped.append(line)
        if i != len(lines) - 1:
            grouped.append("\n")

    return Panel(
        grouped, border_style="dark_red", box=box.HEAVY,
        title="[bold bright_red]SUMMARY[/bold bright_red]",
        title_align="left", padding=(0, 1),
    )


def build_focus_panel(ip, name, device_data, elapsed, history_entries):
    """A single-device deep-dive view — the live, in-terminal equivalent
    of double-clicking a device in the GUI: current stats plus a
    chronological hostname history (DNS + TLS SNI), instead of the
    normal multi-device table+summary."""
    if device_data is None:
        body = Text(f"-- no traffic observed yet for {ip} --", style="dim")
        return Panel(
            body, border_style="dark_red", box=box.HEAVY,
            title=f"[bold bright_red]FOCUS: {name}[/bold bright_red]",
            title_align="left", padding=(0, 1),
        )

    up = device_data["bytes_sent"] / elapsed if elapsed > 0 else 0
    down = device_data["bytes_recv"] / elapsed if elapsed > 0 else 0
    total = device_data["bytes_sent"] + device_data["bytes_recv"]

    stats_text = Text.assemble(
        ("TARGET   ", "red"), (f"{name}\n", "bold bright_red"),
        ("TX       ", "red"), (f"{format_bytes(device_data['bytes_sent'])}\n", "bright_red"),
        ("RX       ", "red"), (f"{format_bytes(device_data['bytes_recv'])}\n", "bright_red"),
        ("TOTAL    ", "red"), (f"{format_bytes(total)}\n", "bright_red"),
        ("RATE     ", "red"), (f"{format_bytes(up)}/s up / {format_bytes(down)}/s down", "bright_red"),
    )

    proto_totals = device_data.get("protocols", {})
    if proto_totals:
        proto_text = Text("\n\nPROTOCOLS  ", style="red")
        total_proto = sum(proto_totals.values()) or 1
        parts = [f"{p} {c/total_proto*100:.0f}%" for p, c in
                 sorted(proto_totals.items(), key=lambda x: -x[1])[:6]]
        proto_text.append("  ".join(parts), style="bright_red")
        stats_text = Text.assemble(stats_text, proto_text)

    history_table = Table(
        show_header=True, header_style="bold bright_red", border_style="dark_red",
        box=box.SIMPLE_HEAVY, expand=True,
    )
    history_table.add_column("TIME", no_wrap=True, width=10)
    history_table.add_column("PROTO", no_wrap=True, width=8)
    history_table.add_column("HOSTNAME", no_wrap=True, overflow="ellipsis")

    if not history_entries:
        history_table.add_row("[dim]-- no hostnames observed yet (DNS/HTTPS) --[/dim]", "", "")
    else:
        for ts, hostname, proto in reversed(history_entries):
            time_str = time.strftime("%H:%M:%S", time.localtime(ts))
            history_table.add_row(time_str, proto, hostname)

    body = Group(stats_text, Text(""), history_table)
    return Panel(
        body, border_style="dark_red", box=box.HEAVY,
        title=f"[bold bright_red]FOCUS: {name}[/bold bright_red]",
        subtitle=f"[dark_red]{len(history_entries)} hostname(s) recorded[/dark_red]",
        subtitle_align="right", title_align="left", padding=(0, 1),
    )


def build_footer():
    text = Text.assemble(
        (" [CTRL+C] ", "bold bright_red"), ("terminate    ", "red"),
        (" [\u2191/\u2193, j/k, or mouse wheel] ", "bold bright_red"), ("scroll    ", "red"),
        (" [*] ", "bright_red"), ("WIREHAWK v2.1 — network traffic analyzer", "dark_red"),
    )
    return Panel(Align.left(text), border_style="dark_red", box=box.HEAVY, padding=(0, 1))


def build_full_content(iface, iface_type, elapsed, stats_snapshot, device_names,
                        agg_history, current_rate, peak_rate, rate_history,
                        total_bytes_session, mode_label="ACTIVE",
                        diagnosis_lines=None, empty_reason=None,
                        focus_ip=None, focus_history=None):
    """Builds the entire dashboard as one tall renderable at its natural
    height — no fixed-size regions. This is what makes whole-dashboard
    scrolling possible: nothing is ever squeezed or clipped to fit a
    small terminal, since we render full size first and scroll a
    window over it afterward. When focus_ip is given, the normal
    multi-device table+summary is replaced with a single-device
    deep-dive view (live stats + hostname history for that one IP)."""
    device_count = 1 if focus_ip else len(stats_snapshot)
    parts = [build_header(iface, iface_type, elapsed, device_count, mode_label)]
    if diagnosis_lines:
        parts.append(build_diagnosis_panel(diagnosis_lines))
    parts.append(build_graph(agg_history, current_rate, peak_rate))

    if focus_ip:
        name = device_names.get(focus_ip, focus_ip)
        device_data = stats_snapshot.get(focus_ip)
        parts.append(build_focus_panel(focus_ip, name, device_data, elapsed, focus_history or []))
    else:
        table_panel = build_table(stats_snapshot, device_names, elapsed, rate_history,
                                   empty_reason=empty_reason)
        summary_panel = build_summary(stats_snapshot, elapsed, len(stats_snapshot), total_bytes_session)
        grid = Table.grid(expand=True)
        grid.add_column(ratio=3)
        grid.add_column(ratio=1)
        grid.add_row(table_panel, summary_panel)
        parts.append(grid)

    parts.append(build_footer())
    return Group(*parts)


def run_dashboard(stats, device_names, stop_event, refresh_interval=1.0,
                   iface="wlan0", iface_type="Unknown", mode_label="ACTIVE",
                   diagnosis_lines=None, empty_reason=None, focus_ip=None):
    """Blocks and continuously renders the multi-panel dashboard until
    stop_event is set. The whole dashboard — not just the device table
    — is scrollable with arrow keys or j/k: it's rendered at its full
    natural height, then a window matching the current terminal size is
    sliced out and shown, so shrinking the terminal never cuts content
    off or squeezes panels — you just scroll to see the rest. When
    diagnosis_lines is given, a persistent panel explains why real
    devices weren't found (e.g. AP isolation). When focus_ip is given,
    the dashboard switches to a single-device deep-dive view — the
    graph tracks that device's own rate instead of total network
    throughput, and a live hostname history table is shown."""
    start_time = time.time()
    prev_totals = {}
    prev_time = start_time
    agg_history = deque(maxlen=HISTORY_LEN)
    rate_history = {}
    peak_rate = 0.0

    scroll_state = ScrollState()
    key_thread = threading.Thread(
        target=run_key_listener, args=(scroll_state, stop_event), daemon=True,
    )
    key_thread.start()

    render_console = Console(color_system="truecolor", force_terminal=True)

    with Live(refresh_per_second=4, screen=True) as live:
        while not stop_event.is_set():
            now = time.time()
            elapsed = now - start_time
            dt = max(now - prev_time, 0.001)
            snapshot = stats.snapshot()

            total_rate = 0.0
            total_bytes_session = 0
            for ip, d in snapshot.items():
                total = d["bytes_sent"] + d["bytes_recv"]
                total_bytes_session += total
                prev = prev_totals.get(ip, total)
                rate = max((total - prev) / dt, 0)
                total_rate += rate
                rate_history.setdefault(ip, deque(maxlen=HISTORY_LEN)).append(rate)
                prev_totals[ip] = total

            # In focus mode, the graph tracks just that one device's
            # rate instead of the whole network's combined throughput.
            graph_value = rate_history.get(focus_ip, deque())[-1] if focus_ip and rate_history.get(focus_ip) else (
                0.0 if focus_ip else total_rate
            )
            peak_rate = max(peak_rate, graph_value)
            agg_history.append(graph_value)
            prev_time = now

            focus_history = stats.device_history(focus_ip) if focus_ip else None

            term_size = shutil.get_terminal_size(fallback=(100, 30))
            content = build_full_content(
                iface, iface_type, elapsed, snapshot, device_names,
                agg_history, graph_value, peak_rate, rate_history, total_bytes_session,
                mode_label=mode_label, diagnosis_lines=diagnosis_lines,
                empty_reason=empty_reason, focus_ip=focus_ip, focus_history=focus_history,
            )

            render_console.size = (term_size.columns, term_size.lines)
            with render_console.capture() as cap:
                render_console.print(content)
            all_lines = cap.get().splitlines()
            total_lines = len(all_lines)

            reserve = 1  # bottom line reserved for the scroll status bar
            visible_height = max(term_size.lines - reserve, 3)
            scroll_state.set_max(max(0, total_lines - visible_height))
            offset, max_offset = scroll_state.get()

            window = all_lines[offset:offset + visible_height]
            body_text = Text.from_ansi("\n".join(window))

            if max_offset > 0:
                shown_end = min(offset + visible_height, total_lines)
                status = Text(
                    f" lines {offset + 1}-{shown_end} of {total_lines}"
                    f"  —  \u2191/\u2193, j/k, or mouse wheel to scroll ",
                    style="bold bright_red on dark_red",
                )
                display = Text("\n").join([body_text, status])
            else:
                display = body_text

            live.update(display)
            time.sleep(refresh_interval)
