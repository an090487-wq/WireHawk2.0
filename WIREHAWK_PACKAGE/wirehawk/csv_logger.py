"""
csv_logger.py
Logs live traffic stats to a CSV file at regular intervals, so a
session's history can be reviewed later (e.g. opened in a spreadsheet,
or charted for a report) instead of only existing while the dashboard
is on screen.
"""

import csv
import os
import time

CSV_HEADER = [
    "timestamp", "device", "bytes_sent", "bytes_recv", "total_bytes",
    "rate_bytes_per_sec", "top_protocol", "hostname",
]


def run_csv_logger(stats, device_names, filepath, stop_event, interval=5.0):
    """
    Background-thread target: appends one row per active device to the
    CSV file every `interval` seconds, until stop_event is set. Safe to
    run alongside the dashboard — it only reads from the shared,
    thread-safe PacketStats object, same as the dashboard does.

    Appends to an existing file rather than overwriting, and only
    writes the header once (when the file is new/empty), so logging to
    the same path across multiple sessions builds up one combined
    history rather than erasing it each time.
    """
    try:
        file_exists = os.path.exists(filepath) and os.path.getsize(filepath) > 0
    except OSError:
        file_exists = False

    prev_totals = {}
    prev_time = time.time()

    try:
        f = open(filepath, "a", newline="")
    except OSError:
        # Bad path, no permission, disk full, etc. — this runs in a
        # background thread, so there's no good way to surface the
        # error to the live dashboard mid-session. Fail silently rather
        # than crash the thread with an unhandled exception; the
        # person will notice no log file appeared when they look.
        return

    try:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(CSV_HEADER)
            f.flush()

        while not stop_event.is_set():
            stop_event.wait(interval)
            if stop_event.is_set():
                break

            now = time.time()
            dt = max(now - prev_time, 0.001)
            snapshot = stats.snapshot()
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

            try:
                for ip, d in snapshot.items():
                    total = d["bytes_sent"] + d["bytes_recv"]
                    prev = prev_totals.get(ip, total)
                    rate = max((total - prev) / dt, 0)
                    prev_totals[ip] = total

                    top_proto = ""
                    if d["protocols"]:
                        top_proto = max(d["protocols"].items(), key=lambda x: x[1])[0]
                    hostname = d["hostnames"][0] if d["hostnames"] else ""
                    name = device_names.get(ip, ip)

                    writer.writerow([
                        ts, name, d["bytes_sent"], d["bytes_recv"], total,
                        f"{rate:.1f}", top_proto, hostname,
                    ])
                f.flush()
            except OSError:
                break  # e.g. disk went away mid-session — stop quietly
            prev_time = now
    finally:
        f.close()
