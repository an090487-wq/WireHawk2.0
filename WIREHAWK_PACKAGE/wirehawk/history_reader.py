"""
history_reader.py
Reads a CSV log file written by --log (see csv_logger.py) and reports
on one specific device's history after a session has ended — the
file-based, after-the-fact counterpart to the live --focus view and
the GUI's device history dialog.
"""

import csv


def read_device_history(log_path, device):
    """
    Reads a CSV log file and returns every row matching the given
    device (matched against the 'device' column, exact string match).
    Returns a list of dicts (one per matching row, in file order), or
    raises FileNotFoundError / csv.Error for the caller to handle.
    """
    rows = []
    with open(log_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("device") == device:
                rows.append(row)
    return rows


def list_logged_devices(log_path):
    """Returns the distinct set of device names/IPs present in a log
    file, in first-seen order — useful for 'what devices are even in
    this log' when the exact name/IP isn't known."""
    seen = []
    seen_set = set()
    with open(log_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            device = row.get("device")
            if device and device not in seen_set:
                seen_set.add(device)
                seen.append(device)
    return seen
