"""
device_aliases.py
Persistent friendly names for devices (IP -> name), stored as JSON in
the user's config directory, so you don't have to keep remembering or
re-typing which raw IP is "mom's phone" across sessions. Separate from
any live session state — this is just a small local name book.
"""

import json
import os
from pathlib import Path


def _config_dir():
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    d = base / "wirehawk"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _aliases_path():
    return _config_dir() / "aliases.json"


def load_aliases():
    """Returns {ip: name}. Never raises — a missing or corrupt file
    just means no aliases yet, not an error."""
    path = _aliases_path()
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_aliases(aliases):
    """Writes atomically (write to a temp file, then rename over the
    real one) so a crash mid-write can't corrupt the existing file."""
    path = _aliases_path()
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(aliases, f, indent=2, sort_keys=True)
    tmp.replace(path)


def set_alias(ip, name):
    aliases = load_aliases()
    aliases[ip] = name
    save_aliases(aliases)
    return aliases


def remove_alias(ip):
    aliases = load_aliases()
    removed = aliases.pop(ip, None)
    save_aliases(aliases)
    return removed is not None


def apply_aliases(device_names):
    """
    Given a dict of {ip: display_name} (usually {ip: ip} before this
    is applied), overlays any saved aliases on top and returns a new
    dict. Devices with no saved alias keep whatever name they already
    had — this never removes or blanks a name, only upgrades it.
    """
    aliases = load_aliases()
    result = dict(device_names)
    for ip in result:
        if ip in aliases:
            result[ip] = aliases[ip]
    return result
