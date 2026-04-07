"""
logger.py - Rolling structured log writer (JSON Lines format).
Limits disk usage by keeping only the last MAX_LINES entries.
"""

import json
import os
import threading
from datetime import datetime
from collections import deque

LOG_DIR   = "logs"
LOG_FILE  = os.path.join(LOG_DIR, "traffic_log.jsonl")
MAX_LINES = 10_000

_lock = threading.Lock()

os.makedirs(LOG_DIR, exist_ok=True)


def _trim_log():
    """Keep only the last MAX_LINES lines in the log file."""
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        if len(lines) > MAX_LINES:
            with open(LOG_FILE, "w") as f:
                f.writelines(lines[-MAX_LINES:])
    except FileNotFoundError:
        pass


def log_traffic(entry: dict):
    """Append a traffic entry to the rolling JSON-Lines log."""
    entry.setdefault("logged_at", datetime.now().isoformat())
    line = json.dumps(entry) + "\n"
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(line)


def log_attack(alert: dict, domain: str = "Unknown"):
    """Append an attack alert entry (higher-priority log)."""
    record = {**alert, "domain": domain, "severity": "HIGH"}
    log_traffic(record)
    # Trim periodically (every 500 writes is handled externally via counter)


def load_recent_logs(n: int = 200) -> list:
    """Return the last n log entries as a list of dicts."""
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        entries = []
        for line in reversed(lines[-n:]):
            try:
                entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass
        return list(reversed(entries))
    except FileNotFoundError:
        return []
