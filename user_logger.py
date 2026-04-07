"""
user_logger.py  —  Per-user attack and traffic log storage
Each user's data is stored in  data/logs/{username}_attacks.jsonl
Admin can read all users' logs via get_all_attacks().
"""

import json
import os
import threading
from datetime import datetime

LOG_DIR   = "data/logs"
MAX_LINES = 5_000
_lock     = threading.Lock()
os.makedirs(LOG_DIR, exist_ok=True)


def _user_file(username: str) -> str:
    safe = username.replace("..", "").replace("/", "")
    return os.path.join(LOG_DIR, f"{safe}_attacks.jsonl")


def _append(filepath: str, entry: dict):
    line = json.dumps(entry) + "\n"
    with _lock:
        with open(filepath, "a") as f:
            f.write(line)
        # Trim if too large
        with open(filepath, "r") as f:
            lines = f.readlines()
        if len(lines) > MAX_LINES:
            with open(filepath, "w") as f:
                f.writelines(lines[-MAX_LINES:])


def log_user_attack(username: str, alert: dict, domain: str = "Unknown"):
    """Persist an attack alert attributed to a specific user."""
    entry = {
        **alert,
        "username":  username,
        "domain":    domain,
        "logged_at": datetime.now().isoformat(),
    }
    _append(_user_file(username), entry)


def log_user_traffic(username: str, pkt: dict):
    """Persist a benign traffic entry attributed to a specific user."""
    entry = {**pkt, "username": username, "logged_at": datetime.now().isoformat()}
    _append(_user_file(username), entry)


def get_user_attacks(username: str, limit: int = 200) -> list[dict]:
    """Return recent attack entries for a specific user."""
    path = _user_file(username)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            lines = f.readlines()
        attacks = []
        for line in reversed(lines[-limit:]):
            try:
                e = json.loads(line.strip())
                if e.get("attack_type"):
                    attacks.append(e)
            except json.JSONDecodeError:
                pass
        return list(reversed(attacks))
    except Exception:
        return []


def get_all_attacks(limit: int = 500) -> list[dict]:
    """Admin only: return attacks from ALL users combined, newest first."""
    all_entries = []
    try:
        for fname in os.listdir(LOG_DIR):
            if not fname.endswith("_attacks.jsonl"):
                continue
            path = os.path.join(LOG_DIR, fname)
            with open(path, "r") as f:
                lines = f.readlines()
            for line in lines[-limit:]:
                try:
                    e = json.loads(line.strip())
                    if e.get("attack_type"):
                        all_entries.append(e)
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    all_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return all_entries[:limit]


def get_user_stats(username: str) -> dict:
    """Return summary stats for a user's session."""
    attacks = get_user_attacks(username, limit=5000)
    counts  = {}
    top_ips = {}
    for a in attacks:
        t  = a.get("attack_type", "Unknown")
        ip = a.get("src_ip", "Unknown")
        counts[t]  = counts.get(t, 0)  + 1
        top_ips[ip]= top_ips.get(ip, 0) + 1
    return {
        "total_attacks":   len(attacks),
        "attack_counts":   counts,
        "top_attacker_ips":top_ips,
        "latest_alert":    attacks[-1] if attacks else None,
    }


def get_admin_overview() -> dict:
    """Admin dashboard: per-user attack summaries."""
    overview = {}
    try:
        for fname in os.listdir(LOG_DIR):
            if not fname.endswith("_attacks.jsonl"):
                continue
            uname = fname.replace("_attacks.jsonl", "")
            overview[uname] = get_user_stats(uname)
    except Exception:
        pass
    return overview
