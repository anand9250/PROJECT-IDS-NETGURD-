"""
auth.py  —  User authentication system for NetGuard IDS
Handles: registration, login, password hashing, role management
Roles: 'admin' (sees all users' data) | 'user' (sees own data only)
"""

import json
import os
import hashlib
import secrets
import threading
from datetime import datetime

AUTH_FILE = "data/users.json"
_lock     = threading.Lock()

os.makedirs("data", exist_ok=True)

# ── Seed admin account on first run ────────────────────────────────────────
def _init_db():
    if not os.path.exists(AUTH_FILE):
        admin = {
            "admin": {
                "username":   "admin",
                "password":   _hash_password("admin123"),
                "role":       "admin",
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "active":     True,
            }
        }
        _save(admin)

def _load() -> dict:
    try:
        with open(AUTH_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _save(users: dict):
    with open(AUTH_FILE, "w") as f:
        json.dump(users, f, indent=2)

def _hash_password(password: str) -> str:
    salt = "netguard_ids_salt_2025"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

# ── Public API ──────────────────────────────────────────────────────────────

def register_user(username: str, password: str, role: str = "user") -> tuple[bool, str]:
    """
    Register a new user. Returns (success, message).
    Only admin can create admin accounts.
    """
    username = username.strip().lower()
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if not username.isalnum():
        return False, "Username must contain only letters and numbers."

    with _lock:
        users = _load()
        if username in users:
            return False, f"Username '{username}' is already taken."
        users[username] = {
            "username":   username,
            "password":   _hash_password(password),
            "role":       role,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "active":     True,
        }
        _save(users)
    return True, f"Account '{username}' created successfully."


def login_user(username: str, password: str) -> tuple[bool, dict | str]:
    """
    Authenticate a user. Returns (success, user_dict) or (False, error_msg).
    """
    username = username.strip().lower()
    with _lock:
        users = _load()
    user = users.get(username)
    if not user:
        return False, "Invalid username or password."
    if not user.get("active", True):
        return False, "This account has been disabled. Contact the admin."
    if user["password"] != _hash_password(password):
        return False, "Invalid username or password."

    # Update last_login
    with _lock:
        users = _load()
        users[username]["last_login"] = datetime.now().isoformat()
        _save(users)

    return True, {
        "username":   user["username"],
        "role":       user["role"],
        "created_at": user["created_at"],
        "last_login": datetime.now().isoformat(),
    }


def get_all_users() -> list[dict]:
    """Return all users (for admin panel) — passwords excluded."""
    users = _load()
    return [
        {k: v for k, v in u.items() if k != "password"}
        for u in users.values()
    ]


def set_user_active(username: str, active: bool) -> bool:
    """Enable or disable a user account (admin only)."""
    with _lock:
        users = _load()
        if username not in users:
            return False
        users[username]["active"] = active
        _save(users)
    return True


def delete_user(username: str) -> tuple[bool, str]:
    """Delete a user account (admin only, cannot delete admin)."""
    if username == "admin":
        return False, "Cannot delete the admin account."
    with _lock:
        users = _load()
        if username not in users:
            return False, "User not found."
        del users[username]
        _save(users)
    return True, f"User '{username}' deleted."


def change_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """Allow a user to change their own password."""
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters."
    with _lock:
        users = _load()
        if username not in users:
            return False, "User not found."
        if users[username]["password"] != _hash_password(old_password):
            return False, "Current password is incorrect."
        users[username]["password"] = _hash_password(new_password)
        _save(users)
    return True, "Password changed successfully."


_init_db()
