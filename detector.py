"""
detector.py - Rule-based + threshold attack detection engine.
Uses time-window counters to avoid false positives.
"""

import time
from collections import defaultdict, deque
from datetime import datetime

# ── Thresholds (tune as needed) ────────────────────────────────────────────
SYN_FLOOD_THRESHOLD   = 100   # SYN packets from one IP in TIME_WINDOW seconds
PORT_SCAN_THRESHOLD   = 15    # unique destination ports in TIME_WINDOW seconds
BRUTE_FORCE_THRESHOLD = 20    # connection attempts to auth port per IP in window
DDOS_THRESHOLD        = 300   # total packets from one IP in TIME_WINDOW seconds
DNS_TUNNEL_THRESHOLD  = 40    # DNS queries from one IP in TIME_WINDOW seconds
TIME_WINDOW           = 10    # seconds for sliding window

BRUTE_FORCE_PORTS = {22, 21, 3389}  # SSH, FTP, RDP

# ── Per-IP sliding window counters ─────────────────────────────────────────
_syn_times     = defaultdict(deque)   # ip -> deque of timestamps
_port_times    = defaultdict(lambda: defaultdict(deque))  # ip -> port -> timestamps
_brute_times   = defaultdict(deque)
_ddos_times    = defaultdict(deque)
_dns_times     = defaultdict(deque)

# Already-raised alerts (ip, attack_type) -> last alert epoch
_alert_cooldown = {}
ALERT_COOLDOWN_SEC = 30  # don't re-alert the same ip+type for 30s


def _prune(dq: deque, window: float):
    """Remove timestamps older than window seconds."""
    cutoff = time.time() - window
    while dq and dq[0] < cutoff:
        dq.popleft()


def _should_alert(ip: str, attack: str) -> bool:
    key = (ip, attack)
    now = time.time()
    last = _alert_cooldown.get(key, 0)
    if now - last > ALERT_COOLDOWN_SEC:
        _alert_cooldown[key] = now
        return True
    return False


def analyze_packet(pkt: dict) -> dict | None:
    """
    Analyse a single parsed packet dict.
    Returns an alert dict if an attack is detected, else None.
    """
    src_ip   = pkt.get("src_ip", "")
    dst_port = pkt.get("dst_port", 0)
    protocol = pkt.get("protocol", "")
    flags    = pkt.get("tcp_flags", "")
    now      = time.time()

    attack_type = None

    # ── 1. SYN Flood ───────────────────────────────────────────────────────
    if protocol == "TCP" and "S" in flags and "A" not in flags:
        dq = _syn_times[src_ip]
        dq.append(now)
        _prune(dq, TIME_WINDOW)
        if len(dq) >= SYN_FLOOD_THRESHOLD:
            attack_type = "SYN Flood"

    # ── 2. Port Scan ───────────────────────────────────────────────────────
    if protocol == "TCP" and dst_port:
        dq = _port_times[src_ip][dst_port]
        dq.append(now)
        _prune(dq, TIME_WINDOW)
        unique_ports = len(_port_times[src_ip])
        # prune stale port entries
        stale = [p for p, d in _port_times[src_ip].items() if not d]
        for p in stale:
            del _port_times[src_ip][p]
        if unique_ports >= PORT_SCAN_THRESHOLD and not attack_type:
            attack_type = "Port Scan"

    # ── 3. Brute Force (SSH/FTP/RDP) ───────────────────────────────────────
    if protocol == "TCP" and dst_port in BRUTE_FORCE_PORTS:
        dq = _brute_times[src_ip]
        dq.append(now)
        _prune(dq, TIME_WINDOW)
        if len(dq) >= BRUTE_FORCE_THRESHOLD and not attack_type:
            service = {22: "SSH", 21: "FTP", 3389: "RDP"}.get(dst_port, "Auth")
            attack_type = f"Brute Force ({service})"

    # ── 4. DDoS ────────────────────────────────────────────────────────────
    dq = _ddos_times[src_ip]
    dq.append(now)
    _prune(dq, TIME_WINDOW)
    if len(dq) >= DDOS_THRESHOLD and not attack_type:
        attack_type = "DDoS"

    # ── 5. DNS Tunneling ───────────────────────────────────────────────────
    if protocol == "DNS":
        dq = _dns_times[src_ip]
        dq.append(now)
        _prune(dq, TIME_WINDOW)
        if len(dq) >= DNS_TUNNEL_THRESHOLD and not attack_type:
            attack_type = "DNS Tunneling"

    if attack_type and _should_alert(src_ip, attack_type):
        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "attack_type": attack_type,
        }

    return None
