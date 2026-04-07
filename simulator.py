"""
simulator.py - Synthetic traffic generator for demo / testing.
Injects realistic-looking packets into packet_sniffer.packet_store
so the dashboard works without real Scapy privileges.
"""

import random
import time
import threading
from datetime import datetime
from collections import deque

import packet_sniffer as ps

_sim_thread  = None
_stop_event  = threading.Event()

ATTACK_SCENARIOS = [
    # (attack_type, proto, flags, port, burst_count)
    ("SYN Flood",        "TCP", "S",   80,   120),
    ("Port Scan",        "TCP", "S",   None, 20),
    ("Brute Force SSH",  "TCP", "PA",  22,   25),
    ("Brute Force FTP",  "TCP", "PA",  21,   25),
    ("DDoS",             "UDP", "",    53,   320),
    ("DNS Tunneling",    "DNS", "",    53,   50),
]

BENIGN_PORTS  = [80, 443, 8080, 53, 25, 110, 143, 3306, 5432]
PRIVATE_NETS  = ["192.168.1.", "10.0.0.", "172.16.0."]
ATTACK_IPS    = [f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(6)]


def _rand_ip(pool=None):
    if pool:
        return random.choice(pool) + str(random.randint(2, 254))
    base = random.choice(PRIVATE_NETS)
    return base + str(random.randint(2, 254))


def _make_packet(src_ip, proto, flags, port, is_attack=False, attack_type=None):
    dst_port = port if port else random.randint(1024, 65535)
    return {
        "timestamp":   datetime.now().isoformat(),
        "src_ip":      src_ip,
        "dst_ip":      "10.0.0.1",
        "protocol":    proto,
        "dst_port":    dst_port,
        "tcp_flags":   flags,
        "length":      random.randint(40, 1500),
        "attack_type": attack_type if is_attack else None,
    }


def _run():
    scenario_timer = time.time()
    scenario_interval = random.uniform(15, 30)
    active_attack = None
    attack_burst  = 0
    attack_count  = 0

    while not _stop_event.is_set():
        now = time.time()

        # Trigger a new attack scenario periodically
        if now - scenario_timer > scenario_interval:
            active_attack   = random.choice(ATTACK_SCENARIOS)
            attack_burst    = active_attack[4]
            attack_count    = 0
            scenario_timer  = now
            scenario_interval = random.uniform(15, 30)

        # Inject attack burst packets
        if active_attack and attack_count < attack_burst:
            a_type, proto, flags, port, _ = active_attack
            src = random.choice(ATTACK_IPS)
            pkt = _make_packet(src, proto, flags, port, is_attack=True, attack_type=a_type)
            ps.packet_store.append(pkt)
            attack_count += 1
            if attack_count >= attack_burst:
                active_attack = None

        # Inject benign background traffic
        for _ in range(random.randint(1, 5)):
            src = _rand_ip()
            proto = random.choice(["TCP", "UDP", "DNS"])
            flags = random.choice(["S", "PA", "FA", ""]) if proto == "TCP" else ""
            port  = random.choice(BENIGN_PORTS)
            ps.packet_store.append(_make_packet(src, proto, flags, port))

        time.sleep(0.05)


def start():
    global _sim_thread
    _stop_event.clear()
    _sim_thread = threading.Thread(target=_run, daemon=True)
    _sim_thread.start()


def stop():
    _stop_event.set()
