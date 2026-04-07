"""
packet_sniffer.py - Real-time network packet capture using Scapy
Runs in a background thread; appends parsed packet data to a shared deque.
"""

import threading
import time
from collections import deque
from datetime import datetime

# Graceful import of Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Shared packet store (thread-safe deque with max 2000 entries)
packet_store = deque(maxlen=2000)
_sniffer_thread = None
_stop_event = threading.Event()


def _parse_packet(pkt):
    """Extract relevant fields from a captured packet."""
    try:
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "OTHER"
        dst_port = 0
        tcp_flags = ""
        payload_len = len(pkt)

        if pkt.haslayer(TCP):
            protocol = "TCP"
            dst_port = pkt[TCP].dport
            tcp_flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            dst_port = pkt[UDP].dport
            if pkt.haslayer(DNS):
                protocol = "DNS"

        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "length": payload_len,
            "attack_type": None,
        }
    except Exception:
        return None


def _packet_callback(pkt):
    parsed = _parse_packet(pkt)
    if parsed:
        packet_store.append(parsed)


def _sniffer_loop(interface=None, bpf_filter="ip"):
    """Blocking sniff loop; stopped via _stop_event."""
    while not _stop_event.is_set():
        try:
            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=_packet_callback,
                store=False,
                timeout=2,
                stop_filter=lambda _: _stop_event.is_set(),
            )
        except Exception:
            time.sleep(1)


def start_sniffing(interface=None):
    """Start packet sniffing in a daemon thread."""
    global _sniffer_thread
    if not SCAPY_AVAILABLE:
        return False
    _stop_event.clear()
    _sniffer_thread = threading.Thread(
        target=_sniffer_loop, args=(interface,), daemon=True
    )
    _sniffer_thread.start()
    return True


def stop_sniffing():
    """Signal the sniffer thread to stop."""
    _stop_event.set()


def get_packets():
    """Return a snapshot list of currently stored packets."""
    return list(packet_store)


def is_running():
    return _sniffer_thread is not None and _sniffer_thread.is_alive()
