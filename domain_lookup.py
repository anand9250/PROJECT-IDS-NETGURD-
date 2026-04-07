"""
domain_lookup.py - Reverse DNS lookup with caching to avoid latency.
"""

import socket
from functools import lru_cache


@lru_cache(maxsize=512)
def resolve_ip(ip: str) -> str:
    """
    Reverse-resolve an IP address to a hostname.
    Returns 'Unknown' if resolution fails.
    Cached so each IP is only looked up once per session.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"
