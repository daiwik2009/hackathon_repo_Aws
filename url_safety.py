"""
AI Bodyguard - URL safety guard.

Shared SSRF (server-side request forgery) protection.

Because AI Bodyguard's entire job is to fetch attacker-influenced URLs
on the server's behalf -- both the URL a caller submits directly to
/scan, and every URL the Investigator later discovers *inside* a
scanned page and recursively follows -- every single fetch in this
codebase must be checked here first. A page under investigation can
freely contain a link to http://169.254.169.254/ (cloud metadata) or
http://localhost:6379/ (an internal service); nothing about that link
looks unusual to the detector's keyword rules, so this has to be
enforced at the network layer, not the content layer.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

# Hostnames that are refused outright, regardless of what they resolve to.
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
}


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Can't parse it -> fail closed.
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_safe_url(url: str) -> tuple[bool, str]:
    """
    Decide whether a URL is safe for AI Bodyguard to fetch.

    Returns
    -------
    (is_safe, reason):
        reason is "" when the URL is safe, otherwise a short machine
        -readable code explaining the rejection (useful for logs and
        for the AI-requested-investigation rejection path).
    """

    if not url:
        return False, "empty_url"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "unparseable_url"

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"disallowed_scheme:{parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, "missing_hostname"

    if hostname.lower() in BLOCKED_HOSTNAMES:
        return False, "blocked_hostname"

    # Resolve DNS ourselves and check *every* returned address. This
    # blocks the common case of an attacker-controlled hostname that
    # simply resolves to a private/internal IP (e.g. a DNS record
    # pointed at 127.0.0.1 or a RFC1918 address).
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, "dns_resolution_failed"

    for _family, _type, _proto, _canon, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        if _is_blocked_ip(ip_str):
            return False, f"blocked_ip:{ip_str}"

    return True, ""


# ----------------------------------------------------------------
# KNOWN LIMITATION
# ----------------------------------------------------------------
# This performs a resolve-then-check, not a resolve-and-pin. A DNS
# record that resolves to a public IP at check time but to a private
# IP a few milliseconds later at request time (DNS rebinding) would
# slip through. Closing that gap fully requires the HTTP client used
# by Static/scanner.py and Dynamic's Playwright fetch to pin and reuse
# the exact IP this function validated, rather than re-resolving the
# hostname. That wiring lives in the scanner modules, which weren't
# available for this review -- flagging it here so it isn't lost.