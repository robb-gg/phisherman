"""
SSRF Protection utilities.

Prevents Server-Side Request Forgery by validating URLs before making requests.
"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Private IP ranges that should never be accessed
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 localhost
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Dangerous hostnames
BLOCKED_HOSTNAMES = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",  # GCP metadata
    "169.254.169.254",  # AWS/GCP/Azure metadata
    "metadata.azure.internal",
]

# Blocked ports (internal services)
BLOCKED_PORTS = [22, 23, 25, 445, 3306, 5432, 6379, 27017]


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_IP_RANGES)
    except ValueError:
        return False


def is_safe_url(url: str) -> tuple[bool, str]:
    """
    Validate that a URL is safe to request (not targeting internal resources).

    Returns:
        tuple: (is_safe, reason)
    """
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ("http", "https"):
            return False, f"Blocked scheme: {parsed.scheme}"

        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname in URL"

        # Check for blocked hostnames
        hostname_lower = hostname.lower()
        if hostname_lower in BLOCKED_HOSTNAMES:
            return False, f"Blocked hostname: {hostname}"

        # Check for IP address in hostname
        try:
            ip = ipaddress.ip_address(hostname)
            if is_private_ip(str(ip)):
                return False, f"Private IP address: {hostname}"
        except ValueError:
            # Not an IP, it's a hostname - resolve it
            try:
                resolved_ips = socket.gethostbyname_ex(hostname)[2]
                for ip_str in resolved_ips:
                    if is_private_ip(ip_str):
                        return False, f"Hostname resolves to private IP: {ip_str}"
            except socket.gaierror:
                # DNS resolution failed - might be suspicious but allow
                pass

        # Check port
        port = parsed.port
        if port and port in BLOCKED_PORTS:
            return False, f"Blocked port: {port}"

        return True, "URL is safe"

    except Exception as e:
        return False, f"Validation error: {str(e)}"


def sanitize_redirect_url(redirect_url: str, original_url: str) -> tuple[bool, str]:
    """
    Validate a redirect URL is safe to follow.

    Applies stricter rules than is_safe_url for redirects.
    """
    # First check basic safety
    is_safe, reason = is_safe_url(redirect_url)
    if not is_safe:
        return False, reason

    # Additional redirect-specific checks
    parsed = urlparse(redirect_url)

    # Reject data: URLs (can be used for attacks)
    if parsed.scheme == "data":
        return False, "Data URLs not allowed in redirects"

    # Reject javascript: URLs
    if parsed.scheme == "javascript":
        return False, "JavaScript URLs not allowed"

    return True, "Redirect URL is safe"

