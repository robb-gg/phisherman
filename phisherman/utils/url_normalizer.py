"""URL normalization utilities for consistent URL processing."""

import hashlib
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent processing and comparison.

    Performs the following normalizations:
    - Converts scheme to lowercase
    - Converts hostname to lowercase
    - Removes default ports (80 for HTTP, 443 for HTTPS)
    - Removes fragment (#) component
    - Sorts query parameters
    - Removes trailing slash from path (except root)
    - Handles punycode domains
    - Removes common tracking parameters

    Args:
        url: URL to normalize

    Returns:
        Normalized URL string

    Raises:
        ValueError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL format: {e}")

    # Normalize scheme
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {scheme}")

    # Normalize hostname
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL missing hostname")

    hostname = hostname.lower()

    # Handle punycode/IDN
    try:
        hostname = hostname.encode("ascii").decode("ascii")
    except UnicodeDecodeError:
        # Convert to punycode
        hostname = hostname.encode("idna").decode("ascii")

    # Remove default ports
    port = parsed.port
    if port:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

    # Construct netloc
    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"

    # Normalize path
    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)  # Remove duplicate slashes

    # Remove trailing slash (except for root)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    # Normalize query parameters
    query = ""
    if parsed.query:
        query = _normalize_query_params(parsed.query)

    # Remove fragment (not used for security analysis)
    fragment = ""

    # Reconstruct URL
    normalized = urlunparse((scheme, netloc, path, "", query, fragment))

    return normalized


def get_url_hash(url: str) -> str:
    """
    Generate consistent hash for normalized URL.

    Args:
        url: URL to hash

    Returns:
        SHA-256 hex digest of normalized URL
    """
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def extract_domain(url: str) -> str:
    """
    Extract domain from URL.

    Args:
        url: URL to extract domain from

    Returns:
        Domain name (lowercase)

    Raises:
        ValueError: If URL is invalid
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    return parsed.netloc.split(":")[0]  # Remove port if present


def extract_tld(url: str) -> str:
    """
    Extract top-level domain from URL.

    Args:
        url: URL to extract TLD from

    Returns:
        TLD (lowercase)
    """
    domain = extract_domain(url)
    parts = domain.split(".")
    return parts[-1] if parts else ""


def _normalize_query_params(query: str) -> str:
    """Normalize query parameters by sorting and removing tracking params."""
    try:
        # Parse query parameters
        params = parse_qs(query, keep_blank_values=True)

        # Remove common tracking parameters
        tracking_params = {
            # Google Analytics
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "utm_content",
            "gclid",
            "gclsrc",
            "dclid",
            # Facebook
            "fbclid",
            "fb_action_ids",
            "fb_action_types",
            "fb_source",
            # Twitter
            "twclid",
            # Microsoft
            "msclkid",
            # General tracking
            "_ga",
            "_gl",
            "_hsenc",
            "_hsmi",
            "hsCtaTracking",
            "ref",
            "referrer",
            "source",
            "medium",
            "campaign",
        }

        # Filter out tracking parameters
        filtered_params = {
            key: value
            for key, value in params.items()
            if key.lower() not in tracking_params
        }

        if not filtered_params:
            return ""

        # Sort parameters for consistency
        sorted_params = []
        for key in sorted(filtered_params.keys()):
            values = filtered_params[key]
            if isinstance(values, list):
                for value in sorted(values):
                    sorted_params.append((key, value))
            else:
                sorted_params.append((key, values))

        return urlencode(sorted_params, doseq=True)

    except Exception:
        # If parsing fails, return original query
        return query


def is_url_shortener(url: str) -> bool:
    """
    Check if URL uses a known URL shortening service.

    Args:
        url: URL to check

    Returns:
        True if URL appears to be from a shortening service
    """
    try:
        domain = extract_domain(url)

        # Common URL shorteners
        shorteners = {
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "ow.ly",
            "t.co",
            "short.link",
            "tiny.cc",
            "lnk.bio",
            "linktr.ee",
            "rebrand.ly",
            "clicksafe.me",
            "buff.ly",
            "dlvr.it",
            "fb.me",
            "amzn.to",
            "apple.co",
            "youtu.be",
        }

        return domain in shorteners

    except ValueError:
        return False


def get_url_components(url: str) -> dict[str, str]:
    """
    Extract all components of a normalized URL.

    Args:
        url: URL to parse

    Returns:
        Dictionary with URL components
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    return {
        "url": normalized,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname or "",
        "port": str(parsed.port) if parsed.port else "",
        "domain": extract_domain(normalized),
        "tld": extract_tld(normalized),
        "path": parsed.path,
        "query": parsed.query,
        "is_shortener": is_url_shortener(normalized),
        "hash": get_url_hash(normalized),
    }
