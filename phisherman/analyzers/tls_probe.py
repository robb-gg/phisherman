"""TLS certificate analyzer for phishing detection."""

import asyncio
import logging
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.config import settings

logger = logging.getLogger(__name__)


# Known certificate issuers and their risk profiles
ISSUER_RISK_PROFILES: dict[str, dict[str, Any]] = {
    # Free/automated CAs - commonly abused but legitimate
    "let's encrypt": {"risk_adjustment": 0, "category": "free_ca"},
    "letsencrypt": {"risk_adjustment": 0, "category": "free_ca"},
    "r3": {"risk_adjustment": 0, "category": "free_ca"},  # Let's Encrypt intermediate
    "e1": {"risk_adjustment": 0, "category": "free_ca"},  # Let's Encrypt ECDSA
    "zerossl": {"risk_adjustment": 5, "category": "free_ca"},
    "buypass": {"risk_adjustment": 0, "category": "free_ca"},
    # Enterprise CAs - generally more trustworthy
    "digicert": {"risk_adjustment": -10, "category": "enterprise"},
    "comodo": {"risk_adjustment": -5, "category": "enterprise"},
    "sectigo": {"risk_adjustment": -5, "category": "enterprise"},
    "globalsign": {"risk_adjustment": -10, "category": "enterprise"},
    "godaddy": {"risk_adjustment": -5, "category": "enterprise"},
    "entrust": {"risk_adjustment": -10, "category": "enterprise"},
    "thawte": {"risk_adjustment": -5, "category": "enterprise"},
    "geotrust": {"risk_adjustment": -5, "category": "enterprise"},
    "verisign": {"risk_adjustment": -10, "category": "enterprise"},
    # Cloud providers
    "amazon": {"risk_adjustment": -5, "category": "cloud"},
    "cloudflare": {"risk_adjustment": -5, "category": "cloud"},
    "google trust services": {"risk_adjustment": -10, "category": "cloud"},
    "microsoft": {"risk_adjustment": -10, "category": "cloud"},
}


class TlsProbeAnalyzer(BaseAnalyzer):
    """
    TLS certificate analyzer for phishing detection.

    Analyzes:
    - Certificate validity (expiration, not yet valid)
    - Self-signed certificate detection
    - Hostname mismatch detection
    - Certificate issuer reputation
    - Subject Alternative Names (SANs)
    - Certificate age (newly issued certs are more suspicious)
    """

    def __init__(self, timeout: float | None = None):
        super().__init__(timeout=timeout or settings.http_timeout)
        self._ssl_timeout = min(self.timeout, 10.0)  # Cap SSL timeout at 10s

    @property
    def name(self) -> str:
        return "tls_probe"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.6  # Medium-high weight for TLS analysis

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Perform TLS certificate analysis."""
        parsed = urlparse(url)
        hostname = parsed.netloc
        port = 443

        # Extract hostname and port
        if ":" in hostname:
            parts = hostname.rsplit(":", 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 443

        risk_score = 0.0
        labels: list[str] = []
        evidence: dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "scheme": parsed.scheme,
        }

        # HTTP without TLS
        if parsed.scheme == "http":
            risk_score = 15.0
            labels.append("no_tls")
            evidence["tls_available"] = False
            evidence["warning"] = "Connection is not encrypted"
            return AnalyzerResult(
                analyzer_name=self.name,
                risk_score=risk_score,
                confidence=0.9,
                labels=labels,
                evidence=evidence,
                execution_time_ms=0.0,
            )

        # Perform TLS analysis
        try:
            cert_data = await self._get_certificate(hostname, port)
            evidence["tls_available"] = True
            evidence["certificate"] = cert_data

            # Analyze certificate
            cert_risk, cert_labels = self._analyze_certificate_data(cert_data, hostname)
            risk_score += cert_risk
            labels.extend(cert_labels)

            confidence = 0.85

        except ssl.SSLCertVerificationError as e:
            risk_score += 40.0
            labels.append("ssl_verification_failed")
            evidence["tls_available"] = True
            evidence["ssl_error"] = str(e)
            evidence["error_type"] = "verification"
            confidence = 0.9

        except ssl.SSLError as e:
            risk_score += 30.0
            labels.append("ssl_error")
            evidence["tls_available"] = False
            evidence["ssl_error"] = str(e)
            evidence["error_type"] = "ssl"
            confidence = 0.7

        except (socket.timeout, TimeoutError):
            risk_score += 15.0
            labels.append("tls_timeout")
            evidence["tls_available"] = None
            evidence["error"] = "Connection timeout"
            confidence = 0.5

        except (socket.gaierror, socket.herror) as e:
            # DNS resolution failed
            risk_score += 20.0
            labels.append("dns_resolution_failed")
            evidence["tls_available"] = None
            evidence["error"] = f"DNS error: {e}"
            confidence = 0.6

        except ConnectionRefusedError:
            risk_score += 25.0
            labels.append("connection_refused")
            evidence["tls_available"] = False
            evidence["error"] = "Connection refused"
            confidence = 0.7

        except Exception as e:
            logger.warning(f"TLS probe error for {hostname}: {e}")
            risk_score += 10.0
            labels.append("tls_probe_error")
            evidence["tls_available"] = None
            evidence["error"] = str(e)
            confidence = 0.4

        # Normalize risk score
        risk_score = max(0.0, min(100.0, risk_score))

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,
        )

    async def _get_certificate(self, hostname: str, port: int = 443) -> dict[str, Any]:
        """Get TLS certificate for hostname and extract relevant data."""
        loop = asyncio.get_event_loop()

        def _fetch_cert() -> dict[str, Any]:
            # Create SSL context that doesn't verify (to get cert even if invalid)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self._ssl_timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get binary certificate
                    der_cert = ssock.getpeercert(binary_form=True)
                    # Also get parsed dict version
                    peer_cert = ssock.getpeercert()

                    # Parse with cryptography for detailed analysis
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    return self._extract_cert_data(cert, peer_cert)

        return await loop.run_in_executor(None, _fetch_cert)

    def _extract_cert_data(
        self, cert: x509.Certificate, peer_cert: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Extract relevant data from certificate."""
        data: dict[str, Any] = {}

        # Validity dates (support both old and new cryptography API)
        not_before = (
            getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        )
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

        # Ensure timezone awareness
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=UTC)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=UTC)

        data["not_before"] = not_before.isoformat()
        data["not_after"] = not_after.isoformat()

        # Calculate certificate age
        now = datetime.now(UTC)
        cert_age_days = (now - not_before).days
        days_until_expiry = (not_after - now).days
        data["age_days"] = cert_age_days
        data["days_until_expiry"] = days_until_expiry

        # Subject information
        subject_parts = {}
        for attribute in cert.subject:
            oid_name = attribute.oid._name
            subject_parts[oid_name] = attribute.value
        data["subject"] = subject_parts
        data["common_name"] = subject_parts.get("commonName", "")

        # Issuer information
        issuer_parts = {}
        for attribute in cert.issuer:
            oid_name = attribute.oid._name
            issuer_parts[oid_name] = attribute.value
        data["issuer"] = issuer_parts
        data["issuer_cn"] = issuer_parts.get("commonName", "")
        data["issuer_org"] = issuer_parts.get("organizationName", "")

        # Self-signed check
        data["is_self_signed"] = cert.issuer == cert.subject

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans = []
            for name in san_ext.value:
                if hasattr(name, "value"):
                    sans.append(str(name.value))
            data["sans"] = sans
        except x509.ExtensionNotFound:
            data["sans"] = []

        # Serial number
        data["serial_number"] = format(cert.serial_number, "x")

        # Signature algorithm
        data["signature_algorithm"] = cert.signature_algorithm_oid._name

        return data

    def _analyze_certificate_data(
        self, cert_data: dict[str, Any], hostname: str
    ) -> tuple[float, list[str]]:
        """Analyze certificate data for suspicious properties."""
        risk = 0.0
        labels: list[str] = []

        now = datetime.now(UTC)

        # Check validity period
        not_after = datetime.fromisoformat(
            cert_data["not_after"].replace("Z", "+00:00")
        )
        not_before = datetime.fromisoformat(
            cert_data["not_before"].replace("Z", "+00:00")
        )

        if not_after < now:
            risk += 50.0
            labels.append("expired_certificate")
        elif not_before > now:
            risk += 40.0
            labels.append("not_yet_valid")

        days_until_expiry = cert_data.get("days_until_expiry", 0)
        if 0 < days_until_expiry < 7:
            risk += 10.0
            labels.append("expiring_soon")

        # Check certificate age (newly issued certs are slightly more suspicious)
        cert_age_days = cert_data.get("age_days", 0)
        if cert_age_days is not None and cert_age_days < 7:
            risk += 10.0
            labels.append("newly_issued_cert")
        elif cert_age_days is not None and cert_age_days < 30:
            risk += 5.0
            labels.append("recent_cert")

        # Self-signed check
        if cert_data.get("is_self_signed"):
            risk += 35.0
            labels.append("self_signed")

        # Hostname mismatch check
        common_name = cert_data.get("common_name", "")
        sans = cert_data.get("sans", [])

        hostname_matches = self._check_hostname_match(hostname, common_name, sans)
        if not hostname_matches:
            risk += 40.0
            labels.append("hostname_mismatch")
        else:
            labels.append("hostname_valid")

        # Issuer reputation
        issuer_org = cert_data.get("issuer_org", "").lower()
        issuer_cn = cert_data.get("issuer_cn", "").lower()

        issuer_profile = None
        for issuer_key, profile in ISSUER_RISK_PROFILES.items():
            if issuer_key in issuer_org or issuer_key in issuer_cn:
                issuer_profile = profile
                break

        if issuer_profile:
            risk += issuer_profile["risk_adjustment"]
            labels.append(f"issuer_{issuer_profile['category']}")
        elif cert_data.get("is_self_signed"):
            pass  # Already handled
        else:
            # Unknown issuer - slightly suspicious
            risk += 5.0
            labels.append("issuer_unknown")

        # Check for wildcard certificates (not necessarily bad, but note it)
        if common_name.startswith("*."):
            labels.append("wildcard_cert")

        # Check SANs count (excessive SANs can be suspicious)
        san_count = len(sans)
        if san_count > 100:
            risk += 15.0
            labels.append("excessive_sans")
        elif san_count > 50:
            risk += 5.0
            labels.append("many_sans")

        return risk, labels

    def _check_hostname_match(
        self, hostname: str, common_name: str, sans: list[str]
    ) -> bool:
        """Check if hostname matches certificate CN or SANs."""
        hostname_lower = hostname.lower()

        # Check against CN
        if self._matches_pattern(hostname_lower, common_name.lower()):
            return True

        # Check against SANs
        for san in sans:
            if self._matches_pattern(hostname_lower, san.lower()):
                return True

        return False

    def _matches_pattern(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches a certificate pattern (including wildcards)."""
        if not pattern:
            return False

        # Exact match
        if hostname == pattern:
            return True

        # Wildcard match (e.g., *.example.com)
        if pattern.startswith("*."):
            # Wildcard only matches one level
            suffix = pattern[2:]  # Remove "*."
            # hostname must be longer than suffix (e.g., "sub.example.com" not "example.com")
            if hostname.endswith(suffix) and len(hostname) > len(suffix):
                # Check that there's exactly one level before the suffix
                prefix = hostname[: -(len(suffix) + 1)]  # Remove suffix and dot
                # Prefix must be non-empty and have no dots (single subdomain level)
                if prefix and "." not in prefix:
                    return True

        return False
