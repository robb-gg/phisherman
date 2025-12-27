"""SSL/TLS certificate analysis."""

import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SSLAnalysisResult:
    """Result from SSL analysis."""

    risk_score: float = 0.0
    labels: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


class SSLAnalyzer:
    """
    Analyzes SSL/TLS certificates for suspicious patterns.

    Checks for:
    - Self-signed certificates
    - Certificate issuer reputation
    - Certificate validity
    - Hostname mismatches
    """

    async def analyze(self, hostname: str) -> SSLAnalysisResult:
        """
        Analyze SSL certificate for the given hostname.

        Args:
            hostname: Hostname to check (without port).

        Returns:
            SSLAnalysisResult with risk score and findings.
        """
        result = SSLAnalysisResult()

        try:
            # Remove port if present
            if ":" in hostname:
                hostname = hostname.split(":")[0]

            # Get SSL certificate
            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    ssl_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                    }

                    result.evidence = ssl_info

                    # Check for self-signed certificates
                    issuer = ssl_info.get("issuer", {})
                    subject = ssl_info.get("subject", {})

                    if issuer.get("commonName") == subject.get("commonName"):
                        result.risk_score += 25
                        result.labels.append("self_signed_cert")

                    # Check issuer reputation
                    issuer_name = issuer.get("organizationName", "").lower()
                    if "let's encrypt" in issuer_name:
                        # Let's Encrypt is legitimate but used by attackers too
                        result.labels.append("letsencrypt_cert")
                        result.labels.append("issuer_free_ca")

        except ssl.SSLError as e:
            result.risk_score += 30
            result.labels.append("ssl_error")
            result.evidence = {"error": f"SSL error: {str(e)}"}

        except TimeoutError:
            result.risk_score += 15
            result.labels.append("ssl_timeout")
            result.evidence = {"error": "SSL connection timeout"}

        except Exception as e:
            result.risk_score += 20
            result.labels.append("ssl_analysis_failed")
            result.evidence = {"error": f"SSL analysis failed: {str(e)}"}

        return result

