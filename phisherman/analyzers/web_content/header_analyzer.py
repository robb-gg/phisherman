"""HTTP security headers analysis."""

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class HeaderAnalysisResult:
    """Result from header analysis."""

    risk_score: float = 0.0
    labels: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


class HeaderAnalyzer:
    """
    Analyzes HTTP headers for security indicators.

    Checks for:
    - Missing security headers (HSTS, CSP, etc.)
    - Suspicious server headers
    - X-Frame-Options
    """

    # Important security headers to check
    SECURITY_HEADERS = {
        "strict-transport-security": "HSTS",
        "x-frame-options": "Frame Options",
        "x-content-type-options": "Content Type Options",
        "content-security-policy": "CSP",
        "x-xss-protection": "XSS Protection",
    }

    # Critical headers that increase risk when missing
    CRITICAL_HEADERS = ["strict-transport-security", "content-security-policy"]

    # Suspicious server header patterns
    SUSPICIOUS_SERVER_PATTERNS = ["test", "dev", "localhost", "staging"]

    def analyze(self, headers: httpx.Headers) -> HeaderAnalysisResult:
        """
        Analyze HTTP headers for security indicators.

        Args:
            headers: HTTP response headers.

        Returns:
            HeaderAnalysisResult with risk score and findings.
        """
        result = HeaderAnalysisResult()
        security_headers = {}

        # Check for important security headers
        for header_name, friendly_name in self.SECURITY_HEADERS.items():
            if header_name in headers:
                security_headers[friendly_name] = "Present"
            else:
                security_headers[friendly_name] = "Missing"
                if header_name in self.CRITICAL_HEADERS:
                    result.risk_score += 5

        result.evidence["security_headers"] = security_headers

        # Check Server header for suspicious values
        server = headers.get("server", "").lower()
        if server:
            result.evidence["server"] = server
            if any(pattern in server for pattern in self.SUSPICIOUS_SERVER_PATTERNS):
                result.risk_score += 10
                result.labels.append("suspicious_server_header")

        return result

