"""
Web Content Analyzer - Migrated from Antifraude
Advanced web content, SSL, and header analysis for phishing detection
"""

import logging
import re
import socket
import ssl
from urllib.parse import urlparse

import httpx

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.config import settings

logger = logging.getLogger(__name__)


class WebContentAnalyzer(BaseAnalyzer):
    """
    Comprehensive web content analyzer for phishing detection.

    Analyzes:
    - HTTP headers and security headers
    - SSL/TLS certificates
    - Page content and suspicious keywords
    - Forms and password inputs
    - Brand impersonation keywords
    - Redirect chains

    This is a deep content analysis that complements URL heuristics.
    """

    # Suspicious phishing keywords
    PHISHING_KEYWORDS = [
        "verify your account",
        "suspended account",
        "urgent action required",
        "click here immediately",
        "limited time offer",
        "act now",
        "confirm your identity",
        "update payment",
        "security alert",
        "unusual activity",
        "account locked",
        "verify identity",
        "confirm payment",
        "billing problem",
        "expire soon",
        "confirm your information",
        "validate account",
        "suspended",
    ]

    # Brand keywords that indicate potential impersonation
    BRAND_KEYWORDS = [
        "paypal",
        "amazon",
        "microsoft",
        "google",
        "apple",
        "facebook",
        "netflix",
        "spotify",
        "instagram",
        "twitter",
        "linkedin",
        "dropbox",
        "adobe",
        "ebay",
        "chase",
        "bank of america",
        "wells fargo",
        "citibank",
        "dhl",
        "fedex",
        "ups",
        "coinbase",
        "binance",
        "metamask",
        "blockchain",
    ]

    def __init__(self):
        super().__init__(timeout=settings.request_timeout)
        self.client = httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
            verify=False,  # Allow SSL errors for analysis
        )

    @property
    def name(self) -> str:
        return "web_content_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.85  # High weight - content is very revealing

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Perform comprehensive web content analysis"""

        # Ensure URL has protocol
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        risk_score = 0.0
        labels = []
        evidence = {
            "original_url": url,
            "content_analysis": {},
            "headers": {},
            "ssl_analysis": {},
            "redirects": [],
        }

        try:
            # Perform HTTP request
            response = await self.client.get(url)

            evidence["status_code"] = response.status_code
            evidence["final_url"] = str(response.url)
            evidence["headers"] = dict(response.headers)

            # Analyze redirects
            if hasattr(response, "history") and response.history:
                redirects = [str(r.url) for r in response.history]
                evidence["redirects"] = redirects
                redirect_risk = self._analyze_redirects(redirects, labels)
                risk_score += redirect_risk

            # Analyze HTTP headers
            header_risk = self._analyze_headers(response.headers, labels, evidence)
            risk_score += header_risk

            # Analyze page content
            if response.status_code == 200:
                content = response.text
                content_risk = self._analyze_content(content, labels, evidence)
                risk_score += content_risk
            else:
                labels.append(f"http_status_{response.status_code}")
                if response.status_code >= 400:
                    risk_score += 10  # Error pages slightly suspicious

            # SSL/TLS analysis for HTTPS
            if url.startswith("https://"):
                ssl_risk = await self._analyze_ssl(
                    urlparse(url).netloc, labels, evidence
                )
                risk_score += ssl_risk
            else:
                # HTTP without HTTPS is suspicious for sensitive sites
                labels.append("no_https")
                risk_score += 15
                evidence["ssl_analysis"]["warning"] = "No HTTPS encryption"

        except httpx.TimeoutException:
            risk_score += 20
            labels.append("request_timeout")
            evidence["error"] = "Request timeout"
        except httpx.ConnectError as e:
            risk_score += 25
            labels.append("connection_error")
            evidence["error"] = f"Connection error: {str(e)}"
        except Exception as e:
            risk_score += 15
            labels.append("analysis_error")
            evidence["error"] = f"Unexpected error: {str(e)}"

        # Normalize risk score
        risk_score = min(max(risk_score, 0.0), 100.0)

        # Confidence based on data quality
        confidence = 0.9 if not evidence.get("error") else 0.5

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,
        )

    def _analyze_redirects(self, redirects: list[str], labels: list[str]) -> float:
        """Analyze redirect chains for suspicious patterns"""
        risk = 0.0

        if not redirects:
            return 0.0

        redirect_count = len(redirects)

        if redirect_count > 3:
            risk += 15
            labels.append("multiple_redirects")
        elif redirect_count > 1:
            risk += 5
            labels.append("redirect_chain")

        # Check for suspicious redirect patterns
        for redirect_url in redirects:
            redirect_lower = redirect_url.lower()

            # Check for URL shortener in chain (often used to hide destination)
            shortener_patterns = ["bit.ly", "t.co", "tinyurl", "goo.gl", "ow.ly"]
            if any(pattern in redirect_lower for pattern in shortener_patterns):
                risk += 10
                labels.append("shortener_in_redirect")
                break

        return risk

    def _analyze_headers(
        self, headers: httpx.Headers, labels: list[str], evidence: dict
    ) -> float:
        """Analyze HTTP headers for security indicators"""
        risk = 0.0
        security_headers = {}

        # Check for important security headers
        important_headers = {
            "strict-transport-security": "HSTS",
            "x-frame-options": "Frame Options",
            "x-content-type-options": "Content Type Options",
            "content-security-policy": "CSP",
            "x-xss-protection": "XSS Protection",
        }

        for header_name, friendly_name in important_headers.items():
            if header_name in headers:
                security_headers[friendly_name] = "Present"
            else:
                security_headers[friendly_name] = "Missing"
                if header_name in [
                    "strict-transport-security",
                    "content-security-policy",
                ]:
                    risk += 5  # Missing critical security headers

        evidence["security_headers"] = security_headers

        # Check Server header for suspicious values
        server = headers.get("server", "").lower()
        if server:
            suspicious_servers = ["test", "dev", "localhost", "staging"]
            if any(pattern in server for pattern in suspicious_servers):
                risk += 10
                labels.append("suspicious_server_header")

        return risk

    def _analyze_content(
        self, content: str, labels: list[str], evidence: dict
    ) -> float:
        """Analyze page content for phishing indicators"""
        if not content:
            return 0.0

        risk = 0.0
        content_lower = content.lower()
        content_analysis = {
            "content_length": len(content),
            "suspicious_keywords_found": [],
            "brand_keywords_found": [],
            "has_forms": False,
            "has_password_input": False,
            "external_links_count": 0,
        }

        # Extract title
        title = self._extract_title(content)
        if title:
            content_analysis["title"] = title

        # Search for suspicious phishing keywords
        found_phishing_keywords = []
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in content_lower:
                found_phishing_keywords.append(keyword)

        if found_phishing_keywords:
            content_analysis["suspicious_keywords_found"] = found_phishing_keywords
            risk += min(len(found_phishing_keywords) * 8, 30)  # Cap at 30
            labels.append("suspicious_keywords")

        # Search for brand impersonation keywords
        found_brand_keywords = []
        for brand in self.BRAND_KEYWORDS:
            if brand in content_lower:
                found_brand_keywords.append(brand)

        if found_brand_keywords:
            content_analysis["brand_keywords_found"] = found_brand_keywords
            risk += min(len(found_brand_keywords) * 5, 20)  # Cap at 20
            labels.append("brand_impersonation_keywords")

        # Check for forms (credential stealing)
        if "<form" in content_lower:
            content_analysis["has_forms"] = True
            risk += 10
            labels.append("has_forms")

            # Password inputs are VERY suspicious with phishing keywords
            if 'type="password"' in content_lower or "type='password'" in content_lower:
                content_analysis["has_password_input"] = True
                risk += 15
                labels.append("password_input")

                # If we have phishing keywords + password input = HIGH risk
                if found_phishing_keywords:
                    risk += 20
                    labels.append("credential_theft_indicators")

        # Count external links (excessive linking can be suspicious)
        external_link_count = content_lower.count("http://") + content_lower.count(
            "https://"
        )
        content_analysis["external_links_count"] = external_link_count

        if external_link_count > 50:
            risk += 10
            labels.append("excessive_external_links")

        # Check for very short content (might be a redirect page)
        if len(content) < 500:
            risk += 5
            labels.append("very_short_content")

        evidence["content_analysis"] = content_analysis
        return risk

    def _extract_title(self, content: str) -> str:
        """Extract page title from HTML"""
        try:
            match = re.search(
                r"<title>(.*?)</title>", content, re.IGNORECASE | re.DOTALL
            )
            return match.group(1).strip() if match else ""
        except Exception:
            return ""

    async def _analyze_ssl(
        self, hostname: str, labels: list[str], evidence: dict
    ) -> float:
        """Analyze SSL/TLS certificate"""
        risk = 0.0

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

                    evidence["ssl_analysis"] = ssl_info

                    # Check for self-signed certificates
                    issuer = ssl_info.get("issuer", {})
                    subject = ssl_info.get("subject", {})

                    if issuer.get("commonName") == subject.get("commonName"):
                        risk += 25
                        labels.append("self_signed_cert")

                    # Check issuer reputation (free CAs are more suspicious)
                    issuer_name = issuer.get("organizationName", "").lower()
                    if "let's encrypt" in issuer_name:
                        # Let's Encrypt is legitimate but used by attackers too
                        # Don't add much risk, just note it
                        labels.append("letsencrypt_cert")

        except ssl.SSLError as e:
            risk += 30
            labels.append("ssl_error")
            evidence["ssl_analysis"] = {"error": f"SSL error: {str(e)}"}
        except TimeoutError:
            risk += 15
            labels.append("ssl_timeout")
            evidence["ssl_analysis"] = {"error": "SSL connection timeout"}
        except Exception as e:
            risk += 20
            labels.append("ssl_analysis_failed")
            evidence["ssl_analysis"] = {"error": f"SSL analysis failed: {str(e)}"}

        return risk

    async def cleanup(self):
        """Cleanup HTTP client"""
        await self.client.aclose()
