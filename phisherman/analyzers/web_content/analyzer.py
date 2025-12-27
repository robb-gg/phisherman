"""
Web Content Analyzer - Orchestrates multiple sub-analyzers for comprehensive analysis.

This is the main entry point for web content analysis, coordinating:
- SSL/TLS certificate analysis
- HTTP security headers analysis
- JavaScript/meta redirect detection
- User-Agent cloaking detection
- Content scanning for keywords and forms
"""

import logging
from urllib.parse import urlparse

import httpx

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.analyzers.web_content.cloaking_detector import CloakingDetector
from phisherman.analyzers.web_content.content_scanner import ContentScanner
from phisherman.analyzers.web_content.header_analyzer import HeaderAnalyzer
from phisherman.analyzers.web_content.redirect_detector import RedirectDetector
from phisherman.analyzers.web_content.ssl_analyzer import SSLAnalyzer
from phisherman.config import settings

logger = logging.getLogger(__name__)


class WebContentAnalyzer(BaseAnalyzer):
    """
    Comprehensive web content analyzer for phishing detection.

    Orchestrates multiple specialized sub-analyzers:
    - SSLAnalyzer: TLS certificate analysis
    - HeaderAnalyzer: HTTP security headers
    - RedirectDetector: JS and meta-refresh redirects
    - CloakingDetector: UA-based cloaking
    - ContentScanner: Keywords, forms, brands
    """

    def __init__(self):
        super().__init__(timeout=settings.http_timeout)

        # Initialize sub-analyzers
        self.ssl_analyzer = SSLAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.redirect_detector = RedirectDetector()
        self.cloaking_detector = CloakingDetector()
        self.content_scanner = ContentScanner()

        # HTTP client for fetching content
        self.client = httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
            verify=False,  # Allow SSL errors for analysis
        )

        # Enable multi-UA analysis for cloaking detection
        self.enable_cloaking_detection = True

    @property
    def name(self) -> str:
        return "web_content_analyzer"

    @property
    def version(self) -> str:
        return "2.0.0"  # Major version bump for refactored architecture

    @property
    def weight(self) -> float:
        return 0.85  # High weight - content is very revealing

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Perform comprehensive web content analysis."""
        # Ensure URL has protocol
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        risk_score = 0.0
        labels: list[str] = []
        evidence = {
            "original_url": url,
            "content_analysis": {},
            "headers": {},
            "ssl_analysis": {},
            "redirects": {},
            "cloaking": {},
        }

        try:
            # Perform HTTP request
            response = await self.client.get(url)

            evidence["status_code"] = response.status_code
            evidence["final_url"] = str(response.url)
            evidence["headers"] = dict(response.headers)

            # Get redirect history
            redirects = []
            if hasattr(response, "history") and response.history:
                redirects = [str(r.url) for r in response.history]

            # Run sub-analyzers

            # 1. Redirect analysis
            redirect_result = self.redirect_detector.analyze(
                response.text, redirects
            )
            risk_score += redirect_result.risk_score
            labels.extend(redirect_result.labels)
            evidence["redirects"] = redirect_result.evidence

            # 2. Header analysis
            header_result = self.header_analyzer.analyze(response.headers)
            risk_score += header_result.risk_score
            labels.extend(header_result.labels)
            evidence["headers"]["security"] = header_result.evidence

            # 3. Content analysis (only if 200 OK)
            if response.status_code == 200:
                content_result = self.content_scanner.analyze(response.text)
                risk_score += content_result.risk_score
                labels.extend(content_result.labels)
                evidence["content_analysis"] = content_result.evidence

                # 4. Cloaking patterns in content
                cloaking_content_result = self.cloaking_detector.analyze_content(
                    response.text
                )
                risk_score += cloaking_content_result.risk_score
                labels.extend(cloaking_content_result.labels)
                evidence["cloaking"]["content_patterns"] = (
                    cloaking_content_result.evidence
                )
            else:
                labels.append(f"http_status_{response.status_code}")
                if response.status_code >= 400:
                    risk_score += 10

            # 5. SSL/TLS analysis for HTTPS
            parsed_url = urlparse(url)
            if url.startswith("https://"):
                ssl_result = await self.ssl_analyzer.analyze(parsed_url.netloc)
                risk_score += ssl_result.risk_score
                labels.extend(ssl_result.labels)
                evidence["ssl_analysis"] = ssl_result.evidence
            else:
                # HTTP without HTTPS is suspicious for sensitive sites
                labels.append("no_https")
                risk_score += 15
                evidence["ssl_analysis"]["warning"] = "No HTTPS encryption"

            # 6. Multi User-Agent cloaking detection (async)
            if self.enable_cloaking_detection:
                ua_cloaking_result = await self.cloaking_detector.detect_ua_cloaking(
                    url
                )
                risk_score += ua_cloaking_result.risk_score
                labels.extend(ua_cloaking_result.labels)
                evidence["cloaking"]["ua_detection"] = ua_cloaking_result.evidence

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

    async def cleanup(self):
        """Cleanup HTTP client."""
        await self.client.aclose()

