"""User-Agent based cloaking detection."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class CloakingDetectionResult:
    """Result from cloaking detection."""

    risk_score: float = 0.0
    labels: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


class CloakingDetector:
    """
    Detects User-Agent based cloaking techniques.

    Cloaking is when attackers show different content based on:
    - User-Agent (mobile vs desktop vs crawler)
    - IP geolocation (specific countries)
    - Referrer (SMS link vs search engine)
    """

    # User-Agents for cloaking detection
    USER_AGENTS = {
        "mobile_android": (
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        ),
        "desktop_chrome": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "crawler_google": (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ),
    }

    # Cloaking detection patterns in JavaScript
    CLOAKING_PATTERNS = [
        r"navigator\.userAgent",
        r"navigator\.platform",
        r"screen\.width",
        r"screen\.height",
        r"navigator\.language",
        r"Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone",
        r'fetch\([\'"]https?://ip',  # IP geolocation API calls
        r"geoip",
        r"geolocation",
        r"/api/.*location",
    ]

    # Suspicious cloaking indicators
    SUSPICIOUS_INDICATORS = [
        (r"navigator\.userAgent\.indexOf\(['\"]Android", "android_ua_check"),
        (r"navigator\.userAgent\.indexOf\(['\"]iPhone", "iphone_ua_check"),
        (r"navigator\.userAgent\.indexOf\(['\"]bot", "bot_detection"),
        (r"navigator\.userAgent\.indexOf\(['\"]crawler", "crawler_detection"),
        (r"\/api\/geo", "geolocation_api"),
        (r"country\s*[=!]==?\s*['\"]", "country_check"),
        (r"timezone", "timezone_check"),
    ]

    def __init__(self, cloaking_threshold: float = 0.3):
        """
        Initialize the cloaking detector.

        Args:
            cloaking_threshold: Content difference ratio that triggers alert.
        """
        self.cloaking_threshold = cloaking_threshold

    def analyze_content(self, content: str) -> CloakingDetectionResult:
        """
        Analyze content for cloaking patterns.

        Args:
            content: HTML content to analyze.

        Returns:
            CloakingDetectionResult with findings.
        """
        result = CloakingDetectionResult()
        patterns_found = []
        suspicious_checks = []

        # Check for cloaking patterns in JavaScript
        for pattern in self.CLOAKING_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                patterns_found.append(pattern)

        # Check for specific suspicious patterns
        for pattern, name in self.SUSPICIOUS_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                suspicious_checks.append(name)

        result.evidence = {
            "patterns_found": patterns_found,
            "suspicious_checks": suspicious_checks,
        }

        # Calculate risk based on findings
        if len(patterns_found) >= 3:
            result.risk_score += 15
            result.labels.append("potential_cloaking")
        elif patterns_found:
            result.risk_score += 5

        if suspicious_checks:
            result.risk_score += len(suspicious_checks) * 5
            result.labels.extend(suspicious_checks)

        return result

    async def detect_ua_cloaking(self, url: str) -> CloakingDetectionResult:
        """
        Detect User-Agent based cloaking by comparing responses with different UAs.

        Attackers often show phishing content only to mobile users (from SMS)
        while showing benign content to desktop/crawler UAs to evade detection.

        Args:
            url: URL to check.

        Returns:
            CloakingDetectionResult with findings.
        """
        result = CloakingDetectionResult()
        responses: dict[str, dict[str, Any]] = {}

        # Fetch with different User-Agents
        for ua_name, ua_string in self.USER_AGENTS.items():
            try:
                async with httpx.AsyncClient(
                    timeout=10,
                    follow_redirects=True,
                    headers={"User-Agent": ua_string},
                    verify=False,
                ) as client:
                    response = await client.get(url)
                    responses[ua_name] = {
                        "status_code": response.status_code,
                        "final_url": str(response.url),
                        "content_length": len(response.text),
                        "content_hash": hash(response.text[:1000]),
                        "has_form": "<form" in response.text.lower(),
                        "has_password": 'type="password"' in response.text.lower(),
                    }
            except Exception as e:
                responses[ua_name] = {"error": str(e)}

        result.evidence["responses"] = responses

        # Compare responses for cloaking indicators
        result = self._compare_responses(responses, result)

        return result

    def _compare_responses(
        self,
        responses: dict[str, dict[str, Any]],
        result: CloakingDetectionResult,
    ) -> CloakingDetectionResult:
        """Compare responses from different User-Agents."""
        content_differences: dict[str, Any] = {}

        # Check 1: Different final URLs (redirect cloaking)
        final_urls = set()
        for data in responses.values():
            if "final_url" in data:
                final_urls.add(data["final_url"])

        if len(final_urls) > 1:
            result.risk_score += 30
            result.labels.append("ua_cloaking_detected")
            result.labels.append("cloaking_redirect_cloaking")
            content_differences["different_destinations"] = list(final_urls)

        # Check 2: Different status codes
        status_codes = set()
        for data in responses.values():
            if "status_code" in data:
                status_codes.add(data["status_code"])

        if len(status_codes) > 1:
            result.risk_score += 20
            result.labels.append("cloaking_status_code_cloaking")
            content_differences["different_status_codes"] = list(status_codes)

        # Check 3: Significant content length differences
        content_lengths = [
            d.get("content_length", 0)
            for d in responses.values()
            if "content_length" in d
        ]
        if len(content_lengths) >= 2:
            max_len = max(content_lengths)
            min_len = min(content_lengths)
            if max_len > 0:
                difference_ratio = (max_len - min_len) / max_len
                if difference_ratio > self.cloaking_threshold:
                    result.risk_score += 25
                    result.labels.append("cloaking_content_cloaking")
                    content_differences["length_ratio"] = difference_ratio

        # Check 4: Form/password present in mobile but not crawler
        mobile_data = responses.get("mobile_android", {})
        crawler_data = responses.get("crawler_google", {})

        if mobile_data.get("has_password") and not crawler_data.get("has_password"):
            result.risk_score += 35
            result.labels.append("cloaking_credential_cloaking")
            content_differences["mobile_only_password"] = True

        if mobile_data.get("has_form") and not crawler_data.get("has_form"):
            result.risk_score += 20
            content_differences["mobile_only_form"] = True

        result.evidence["content_differences"] = content_differences
        result.evidence["cloaking_detected"] = bool(content_differences)

        return result

