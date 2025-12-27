"""JavaScript and meta-refresh redirect detection."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RedirectDetectionResult:
    """Result from redirect detection."""

    risk_score: float = 0.0
    labels: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


class RedirectDetector:
    """
    Detects JavaScript redirects and meta-refresh redirects.

    These are commonly used by attackers to:
    1. Hide the final phishing destination
    2. Evade URL scanners that don't execute JS
    3. Maintain persistence (change destination without changing initial URL)
    """

    # JavaScript redirect patterns
    JS_REDIRECT_PATTERNS = [
        r"window\.location\s*=",
        r"window\.location\.href\s*=",
        r"window\.location\.replace\s*\(",
        r"document\.location\s*=",
        r"document\.location\.href\s*=",
        r"location\.href\s*=",
        r"location\.replace\s*\(",
        r"window\.navigate\s*\(",
        r"\.location\.assign\s*\(",
        r"top\.location\s*=",
        r"parent\.location\s*=",
    ]

    # Meta refresh pattern
    META_REFRESH_PATTERN = (
        r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+'
        r'content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^"\'>\s]+)'
    )

    # URL shortener patterns
    SHORTENER_PATTERNS = ["bit.ly", "t.co", "tinyurl", "goo.gl", "ow.ly"]

    def analyze(self, content: str, redirects: list[str] | None = None) -> RedirectDetectionResult:
        """
        Analyze content for redirect patterns.

        Args:
            content: HTML content to analyze.
            redirects: Optional list of redirect URLs from response history.

        Returns:
            RedirectDetectionResult with findings.
        """
        result = RedirectDetectionResult()

        # Analyze redirect chain
        if redirects:
            chain_result = self._analyze_redirect_chain(redirects)
            result.risk_score += chain_result["risk"]
            result.labels.extend(chain_result["labels"])
            result.evidence["redirect_chain"] = chain_result

        # Detect JavaScript redirects
        js_result = self._detect_js_redirects(content)
        result.risk_score += js_result["risk"]
        result.labels.extend(js_result["labels"])
        result.evidence["js_redirects"] = js_result

        # Detect meta refresh
        meta_result = self._detect_meta_refresh(content)
        result.risk_score += meta_result["risk"]
        result.labels.extend(meta_result["labels"])
        result.evidence["meta_refresh"] = meta_result

        # Check if page is primarily a redirector
        if self._is_redirector_page(content, js_result, meta_result):
            result.risk_score += 25
            result.labels.append("redirector_page")
            result.evidence["is_redirector"] = True

        return result

    def _analyze_redirect_chain(self, redirects: list[str]) -> dict[str, Any]:
        """Analyze HTTP redirect chain."""
        info: dict[str, Any] = {
            "risk": 0.0,
            "labels": [],
            "count": len(redirects),
            "urls": redirects,
        }

        if not redirects:
            return info

        if len(redirects) > 3:
            info["risk"] += 15
            info["labels"].append("multiple_redirects")
        elif len(redirects) > 1:
            info["risk"] += 5
            info["labels"].append("redirect_chain")

        # Check for URL shorteners in chain
        for redirect_url in redirects:
            redirect_lower = redirect_url.lower()
            if any(pattern in redirect_lower for pattern in self.SHORTENER_PATTERNS):
                info["risk"] += 10
                info["labels"].append("shortener_in_redirect")
                break

        return info

    def _detect_js_redirects(self, content: str) -> dict[str, Any]:
        """Detect JavaScript redirect patterns."""
        info: dict[str, Any] = {
            "risk": 0.0,
            "labels": [],
            "patterns_found": [],
            "redirect_urls": [],
        }

        for pattern in self.JS_REDIRECT_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                info["patterns_found"].append(pattern)

        if info["patterns_found"]:
            info["risk"] += 20
            info["labels"].append("javascript_redirect")

            # Try to extract destination URLs
            url_matches = re.findall(
                r'(?:location\.href|location\.replace|window\.location)'
                r'\s*=\s*["\']([^"\']+)["\']',
                content,
                re.IGNORECASE,
            )
            if url_matches:
                info["redirect_urls"] = url_matches
                info["risk"] += 10

        return info

    def _detect_meta_refresh(self, content: str) -> dict[str, Any]:
        """Detect meta refresh redirects."""
        info: dict[str, Any] = {
            "risk": 0.0,
            "labels": [],
            "refresh_url": None,
        }

        match = re.search(self.META_REFRESH_PATTERN, content, re.IGNORECASE)
        if match:
            info["refresh_url"] = match.group(1)
            info["risk"] += 15
            info["labels"].append("meta_refresh_redirect")

        return info

    def _is_redirector_page(
        self,
        content: str,
        js_result: dict[str, Any],
        meta_result: dict[str, Any],
    ) -> bool:
        """Determine if page is primarily a redirector."""
        content_length = len(content)
        has_redirect = bool(js_result["patterns_found"] or meta_result["refresh_url"])

        # Short page with redirect = likely a redirector
        return has_redirect and content_length < 2000

