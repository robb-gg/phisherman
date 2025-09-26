"""URL heuristics analyzer for suspicious URL patterns and features."""

import logging
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlparse

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer

logger = logging.getLogger(__name__)


class UrlHeuristicsAnalyzer(BaseAnalyzer):
    """
    Analyzes URL structure and features for suspicious patterns.

    Performs the following heuristic checks:
    - Punycode/homograph detection
    - Excessive subdomain analysis
    - TLD risk assessment
    - Path/query entropy analysis
    - Suspicious keywords detection
    - URL length analysis
    - Character distribution analysis
    """

    def __init__(self):
        super().__init__()

        # High-risk TLDs (based on abuse statistics)
        self.high_risk_tlds = {
            "tk",
            "ml",
            "ga",
            "cf",
            "gq",  # Free domains
            "cc",
            "pw",
            "top",
            "click",
            "download",
            "zip",
            "review",
            "country",
            "kim",
            "work",
        }

        # Medium-risk TLDs
        self.medium_risk_tlds = {
            "info",
            "biz",
            "name",
            "pro",
            "mobi",
            "asia",
            "tel",
            "travel",
            "xxx",
        }

        # Suspicious keywords in URLs
        self.suspicious_keywords = {
            # Banking/Finance
            "paypal",
            "bank",
            "secure",
            "account",
            "login",
            "verify",
            "update",
            "confirm",
            "billing",
            "payment",
            "wallet",
            "credit",
            "card",
            # Social/Tech brands
            "facebook",
            "google",
            "microsoft",
            "apple",
            "amazon",
            "netflix",
            "spotify",
            "instagram",
            # Phishing terms
            "suspended",
            "expired",
            "urgent",
            "immediate",
            "action",
            "required",
            "click",
            "here",
            "now",
            # URL shorteners (suspicious in this context)
            "bit.ly",
            "tinyurl",
            "goo.gl",
            "ow.ly",
            "t.co",
        }

    @property
    def name(self) -> str:
        return "url_heuristics"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.6

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Analyze URL heuristics."""
        parsed = urlparse(url)

        risk_score = 0.0
        labels: list[str] = []
        evidence: dict[str, Any] = {
            "url": url,
            "parsed": {
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
            },
            "features": {},
        }

        # Analyze different components
        risk_score += self._analyze_domain(parsed.netloc, labels, evidence)
        risk_score += self._analyze_path(parsed.path, labels, evidence)
        risk_score += self._analyze_query(parsed.query, labels, evidence)
        risk_score += self._analyze_overall_structure(url, labels, evidence)

        # Normalize risk score
        risk_score = min(risk_score, 100.0)
        confidence = 0.6  # Heuristics have moderate confidence

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,
        )

    def _analyze_domain(
        self, netloc: str, labels: list[str], evidence: dict[str, Any]
    ) -> float:
        """Analyze domain/netloc for suspicious patterns."""
        risk = 0.0
        domain_features = {}

        # Remove port if present
        domain = netloc.split(":")[0].lower()

        # Punycode/IDN analysis
        try:
            if domain.startswith("xn--"):
                labels.append("punycode_domain")
                risk += 25
                domain_features["punycode"] = True

                # Decode punycode
                try:
                    decoded = domain.encode("ascii").decode("idna")
                    domain_features["punycode_decoded"] = decoded

                    # Check for homographs (visually similar characters)
                    if self._contains_homographs(decoded):
                        labels.append("homograph_attack")
                        risk += 30
                        domain_features["homograph_detected"] = True

                except Exception:
                    pass
        except Exception:
            pass

        # Subdomain analysis
        domain_parts = domain.split(".")
        subdomain_count = len(domain_parts) - 2  # Subtract domain + TLD
        domain_features["subdomain_count"] = subdomain_count

        if subdomain_count > 3:
            labels.append("excessive_subdomains")
            risk += 15
        elif subdomain_count > 5:
            labels.append("many_subdomains")
            risk += 25

        # TLD risk analysis
        if domain_parts:
            tld = domain_parts[-1]
            domain_features["tld"] = tld

            if tld in self.high_risk_tlds:
                labels.append("high_risk_tld")
                risk += 20
            elif tld in self.medium_risk_tlds:
                labels.append("medium_risk_tld")
                risk += 10

        # Domain length analysis
        domain_length = len(domain)
        domain_features["length"] = domain_length

        if domain_length > 50:
            labels.append("long_domain")
            risk += 10
        elif domain_length > 75:
            labels.append("very_long_domain")
            risk += 15

        # Character analysis
        digit_count = sum(c.isdigit() for c in domain)
        if digit_count > len(domain) * 0.3:  # More than 30% digits
            labels.append("digit_heavy_domain")
            risk += 10

        # Hyphen analysis
        hyphen_count = domain.count("-")
        if hyphen_count > 3:
            labels.append("hyphen_heavy_domain")
            risk += 5

        # Brand impersonation (simple keyword matching)
        for keyword in self.suspicious_keywords:
            if keyword in domain:
                labels.append("suspicious_keyword")
                risk += 15
                domain_features["suspicious_keyword"] = keyword
                break

        evidence["features"]["domain"] = domain_features
        return risk

    def _analyze_path(
        self, path: str, labels: list[str], evidence: dict[str, Any]
    ) -> float:
        """Analyze URL path for suspicious patterns."""
        risk = 0.0
        path_features = {}

        if not path or path == "/":
            return 0.0

        # Path length
        path_length = len(path)
        path_features["length"] = path_length

        if path_length > 100:
            labels.append("long_path")
            risk += 5

        # Entropy analysis (randomness)
        entropy = self._calculate_entropy(path)
        path_features["entropy"] = entropy

        if entropy > 4.0:  # High entropy suggests randomness
            labels.append("high_entropy_path")
            risk += 10

        # Suspicious patterns in path
        suspicious_path_patterns = [
            r"/[a-zA-Z0-9]{20,}",  # Long random strings
            r"/admin",
            r"/login",
            r"/secure",
            r"/verify",
            r"/update",
            r"/confirm",
        ]

        for pattern in suspicious_path_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                labels.append("suspicious_path_pattern")
                risk += 5
                path_features["suspicious_pattern"] = pattern
                break

        evidence["features"]["path"] = path_features
        return risk

    def _analyze_query(
        self, query: str, labels: list[str], evidence: dict[str, Any]
    ) -> float:
        """Analyze URL query parameters for suspicious patterns."""
        risk = 0.0
        query_features = {}

        if not query:
            return 0.0

        # Parse query parameters
        try:
            params = parse_qs(query, keep_blank_values=True)
            param_count = len(params)
            query_features["parameter_count"] = param_count

            if param_count > 10:
                labels.append("many_parameters")
                risk += 5

            # Check for suspicious parameter names
            suspicious_param_names = [
                "token",
                "session",
                "auth",
                "key",
                "id",
                "redirect",
                "return",
                "continue",
                "next",
            ]

            for param_name in params:
                if param_name.lower() in suspicious_param_names:
                    labels.append("suspicious_parameter")
                    risk += 3
                    query_features["suspicious_param"] = param_name

                # Check parameter values
                for value in params[param_name]:
                    if len(value) > 100:
                        labels.append("long_parameter_value")
                        risk += 5

                    # High entropy in parameter values
                    if self._calculate_entropy(value) > 4.0:
                        labels.append("high_entropy_parameter")
                        risk += 5

        except Exception:
            pass

        # Overall query entropy
        query_entropy = self._calculate_entropy(query)
        query_features["entropy"] = query_entropy

        if query_entropy > 4.5:
            labels.append("high_entropy_query")
            risk += 8

        evidence["features"]["query"] = query_features
        return risk

    def _analyze_overall_structure(
        self, url: str, labels: list[str], evidence: dict[str, Any]
    ) -> float:
        """Analyze overall URL structure."""
        risk = 0.0
        structure_features = {}

        # URL length
        url_length = len(url)
        structure_features["length"] = url_length

        if url_length > 200:
            labels.append("long_url")
            risk += 10
        elif url_length > 400:
            labels.append("very_long_url")
            risk += 20

        # Character distribution analysis
        char_counts = Counter(url.lower())
        total_chars = len(url)

        # Check for character repetition
        max_char_freq = (
            max(char_counts.values()) / total_chars if total_chars > 0 else 0
        )
        structure_features["max_char_frequency"] = max_char_freq

        if max_char_freq > 0.2:  # More than 20% of URL is single character
            labels.append("repetitive_characters")
            risk += 8

        # Overall entropy
        url_entropy = self._calculate_entropy(url)
        structure_features["entropy"] = url_entropy

        if url_entropy < 3.0:  # Very low entropy (repetitive)
            labels.append("low_entropy_url")
            risk += 10
        elif url_entropy > 5.0:  # Very high entropy (random)
            labels.append("high_entropy_url")
            risk += 15

        evidence["features"]["structure"] = structure_features
        return risk

    def _contains_homographs(self, text: str) -> bool:
        """Check if text contains potential homograph characters."""
        # Simplified homograph detection
        suspicious_chars = {
            # Cyrillic lookalikes
            "а",
            "е",
            "о",
            "р",
            "с",
            "у",
            "х",
            # Greek lookalikes
            "α",
            "β",
            "ε",
            "ο",
            "ρ",
            "υ",
            "χ",
        }

        return any(char in text for char in suspicious_chars)

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = Counter(text.lower())
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy
