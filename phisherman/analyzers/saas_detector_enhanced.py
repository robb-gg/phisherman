"""
Enhanced SaaS Domain Detector - Migrated from Antifraude
Improved detection with PhishTank frequency analysis and dynamic risk assessment
"""

import logging
from dataclasses import dataclass

import tldextract

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class SaaSInfo:
    """SaaS domain information with risk context"""

    is_saas: bool = False
    provider: str | None = None
    service_type: str | None = None
    risk_modifier: float = 1.0
    analysis_notes: list[str] = None
    abuse_frequency: int = 0

    def __post_init__(self):
        if self.analysis_notes is None:
            self.analysis_notes = []


class EnhancedSaaSDetector(BaseAnalyzer):
    """
    Enhanced SaaS Domain Detector with PhishTank abuse statistics.

    This analyzer provides intelligent SaaS detection with context-aware risk scoring:
    - Detects major SaaS platforms (Firebase, Weebly, Cloudflare, etc.)
    - Applies risk modifiers based on real abuse frequency data from PhishTank
    - Identifies subdomain abuse patterns (common phishing technique)
    - Provides detailed analysis notes for downstream processors

    Key innovation: Higher abuse frequency != automatic high risk
    - Very high abuse services (Firebase: 4,326 cases) get NEUTRAL risk (0)
      because the denominator (legitimate uses) is also massive
    - Moderate abuse with smaller platforms (Weebly: 4,410) get INCREASED risk (+1.2)
      because abuse ratio is higher
    """

    # Enhanced SaaS database with PhishTank frequency analysis
    SAAS_DOMAINS = {
        # High-abuse website builders (smaller platforms = higher risk)
        "weebly.com": (3432, "website_builder", "Weebly", 1.2),
        "weeblysite.com": (978, "website_builder", "Weebly", 1.2),
        "wixsite.com": (796, "website_builder", "Wix", 1.1),
        "webflow.io": (787, "website_builder", "Webflow", 1.0),
        "carrd.co": (0, "website_builder", "Carrd", 1.1),
        # Google ecosystem (very high abuse but also very high legitimate use)
        "google.com": (7301, "search_engine", "Google", 0.3),
        "firebaseapp.com": (2134, "hosting", "Google Firebase", 0.8),
        "web.app": (2192, "hosting", "Google Firebase", 1.0),
        "appspot.com": (0, "hosting", "Google App Engine", 0.8),
        "blogspot.com": (378, "blog_platform", "Google Blogger", 1.2),
        "docs.google.com": (0, "document_sharing", "Google Docs", 0.7),
        "forms.gle": (0, "form_builder", "Google Forms", 0.8),
        # URL shorteners (VERY high risk - hide destination)
        "bit.ly": (2447, "url_shortener", "Bitly", 1.5),
        "t.co": (413, "url_shortener", "Twitter", 1.2),
        "tinyurl.com": (0, "url_shortener", "TinyURL", 1.4),
        "rebrandly.com": (0, "url_shortener", "Rebrandly", 1.2),
        "shorturl.at": (0, "url_shortener", "Short URL", 1.4),
        # QR code generators (high risk - common in phishing)
        "qrco.de": (2548, "qr_generator", "QR Code Generator", 1.3),
        "q-r.to": (1996, "qr_generator", "QR Code Generator", 1.3),
        # Cloudflare services (legitimate CDN, moderate abuse)
        "r2.dev": (1975, "cdn", "Cloudflare R2", 1.0),
        "pages.dev": (374, "hosting", "Cloudflare Pages", 0.9),
        "cloudfront.net": (0, "cdn", "Amazon CloudFront", 0.7),
        # IPFS / Web3 (emerging threat vector)
        "dweb.link": (803, "hosting", "IPFS", 1.1),
        "ead.me": (1975, "url_shortener", "EAD.me", 1.3),
        # Email marketing platforms
        "campaign-archive.com": (525, "email_marketing", "Mailchimp", 1.0),
        # Free hosting (high risk)
        "webcindario.com": (435, "free_hosting", "Webcindario", 1.4),
        "herokuapp.com": (0, "hosting", "Heroku", 1.0),
        # Cloud storage (legitimate services, low abuse)
        "dropbox.com": (533, "cloud_storage", "Dropbox", 0.4),
        # Forms (credential stealing risk)
        "jotform.com": (386, "form_builder", "JotForm", 1.1),
        "typeform.com": (0, "form_builder", "Typeform", 0.9),
        "airtable.com": (0, "database", "Airtable", 0.6),
        # Developer platforms (low risk in general)
        "github.io": (0, "hosting", "GitHub Pages", 0.8),
        "netlify.app": (0, "hosting", "Netlify", 0.8),
        "vercel.app": (0, "hosting", "Vercel", 0.8),
        "azurewebsites.net": (0, "hosting", "Microsoft Azure", 0.7),
        "amazonaws.com": (0, "hosting", "Amazon AWS", 0.6),
        # Social/Productivity (low risk)
        "medium.com": (0, "blog_platform", "Medium", 0.5),
        "notion.so": (0, "productivity", "Notion", 0.6),
        "linktree.com": (0, "link_aggregator", "Linktree", 1.0),
        "wordpress.com": (0, "blog_platform", "WordPress", 1.1),
        # Software companies (very low risk)
        "adobe.com": (1094, "creative_software", "Adobe", 0.2),
    }

    def __init__(self):
        super().__init__(timeout=5)
        self.known_domains = set(self.SAAS_DOMAINS.keys())

    @property
    def name(self) -> str:
        return "saas_detector_enhanced"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def weight(self) -> float:
        return 0.75  # Important analyzer for avoiding false positives

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Analyze URL for SaaS platform detection"""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        # Detect SaaS
        saas_info = self.detect_saas(domain)

        risk_score = 0.0
        confidence = 0.9  # High confidence in SaaS detection
        labels = []
        evidence = {
            "domain": domain,
            "is_saas": saas_info.is_saas,
        }

        if saas_info.is_saas:
            labels.append("saas_hosting")
            labels.append(f"provider_{saas_info.provider.lower().replace(' ', '_')}")
            labels.append(f"type_{saas_info.service_type}")

            # Base SaaS risk (platforms allow user content)
            risk_score = 15.0

            # Apply intelligent risk modifier based on abuse data
            risk_score *= saas_info.risk_modifier

            # Add context to evidence
            evidence.update(
                {
                    "provider": saas_info.provider,
                    "service_type": saas_info.service_type,
                    "risk_modifier": saas_info.risk_modifier,
                    "abuse_frequency": saas_info.abuse_frequency,
                    "analysis_notes": saas_info.analysis_notes,
                }
            )

            # High-risk service types get extra scoring
            high_risk_types = ["url_shortener", "qr_generator", "free_hosting"]
            if saas_info.service_type in high_risk_types:
                risk_score += 20
                labels.append("high_risk_service_type")

            # Abuse frequency bands
            if saas_info.abuse_frequency > 2000:
                labels.append("very_high_abuse_frequency")
            elif saas_info.abuse_frequency > 500:
                labels.append("high_abuse_frequency")
            elif saas_info.abuse_frequency > 100:
                labels.append("moderate_abuse_frequency")

        else:
            # Not SaaS - standard domain
            labels.append("standard_domain")
            risk_score = 0.0  # Neutral score, other analyzers will judge
            confidence = 0.7  # Lower confidence (we only know it's NOT SaaS)

        # Normalize score
        risk_score = min(max(risk_score, 0.0), 100.0)

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,  # Set by base class
        )

    def detect_saas(self, domain: str) -> SaaSInfo:
        """
        Detect if domain is SaaS and return detailed analysis info

        Args:
            domain: Domain to analyze (e.g., "example.com" or "subdomain.example.com")

        Returns:
            SaaSInfo with detection results and risk context
        """
        domain = domain.lower().strip()

        # Extract domain components
        extracted = tldextract.extract(domain)
        full_domain = f"{extracted.domain}.{extracted.suffix}"

        # Check direct match first
        if domain in self.SAAS_DOMAINS:
            return self._create_saas_info(
                domain, self.SAAS_DOMAINS[domain], is_subdomain=False
            )

        # Check base domain match
        if full_domain in self.SAAS_DOMAINS:
            return self._create_saas_info(
                full_domain, self.SAAS_DOMAINS[full_domain], is_subdomain=False
            )

        # Check for subdomain patterns of known SaaS domains
        for saas_domain, info in self.SAAS_DOMAINS.items():
            if domain.endswith(f".{saas_domain}"):
                # This is a subdomain of a known SaaS
                saas_info = self._create_saas_info(saas_domain, info, is_subdomain=True)
                saas_info.analysis_notes.append(
                    f"Subdomain of known SaaS: {saas_domain}"
                )
                # Subdomains get HIGHER risk modifier - common phishing technique
                saas_info.risk_modifier = min(saas_info.risk_modifier + 0.3, 2.0)
                return saas_info

        # Not a known SaaS domain
        return SaaSInfo(is_saas=False)

    def _create_saas_info(
        self, domain: str, info: tuple, is_subdomain: bool = False
    ) -> SaaSInfo:
        """Create SaaSInfo from domain data with intelligent risk assessment"""
        frequency, service_type, provider, risk_modifier = info

        analysis_notes = []

        # PhishTank frequency context
        if frequency > 0:
            analysis_notes.append(f"Appears in {frequency} PhishTank reports")

        # Risk context based on frequency and platform size
        if frequency > 2000:
            analysis_notes.append(
                "Very high abuse frequency - commonly exploited platform"
            )
            if risk_modifier < 1.0:
                analysis_notes.append(
                    "Risk kept neutral due to massive legitimate user base"
                )
        elif frequency > 1000:
            analysis_notes.append(
                "High abuse frequency - significant phishing activity"
            )
        elif frequency > 500:
            analysis_notes.append(
                "Moderate abuse frequency - regular phishing activity"
            )
        elif frequency > 0:
            analysis_notes.append("Low abuse frequency - occasional phishing activity")

        # Service type specific warnings
        service_warnings = {
            "url_shortener": "⚠️ URL shorteners hide final destination - HIGH phishing risk",
            "qr_generator": "⚠️ QR codes can redirect to malicious sites - HIGH risk",
            "website_builder": "Free website builders commonly used for phishing pages",
            "free_hosting": "Free hosting services frequently abused for malicious content",
            "form_builder": "Forms can be weaponized to steal credentials",
        }

        if service_type in service_warnings:
            analysis_notes.append(service_warnings[service_type])

        # Subdomain abuse warning
        if is_subdomain:
            analysis_notes.append("⚠️ Subdomain hosting - common phishing technique")

        return SaaSInfo(
            is_saas=True,
            provider=provider,
            service_type=service_type,
            risk_modifier=risk_modifier,
            analysis_notes=analysis_notes,
            abuse_frequency=frequency,
        )

    def get_analysis_strategy(self, saas_info: SaaSInfo) -> dict[str, bool]:
        """
        Get recommended analysis strategy for SaaS domains

        Returns:
            Dict with analysis strategy flags for other analyzers
        """
        if not saas_info.is_saas:
            return {
                "skip_whois": False,
                "focus_on_content": False,
                "check_subdomain_patterns": False,
                "enhanced_reputation_check": False,
            }

        # SaaS domains need different analysis approach
        strategy = {
            "skip_whois": True,  # WHOIS is useless for shared SaaS domains
            "focus_on_content": True,  # Content analysis is CRITICAL
            "check_subdomain_patterns": True,  # Check for suspicious subdomains
            "enhanced_reputation_check": True,  # More thorough reputation checks needed
        }

        # Service-specific strategies
        if saas_info.service_type in ["url_shortener", "qr_generator"]:
            strategy["check_redirect_chain"] = True
            strategy["follow_redirects"] = True

        if saas_info.service_type in ["website_builder", "free_hosting"]:
            strategy["deep_content_analysis"] = True
            strategy["screenshot_analysis"] = True  # For future ML models

        return strategy
