"""Content scanning for phishing indicators."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger(__name__)


@dataclass
class ContentScanResult:
    """Result from content scanning."""

    risk_score: float = 0.0
    labels: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


class ContentScanner:
    """
    Scans page content for phishing indicators.

    Checks for:
    - Brand impersonation (brand mentioned but domain doesn't match)
    - Suspicious phishing keywords IN CONTEXT (not on legitimate sites)
    - Login forms and password inputs
    - External links analysis
    """

    # Brand to legitimate domains mapping
    # Only flag as suspicious if brand appears in content but domain doesn't match
    BRAND_DOMAINS: dict[str, set[str]] = {
        "paypal": {"paypal.com", "paypal.me"},
        "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.es", "amazon.fr", "amazon.it", "amazon.ca", "amazon.com.mx", "amazon.com.br", "amazon.co.jp", "amazon.in", "amazon.com.au", "aws.amazon.com"},
        "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "azure.com", "windows.com", "xbox.com", "github.com", "linkedin.com"},
        "google": {"google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.co.uk", "google.es", "google.de", "google.fr"},
        "apple": {"apple.com", "icloud.com", "itunes.com", "me.com"},
        "facebook": {"facebook.com", "fb.com", "messenger.com", "instagram.com", "whatsapp.com", "meta.com", "oculus.com"},
        "netflix": {"netflix.com"},
        "spotify": {"spotify.com"},
        "instagram": {"instagram.com", "facebook.com", "meta.com"},
        "twitter": {"twitter.com", "x.com", "t.co"},
        "linkedin": {"linkedin.com", "microsoft.com"},
        "dropbox": {"dropbox.com", "dropboxusercontent.com"},
        "adobe": {"adobe.com", "behance.net", "creativecloud.com"},
        "ebay": {"ebay.com", "ebay.co.uk", "ebay.de", "ebay.es"},
        "chase": {"chase.com", "jpmorganchase.com"},
        "bank of america": {"bankofamerica.com", "bofa.com"},
        "wells fargo": {"wellsfargo.com"},
        "citibank": {"citi.com", "citibank.com"},
        "dhl": {"dhl.com", "dhl.de"},
        "fedex": {"fedex.com"},
        "ups": {"ups.com"},
        "coinbase": {"coinbase.com"},
        "binance": {"binance.com", "binance.us"},
        "metamask": {"metamask.io"},
        "santander": {"santander.com", "santander.es", "santander.co.uk"},
        "bbva": {"bbva.com", "bbva.es"},
        "caixabank": {"caixabank.com", "caixabank.es"},
        "optus": {"optus.com.au"},
        "telstra": {"telstra.com.au"},
        "vodafone": {"vodafone.com", "vodafone.es", "vodafone.de", "vodafone.co.uk"},
        "movistar": {"movistar.es", "movistar.com"},
    }

    # Suspicious phishing keywords - only suspicious in non-legitimate contexts
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
    ]

    def analyze(self, content: str, url: str | None = None) -> ContentScanResult:
        """
        Analyze page content for phishing indicators.

        Args:
            content: HTML content to analyze.
            url: Original URL being analyzed (used to determine if brand mentions are legitimate).

        Returns:
            ContentScanResult with findings.
        """
        if not content:
            return ContentScanResult()

        result = ContentScanResult()
        content_lower = content.lower()

        # Extract domain info for brand impersonation check
        domain_info = self._extract_domain_info(url) if url else None

        content_analysis: dict[str, Any] = {
            "content_length": len(content),
            "brands_mentioned": [],
            "impersonated_brands": [],
            "suspicious_keywords_found": [],
            "has_forms": False,
            "has_password_input": False,
            "external_links_count": 0,
        }

        # Extract title
        title = self._extract_title(content)
        if title:
            content_analysis["title"] = title

        # Check for brand impersonation (brand in content but NOT legitimate domain)
        impersonation_result = self._check_brand_impersonation(
            content_lower, domain_info
        )
        content_analysis["brands_mentioned"] = impersonation_result["brands_mentioned"]
        content_analysis["impersonated_brands"] = impersonation_result["impersonated_brands"]

        if impersonation_result["impersonated_brands"]:
            # Only add risk if there's actual impersonation
            result.risk_score += min(len(impersonation_result["impersonated_brands"]) * 15, 40)
            result.labels.append("brand_impersonation")
            for brand in impersonation_result["impersonated_brands"]:
                result.labels.append(f"impersonates_{brand}")

        # Check for phishing keywords - but reduce weight if on legitimate domain
        is_legitimate_domain = domain_info and domain_info.get("is_known_brand", False)
        
        found_phishing_keywords = []
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in content_lower:
                found_phishing_keywords.append(keyword)

        if found_phishing_keywords:
            content_analysis["suspicious_keywords_found"] = found_phishing_keywords
            
            if is_legitimate_domain:
                # On legitimate sites, phishing keywords are less suspicious
                # (banks legitimately say "verify your account")
                result.risk_score += min(len(found_phishing_keywords) * 2, 10)
            else:
                # On unknown sites, phishing keywords are more suspicious
                result.risk_score += min(len(found_phishing_keywords) * 5, 25)
                result.labels.append("suspicious_keywords")

        # Check for forms (credential stealing) - context matters
        if "<form" in content_lower:
            content_analysis["has_forms"] = True
            
            # Password inputs
            if 'type="password"' in content_lower or "type='password'" in content_lower:
                content_analysis["has_password_input"] = True
                
                if is_legitimate_domain:
                    # Password forms on legitimate sites are normal
                    result.labels.append("has_login_form")
                else:
                    # Password forms on unknown sites WITH brand impersonation = HIGH risk
                    result.labels.append("password_input")
                    result.risk_score += 10
                    
                    if impersonation_result["impersonated_brands"]:
                        result.risk_score += 25
                        result.labels.append("credential_theft_indicators")
                    
                    if found_phishing_keywords:
                        result.risk_score += 15

        # Count external links
        external_link_count = content_lower.count("http://") + content_lower.count(
            "https://"
        )
        content_analysis["external_links_count"] = external_link_count

        if external_link_count > 50:
            result.risk_score += 5
            result.labels.append("many_external_links")

        # Very short content (might be a redirect page)
        if len(content) < 500 and not is_legitimate_domain:
            result.risk_score += 5
            result.labels.append("very_short_content")

        result.evidence = content_analysis
        return result

    def _extract_domain_info(self, url: str) -> dict[str, Any]:
        """Extract domain information from URL."""
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Get the registered domain (e.g., "facebook.com")
            registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # Check if this is a known brand's legitimate domain
            is_known_brand = False
            matching_brand = None
            
            for brand, domains in self.BRAND_DOMAINS.items():
                if registered_domain in domains:
                    is_known_brand = True
                    matching_brand = brand
                    break
            
            return {
                "full_domain": parsed.netloc.lower(),
                "registered_domain": registered_domain,
                "subdomain": extracted.subdomain,
                "is_known_brand": is_known_brand,
                "matching_brand": matching_brand,
            }
        except Exception:
            return {}

    def _check_brand_impersonation(
        self,
        content_lower: str,
        domain_info: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Check for brand impersonation.
        
        Only flags as impersonation if:
        - Brand name appears in content
        - Domain is NOT a legitimate domain for that brand
        """
        brands_mentioned = []
        impersonated_brands = []
        
        # Get the current domain's registered domain
        current_domain = domain_info.get("registered_domain", "") if domain_info else ""
        is_known_brand = domain_info.get("is_known_brand", False) if domain_info else False
        matching_brand = domain_info.get("matching_brand") if domain_info else None
        
        for brand, legitimate_domains in self.BRAND_DOMAINS.items():
            # Check if brand name appears in content
            if brand in content_lower:
                brands_mentioned.append(brand)
                
                # If we're on a known brand's domain, it's not impersonation
                if is_known_brand:
                    # Check if this brand is related to the domain's brand
                    # (e.g., facebook.com mentioning "instagram" is fine since Meta owns both)
                    if brand == matching_brand:
                        continue  # Same brand, not impersonation
                    
                    # Check if domains are related (same company)
                    if self._brands_are_related(brand, matching_brand):
                        continue  # Related brands, not impersonation
                
                # If we're NOT on a legitimate domain for this brand, it's impersonation
                if current_domain not in legitimate_domains:
                    impersonated_brands.append(brand)
        
        return {
            "brands_mentioned": brands_mentioned,
            "impersonated_brands": impersonated_brands,
        }

    def _brands_are_related(self, brand1: str | None, brand2: str | None) -> bool:
        """Check if two brands are related (same parent company)."""
        if not brand1 or not brand2:
            return False
            
        # Define brand relationships (same company)
        related_brands = [
            {"facebook", "instagram", "whatsapp", "messenger", "meta"},
            {"google", "youtube", "gmail"},
            {"microsoft", "linkedin", "github", "outlook", "xbox"},
            {"apple", "icloud"},
        ]
        
        for group in related_brands:
            if brand1 in group and brand2 in group:
                return True
        
        return False

    @staticmethod
    def _extract_title(content: str) -> str:
        """Extract page title from HTML."""
        try:
            match = re.search(
                r"<title>(.*?)</title>", content, re.IGNORECASE | re.DOTALL
            )
            return match.group(1).strip() if match else ""
        except Exception:
            return ""
