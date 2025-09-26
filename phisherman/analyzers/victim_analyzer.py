"""Victim company analyzer for automatic phishing classification and cataloging."""

import logging
from typing import Any

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.datastore.database import AsyncSessionLocal
from phisherman.services.victim_classifier import VictimClassifier

logger = logging.getLogger(__name__)


class VictimAnalyzer(BaseAnalyzer):
    """
    Analyzer that identifies which companies are being impersonated in phishing URLs.

    This analyzer:
    1. Automatically classifies phishing URLs by victim company
    2. Organizes URLs into phishing campaigns
    3. Builds a database for B2B threat intelligence
    4. Provides educational data for B2C users
    """

    @property
    def name(self) -> str:
        return "victim_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.7  # Moderate weight for classification intelligence

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Analyze URL to identify victim company and classification patterns."""

        risk_score = 0.0
        labels: list[str] = []
        evidence: dict[str, Any] = {
            "url": url,
            "classification_attempted": True,
        }

        try:
            # Use async session for victim classification
            async with AsyncSessionLocal() as session:
                classifier = VictimClassifier(session)

                # For now, we don't have url_scan_id yet, so we'll simulate classification
                # In production, this would be called after URL is stored in database
                classification_result = await self._simulate_classification(
                    classifier, url
                )

                if classification_result:
                    (
                        victim_company,
                        confidence,
                        impersonation_type,
                        campaign_info,
                    ) = classification_result

                    # Increase risk score based on classification
                    risk_score += 20.0  # Base score for identified phishing

                    # Additional risk based on victim company profile
                    if victim_company.get("industry") in [
                        "banking",
                        "cryptocurrency",
                        "government",
                    ]:
                        risk_score += 25.0  # High-value targets
                        labels.append("high_value_target")

                    # Risk adjustment based on impersonation sophistication
                    impersonation_risks = {
                        "typosquatting": 15.0,
                        "subdomain_abuse": 20.0,
                        "domain_squatting": 25.0,
                        "tld_confusion": 10.0,
                        "keyword_impersonation": 12.0,
                    }
                    risk_score += impersonation_risks.get(impersonation_type, 10.0)

                    # Build evidence
                    evidence.update(
                        {
                            "victim_company": {
                                "name": victim_company.get("name"),
                                "industry": victim_company.get("industry"),
                                "risk_profile": victim_company.get("risk_score", 0),
                            },
                            "impersonation": {
                                "type": impersonation_type,
                                "confidence": confidence,
                                "deception_techniques": classification_result[4]
                                if len(classification_result) > 4
                                else [],
                            },
                            "campaign": campaign_info,
                        }
                    )

                    # Add classification labels
                    labels.extend(
                        [
                            "phishing_confirmed",
                            f"impersonates_{victim_company.get('normalized_name', 'unknown')}",
                            f"industry_{victim_company.get('industry', 'other')}",
                            f"technique_{impersonation_type}",
                        ]
                    )

                    # High confidence if auto-classified successfully
                    confidence_score = confidence

                    # Educational value assessment for B2C
                    educational_indicators = self._assess_educational_value(
                        url, impersonation_type, victim_company
                    )
                    if educational_indicators:
                        evidence["educational_value"] = educational_indicators
                        labels.append("educational_example")

                    # B2B intelligence value assessment
                    commercial_value = self._assess_commercial_value(
                        victim_company, campaign_info
                    )
                    if commercial_value:
                        evidence["commercial_value"] = commercial_value
                        labels.append("high_commercial_value")

                else:
                    # No classification found
                    risk_score = 0.0
                    confidence_score = 0.1
                    labels.append("unclassified_potential_phishing")
                    evidence["classification_status"] = "no_victim_identified"

        except Exception as e:
            logger.error(f"Victim analysis error for {url}: {e}")
            risk_score = 0.0
            confidence_score = 0.0
            labels.append("classification_error")
            evidence["error"] = str(e)

        # Normalize risk score
        risk_score = min(risk_score, 100.0)

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence_score,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,
        )

    async def _simulate_classification(self, classifier: VictimClassifier, url: str):
        """
        Simulate victim classification for demonstration.

        In production, this would be integrated with the actual classification
        process after the URL is stored in the database.
        """

        # Simple pattern-based simulation for demo
        url_lower = url.lower()

        # Check for common brands
        brand_patterns = {
            "paypal": {
                "name": "PayPal",
                "normalized_name": "paypal",
                "industry": "banking",
                "risk_score": 85.0,
            },
            "apple": {
                "name": "Apple Inc.",
                "normalized_name": "apple",
                "industry": "technology",
                "risk_score": 75.0,
            },
            "microsoft": {
                "name": "Microsoft Corporation",
                "normalized_name": "microsoft",
                "industry": "technology",
                "risk_score": 70.0,
            },
            "amazon": {
                "name": "Amazon",
                "normalized_name": "amazon",
                "industry": "ecommerce",
                "risk_score": 80.0,
            },
            "google": {
                "name": "Google",
                "normalized_name": "google",
                "industry": "technology",
                "risk_score": 65.0,
            },
        }

        for brand_key, company_info in brand_patterns.items():
            if brand_key in url_lower:
                # Determine impersonation type
                impersonation_type = "domain_squatting"
                if f"{brand_key}-" in url_lower or f"{brand_key}." in url_lower:
                    impersonation_type = "subdomain_abuse"
                elif any(char in url_lower for char in ["0", "1", "2", "3"]):
                    impersonation_type = "typosquatting"

                # Simulate campaign info
                campaign_info = {
                    "estimated_campaign": f"{company_info['name']} targeting campaign",
                    "attack_vector": "web",
                    "sophistication": "medium",
                }

                # Simulate deception techniques
                deception_techniques = ["brand_impersonation"]

                confidence = 0.8
                return (
                    company_info,
                    confidence,
                    impersonation_type,
                    campaign_info,
                    deception_techniques,
                )

        return None

    def _assess_educational_value(
        self, url: str, impersonation_type: str, victim_company: dict[str, Any]
    ) -> dict[str, Any]:
        """Assess educational value for B2C users."""

        educational_value = {}

        # Clear examples of common techniques
        if impersonation_type in ["typosquatting", "subdomain_abuse"]:
            educational_value["technique_example"] = True
            educational_value["difficulty_level"] = "beginner"

        # Well-known brands are good for education
        if victim_company.get("industry") in ["banking", "technology", "ecommerce"]:
            educational_value["brand_recognition"] = "high"
            educational_value["user_familiarity"] = "high"

        # Obvious deception techniques
        if any(char in url.lower() for char in ["0", "1", "2", "3"]):
            educational_value["obvious_deception"] = True
            educational_value["learning_opportunity"] = "numeric_substitution"

        return educational_value

    def _assess_commercial_value(
        self, victim_company: dict[str, Any], campaign_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Assess commercial value for B2B intelligence."""

        commercial_value = {}

        # High-value industries
        high_value_industries = [
            "banking",
            "cryptocurrency",
            "government",
            "healthcare",
        ]
        if victim_company.get("industry") in high_value_industries:
            commercial_value["industry_priority"] = "high"
            commercial_value["compliance_relevant"] = True

        # Campaign sophistication
        if campaign_info.get("sophistication") in ["high", "advanced"]:
            commercial_value["threat_sophistication"] = "high"
            commercial_value["apt_indicators"] = True

        # Targeting assessment
        if victim_company.get("risk_score", 0) > 75:
            commercial_value["targeting_frequency"] = "high"
            commercial_value["threat_landscape_impact"] = "significant"

        return commercial_value
