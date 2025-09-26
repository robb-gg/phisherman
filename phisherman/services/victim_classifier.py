"""Service for automatic classification of phishing URLs by victim company."""

import hashlib
import logging
import re
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from phisherman.datastore.victim_models import (
    BrandPattern,
    CampaignStatusEnum,
    IndustryEnum,
    PhishingCampaign,
    VictimCompany,
    VictimUrl,
)

logger = logging.getLogger(__name__)


class VictimClassifier:
    """
    Automatic classifier for identifying which companies are being impersonated
    in phishing URLs and organizing them into campaigns.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

        # Common brand keywords and patterns
        self.high_value_brands = {
            # Banking
            "paypal",
            "chase",
            "bankofamerica",
            "wells",
            "citi",
            "santander",
            "hsbc",
            "barclays",
            "lloyds",
            "natwest",
            # Tech giants
            "apple",
            "microsoft",
            "google",
            "amazon",
            "meta",
            "facebook",
            "instagram",
            "netflix",
            "spotify",
            "dropbox",
            "adobe",
            # Ecommerce
            "ebay",
            "aliexpress",
            "walmart",
            "target",
            "bestbuy",
            # Crypto
            "coinbase",
            "binance",
            "kraken",
            "metamask",
            "blockchain",
            # Social/Communication
            "whatsapp",
            "telegram",
            "discord",
            "linkedin",
            "twitter",
            # Cloud/Business
            "salesforce",
            "slack",
            "zoom",
            "teams",
            "office365",
        }

        # Industry classification patterns
        self.industry_patterns = {
            IndustryEnum.BANKING: [
                "bank",
                "credit",
                "financial",
                "loan",
                "mortgage",
                "visa",
                "mastercard",
                "paypal",
                "stripe",
                "square",
                "chase",
                "wells",
                "citi",
            ],
            IndustryEnum.ECOMMERCE: [
                "shop",
                "store",
                "buy",
                "cart",
                "checkout",
                "amazon",
                "ebay",
                "alibaba",
                "walmart",
                "target",
            ],
            IndustryEnum.SOCIAL_MEDIA: [
                "facebook",
                "instagram",
                "twitter",
                "linkedin",
                "tiktok",
                "snapchat",
                "discord",
                "telegram",
            ],
            IndustryEnum.CLOUD_SERVICES: [
                "google",
                "microsoft",
                "amazon",
                "aws",
                "azure",
                "icloud",
                "dropbox",
                "onedrive",
                "gdrive",
            ],
            IndustryEnum.CRYPTOCURRENCY: [
                "bitcoin",
                "crypto",
                "blockchain",
                "coinbase",
                "binance",
                "metamask",
                "wallet",
                "defi",
            ],
        }

    async def classify_url(
        self, url: str, url_scan_id: str, additional_context: dict | None = None
    ) -> VictimUrl | None:
        """
        Classify a phishing URL and determine which company is being impersonated.

        Args:
            url: The malicious URL to classify
            url_scan_id: Reference to the UrlScan record
            additional_context: Additional context like page content, title, etc.

        Returns:
            VictimUrl record if classification successful, None otherwise
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        parsed_url.path.lower()

        # Try different classification methods
        classification_results = []

        # Method 1: Domain-based classification
        domain_result = await self._classify_by_domain_patterns(domain)
        if domain_result:
            classification_results.append(("domain_pattern", domain_result))

        # Method 2: Keyword-based classification
        keyword_result = await self._classify_by_keywords(url)
        if keyword_result:
            classification_results.append(("keyword_pattern", keyword_result))

        # Method 3: Existing brand patterns
        pattern_result = await self._classify_by_brand_patterns(url)
        if pattern_result:
            classification_results.append(("brand_pattern", pattern_result))

        # Method 4: Content-based (if available)
        if additional_context and additional_context.get("page_content"):
            content_result = await self._classify_by_content(
                additional_context["page_content"]
            )
            if content_result:
                classification_results.append(("content_analysis", content_result))

        if not classification_results:
            return None

        # Select best classification result
        best_result = self._select_best_classification(classification_results)

        if not best_result:
            return None

        method, (victim_company, confidence, impersonation_type) = best_result

        # Create or find campaign
        campaign = await self._find_or_create_campaign(victim_company, url, domain)

        # Create VictimUrl record
        victim_url = VictimUrl(
            url_scan_id=url_scan_id,
            victim_company_id=victim_company.id,
            campaign_id=campaign.id if campaign else None,
            impersonation_type=impersonation_type,
            similarity_score=confidence,
            deception_techniques=self._analyze_deception_techniques(
                url, victim_company
            ),
            auto_classified=True,
            classification_confidence=confidence,
            classification_method=method,
            high_value_target=self._is_high_value_target(victim_company),
        )

        self.session.add(victim_url)
        await self.session.commit()

        # Update statistics
        await self._update_victim_statistics(victim_company)

        return victim_url

    async def _classify_by_domain_patterns(
        self, domain: str
    ) -> tuple[VictimCompany, float, str] | None:
        """Classify by analyzing domain patterns like typosquatting, subdomain abuse."""

        # Look for existing companies with similar official domains
        stmt = select(VictimCompany)
        result = await self.session.execute(stmt)
        companies = result.scalars().all()

        for company in companies:
            for official_domain in company.official_domains:
                similarity = self._calculate_domain_similarity(domain, official_domain)

                if similarity > 0.7:  # High similarity threshold
                    impersonation_type = self._determine_impersonation_type(
                        domain, official_domain
                    )
                    return company, similarity, impersonation_type

        return None

    async def _classify_by_keywords(
        self, url: str
    ) -> tuple[VictimCompany, float, str] | None:
        """Classify by looking for brand keywords in the URL."""

        url_lower = url.lower()

        for brand_keyword in self.high_value_brands:
            if brand_keyword in url_lower:
                # Look for existing company with this keyword
                stmt = select(VictimCompany).where(
                    VictimCompany.brand_keywords.contains([brand_keyword])
                )
                result = await self.session.execute(stmt)
                company = result.scalar_one_or_none()

                if company:
                    confidence = self._calculate_keyword_confidence(
                        url_lower, brand_keyword
                    )
                    return company, confidence, "keyword_impersonation"
                else:
                    # Create new company if it doesn't exist
                    company = await self._create_company_from_keyword(brand_keyword)
                    if company:
                        return company, 0.8, "keyword_impersonation"

        return None

    async def _classify_by_brand_patterns(
        self, url: str
    ) -> tuple[VictimCompany, float, str] | None:
        """Classify using existing brand patterns in the database."""

        stmt = select(BrandPattern).where(BrandPattern.is_active)
        result = await self.session.execute(stmt)
        patterns = result.scalars().all()

        for pattern in patterns:
            if pattern.pattern_type == "domain":
                if pattern.pattern_value.lower() in url.lower():
                    # Get associated company
                    company = await self.session.get(
                        VictimCompany, pattern.victim_company_id
                    )
                    if company:
                        return company, pattern.confidence, "pattern_match"

            elif pattern.pattern_type == "regex" and pattern.pattern_regex:
                if re.search(pattern.pattern_regex, url, re.IGNORECASE):
                    company = await self.session.get(
                        VictimCompany, pattern.victim_company_id
                    )
                    if company:
                        return company, pattern.confidence, "regex_match"

        return None

    async def _classify_by_content(
        self, content: str
    ) -> tuple[VictimCompany, float, str] | None:
        """Classify by analyzing page content (titles, forms, etc.)."""

        content_lower = content.lower()

        # Look for brand mentions in content
        for brand_keyword in self.high_value_brands:
            if brand_keyword in content_lower:
                stmt = select(VictimCompany).where(
                    VictimCompany.brand_keywords.contains([brand_keyword])
                )
                result = await self.session.execute(stmt)
                company = result.scalar_one_or_none()

                if company:
                    # Higher confidence if brand appears in title or forms
                    confidence = 0.6
                    if "<title>" in content_lower and brand_keyword in content_lower:
                        confidence = 0.9

                    return company, confidence, "content_impersonation"

        return None

    async def _create_company_from_keyword(self, keyword: str) -> VictimCompany | None:
        """Create a new victim company from a detected brand keyword."""

        # Basic company templates based on known brands
        company_templates = {
            "paypal": {
                "name": "PayPal",
                "industry": IndustryEnum.BANKING,
                "official_domains": ["paypal.com", "paypal.me"],
                "official_tlds": ["com", "me"],
                "brand_keywords": ["paypal", "pay-pal", "payp4l"],
                "common_misspellings": ["payp4l", "paypaI", "payp@l"],
            },
            "apple": {
                "name": "Apple Inc.",
                "industry": IndustryEnum.TECHNOLOGY,
                "official_domains": ["apple.com", "icloud.com", "me.com"],
                "official_tlds": ["com"],
                "brand_keywords": ["apple", "iphone", "ipad", "icloud"],
                "common_misspellings": ["appl3", "appIe", "app1e"],
            },
            "microsoft": {
                "name": "Microsoft Corporation",
                "industry": IndustryEnum.TECHNOLOGY,
                "official_domains": [
                    "microsoft.com",
                    "outlook.com",
                    "live.com",
                    "hotmail.com",
                ],
                "official_tlds": ["com"],
                "brand_keywords": ["microsoft", "outlook", "office", "teams"],
                "common_misspellings": ["micr0soft", "microsooft", "microsft"],
            },
            # Add more templates as needed
        }

        template = company_templates.get(keyword.lower())
        if not template:
            # Generic template
            template = {
                "name": keyword.title(),
                "industry": IndustryEnum.OTHER,
                "official_domains": [],
                "official_tlds": ["com"],
                "brand_keywords": [keyword],
                "common_misspellings": [],
            }

        company = VictimCompany(
            name=template["name"],
            normalized_name=template["name"].lower().replace(" ", "_"),
            industry=template["industry"],
            official_domains=template["official_domains"],
            official_tlds=template["official_tlds"],
            brand_keywords=template["brand_keywords"],
            common_misspellings=template["common_misspellings"],
            source="auto_detection",
            confidence=0.8,
        )

        self.session.add(company)
        await self.session.commit()

        logger.info(
            f"Created new victim company: {company.name} from keyword: {keyword}"
        )
        return company

    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains using edit distance."""

        # Remove common prefixes/suffixes
        domain1_clean = re.sub(r"^(www\.|m\.)", "", domain1)
        domain2_clean = re.sub(r"^(www\.|m\.)", "", domain2)

        # Simple Levenshtein distance calculation
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)

            if len(s2) == 0:
                return len(s1)

            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row

            return previous_row[-1]

        distance = levenshtein_distance(domain1_clean, domain2_clean)
        max_length = max(len(domain1_clean), len(domain2_clean))

        if max_length == 0:
            return 1.0

        return 1.0 - (distance / max_length)

    def _determine_impersonation_type(
        self, malicious_domain: str, legitimate_domain: str
    ) -> str:
        """Determine the type of domain impersonation technique used."""

        if malicious_domain.endswith(f".{legitimate_domain}"):
            return "subdomain_abuse"
        elif legitimate_domain.replace(".", "") in malicious_domain:
            return "domain_squatting"
        elif self._is_typosquatting(malicious_domain, legitimate_domain):
            return "typosquatting"
        elif self._uses_similar_tld(malicious_domain, legitimate_domain):
            return "tld_confusion"
        else:
            return "domain_similarity"

    def _is_typosquatting(self, domain1: str, domain2: str) -> bool:
        """Check if domain1 is a typosquatting variant of domain2."""
        # Simple heuristic: single character difference
        base1 = domain1.split(".")[0]
        base2 = domain2.split(".")[0]

        if abs(len(base1) - len(base2)) <= 1:
            differences = sum(c1 != c2 for c1, c2 in zip(base1, base2, strict=False))
            return differences <= 2

        return False

    def _uses_similar_tld(self, domain1: str, domain2: str) -> bool:
        """Check if domains use confusing TLDs."""
        tld1 = domain1.split(".")[-1]
        tld2 = domain2.split(".")[-1]

        confusing_tlds = [
            ("com", "co"),
            ("com", "cm"),
            ("org", "0rg"),
            ("net", "n3t"),
        ]

        return (tld1, tld2) in confusing_tlds or (tld2, tld1) in confusing_tlds

    def _calculate_keyword_confidence(self, url: str, keyword: str) -> float:
        """Calculate confidence based on keyword placement in URL."""

        confidence = 0.5  # Base confidence

        # Higher confidence if keyword is in domain
        parsed = urlparse(url)
        domain = parsed.netloc

        if keyword in domain:
            confidence += 0.3

        # Higher confidence if keyword appears early in URL
        if url.find(keyword) < 50:
            confidence += 0.2

        return min(confidence, 1.0)

    def _analyze_deception_techniques(
        self, url: str, victim_company: VictimCompany
    ) -> list[str]:
        """Analyze what deception techniques are being used."""

        techniques = []
        url_lower = url.lower()
        parsed = urlparse(url)

        # Check for common techniques
        if any(
            misspelling in url_lower
            for misspelling in victim_company.common_misspellings
        ):
            techniques.append("brand_misspelling")

        if parsed.netloc.count(".") > 3:
            techniques.append("excessive_subdomains")

        if any(
            char in parsed.netloc
            for char in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        ):
            techniques.append("numeric_substitution")

        if any(tld in parsed.netloc for tld in [".tk", ".ml", ".ga", ".cf"]):
            techniques.append("suspicious_tld")

        return techniques

    def _is_high_value_target(self, victim_company: VictimCompany) -> bool:
        """Determine if this is a high-value target for B2B intelligence."""

        # High value industries
        high_value_industries = {
            IndustryEnum.BANKING,
            IndustryEnum.CRYPTOCURRENCY,
            IndustryEnum.TECHNOLOGY,
            IndustryEnum.GOVERNMENT,
        }

        return (
            victim_company.industry in high_value_industries
            or victim_company.is_premium
        )

    def _select_best_classification(
        self, results: list[tuple[str, tuple]]
    ) -> tuple[str, tuple] | None:
        """Select the best classification result from multiple methods."""

        if not results:
            return None

        # Sort by confidence score (third element in the tuple)
        sorted_results = sorted(results, key=lambda x: x[1][1], reverse=True)

        # Return highest confidence result
        return sorted_results[0]

    async def _find_or_create_campaign(
        self, victim_company: VictimCompany, url: str, domain: str
    ) -> PhishingCampaign | None:
        """Find existing campaign or create new one based on clustering heuristics."""

        # Simple campaign clustering based on domain patterns
        campaign_hash = hashlib.sha256(
            f"{victim_company.id}:{domain}".encode()
        ).hexdigest()[:16]

        # Look for existing campaign
        stmt = select(PhishingCampaign).where(
            PhishingCampaign.campaign_hash == campaign_hash
        )
        result = await self.session.execute(stmt)
        existing_campaign = result.scalar_one_or_none()

        if existing_campaign:
            # Update existing campaign
            existing_campaign.total_urls += 1
            existing_campaign.last_observed = func.now()
            return existing_campaign

        # Create new campaign
        campaign = PhishingCampaign(
            name=f"{victim_company.name} - {domain}",
            campaign_hash=campaign_hash,
            victim_company_id=victim_company.id,
            attack_vector="web",
            total_urls=1,
            active_urls=1,
            domains_count=1,
            first_observed=func.now(),
            last_observed=func.now(),
        )

        self.session.add(campaign)
        return campaign

    async def _update_victim_statistics(self, victim_company: VictimCompany) -> None:
        """Update statistics for the victim company."""

        # Count total URLs
        stmt = select(VictimUrl).where(VictimUrl.victim_company_id == victim_company.id)
        result = await self.session.execute(stmt)
        total_urls = len(result.scalars().all())

        # Count active campaigns
        stmt = select(PhishingCampaign).where(
            PhishingCampaign.victim_company_id == victim_company.id,
            PhishingCampaign.status == CampaignStatusEnum.ACTIVE,
        )
        result = await self.session.execute(stmt)
        active_campaigns = len(result.scalars().all())

        # Update company statistics
        victim_company.total_phishing_urls = total_urls
        victim_company.active_campaigns = active_campaigns
        victim_company.risk_score = min(
            100.0, (total_urls * 0.1) + (active_campaigns * 5)
        )

        await self.session.commit()
