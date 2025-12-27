"""Tests for VictimClassifier service."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

# Import all models to ensure SQLAlchemy registers them
from phisherman.datastore import (
    CampaignStatusEnum,
    IndustryEnum,
    PhishingCampaign,
    UrlScan,  # noqa: F401 - needed for relationship registration
    VictimCompany,
    VictimUrl,
)
from phisherman.services.victim_classifier import VictimClassifier


class TestVictimClassifier:
    """Tests for VictimClassifier service."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async database session."""
        session = MagicMock()
        session.execute = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        session.get = AsyncMock()
        return session

    @pytest.fixture
    def classifier(self, mock_session):
        """Create classifier with mock session."""
        return VictimClassifier(mock_session)

    @pytest.fixture
    def sample_company(self):
        """Create a sample victim company."""
        return VictimCompany(
            id=uuid4(),
            name="PayPal",
            normalized_name="paypal",
            industry=IndustryEnum.BANKING,
            official_domains=["paypal.com", "paypal.me"],
            official_tlds=["com", "me"],
            brand_keywords=["paypal", "pay-pal"],
            common_misspellings=["payp4l", "paypaI"],
            total_phishing_urls=0,
            active_campaigns=0,
            risk_score=0.0,
        )

    def test_classifier_initialization(self, classifier):
        """Test classifier initializes with high value brands."""
        assert "paypal" in classifier.high_value_brands
        assert "apple" in classifier.high_value_brands
        assert "microsoft" in classifier.high_value_brands
        assert "google" in classifier.high_value_brands

    def test_industry_patterns(self, classifier):
        """Test industry patterns are properly configured."""
        assert IndustryEnum.BANKING in classifier.industry_patterns
        assert "paypal" in classifier.industry_patterns[IndustryEnum.BANKING]
        assert "amazon" in classifier.industry_patterns[IndustryEnum.ECOMMERCE]
        assert "facebook" in classifier.industry_patterns[IndustryEnum.SOCIAL_MEDIA]

    def test_calculate_domain_similarity(self, classifier):
        """Test domain similarity calculation."""
        # Exact match
        similarity = classifier._calculate_domain_similarity("paypal.com", "paypal.com")
        assert similarity == 1.0

        # Very similar (typosquatting)
        similarity = classifier._calculate_domain_similarity("paypa1.com", "paypal.com")
        assert similarity > 0.8

        # Completely different
        similarity = classifier._calculate_domain_similarity("google.com", "paypal.com")
        assert similarity < 0.5

        # With www prefix (should be stripped)
        similarity = classifier._calculate_domain_similarity(
            "www.paypal.com", "paypal.com"
        )
        assert similarity == 1.0

    def test_determine_impersonation_type_subdomain_abuse(self, classifier):
        """Test subdomain abuse detection."""
        result = classifier._determine_impersonation_type(
            "login.paypal.malicious.com", "paypal.com"
        )
        # This would be domain_similarity since it doesn't end with .paypal.com
        assert result in ["subdomain_abuse", "domain_similarity", "domain_squatting"]

    def test_determine_impersonation_type_typosquatting(self, classifier):
        """Test typosquatting detection."""
        result = classifier._determine_impersonation_type("paypa1.com", "paypal.com")
        assert result == "typosquatting"

    def test_is_typosquatting(self, classifier):
        """Test typosquatting check."""
        # One character difference
        assert classifier._is_typosquatting("paypa1.com", "paypal.com") is True
        assert classifier._is_typosquatting("paypall.com", "paypal.com") is True

        # Too different
        assert classifier._is_typosquatting("google.com", "paypal.com") is False

    def test_uses_similar_tld(self, classifier):
        """Test TLD confusion detection."""
        assert classifier._uses_similar_tld("paypal.co", "paypal.com") is True
        assert classifier._uses_similar_tld("paypal.cm", "paypal.com") is True
        assert classifier._uses_similar_tld("paypal.org", "paypal.com") is False

    def test_calculate_keyword_confidence(self, classifier):
        """Test keyword confidence calculation."""
        # Keyword in domain - higher confidence
        url = "https://paypal-verify.com/login"
        confidence = classifier._calculate_keyword_confidence(url, "paypal")
        assert confidence >= 0.8

        # Keyword only in path - lower confidence
        url = "https://malicious.com/paypal/login"
        confidence = classifier._calculate_keyword_confidence(url, "paypal")
        assert confidence >= 0.5

    def test_analyze_deception_techniques(self, classifier, sample_company):
        """Test deception technique analysis."""
        # URL with misspelling
        url = "https://payp4l-verify.com/login"
        techniques = classifier._analyze_deception_techniques(url, sample_company)
        assert "brand_misspelling" in techniques

        # URL with excessive subdomains
        url = "https://a.b.c.d.e.paypal.fake.com/login"
        techniques = classifier._analyze_deception_techniques(url, sample_company)
        assert "excessive_subdomains" in techniques

        # URL with suspicious TLD
        url = "https://paypal-login.tk/verify"
        techniques = classifier._analyze_deception_techniques(url, sample_company)
        assert "suspicious_tld" in techniques

        # URL with numeric substitution
        url = "https://paypa1-l0gin.com/verify"
        techniques = classifier._analyze_deception_techniques(url, sample_company)
        assert "numeric_substitution" in techniques

    def test_is_high_value_target(self, classifier, sample_company):
        """Test high value target detection."""
        # Banking is high value
        sample_company.industry = IndustryEnum.BANKING
        assert classifier._is_high_value_target(sample_company) is True

        # Crypto is high value
        sample_company.industry = IndustryEnum.CRYPTOCURRENCY
        assert classifier._is_high_value_target(sample_company) is True

        # Social media is not high value (unless premium)
        sample_company.industry = IndustryEnum.SOCIAL_MEDIA
        sample_company.is_premium = False
        assert classifier._is_high_value_target(sample_company) is False

        # Premium is always high value
        sample_company.is_premium = True
        assert classifier._is_high_value_target(sample_company) is True

    def test_select_best_classification(self, classifier, sample_company):
        """Test best classification selection."""
        results = [
            ("domain_pattern", (sample_company, 0.7, "typosquatting")),
            ("keyword_pattern", (sample_company, 0.9, "keyword_impersonation")),
            ("content_analysis", (sample_company, 0.6, "content_impersonation")),
        ]

        best = classifier._select_best_classification(results)

        assert best is not None
        assert best[0] == "keyword_pattern"  # Highest confidence
        assert best[1][1] == 0.9

    def test_select_best_classification_empty(self, classifier):
        """Test best classification with empty results."""
        result = classifier._select_best_classification([])
        assert result is None

    @pytest.mark.asyncio
    async def test_classify_by_domain_patterns(self, classifier, mock_session, sample_company):
        """Test domain pattern classification."""
        # Mock database to return sample company
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_company]
        mock_session.execute.return_value = mock_result

        # Similar domain to paypal.com
        result = await classifier._classify_by_domain_patterns("paypa1.com")

        assert result is not None
        company, confidence, impersonation_type = result
        assert company.name == "PayPal"
        assert confidence > 0.7
        assert impersonation_type == "typosquatting"

    @pytest.mark.asyncio
    async def test_classify_by_domain_patterns_no_match(
        self, classifier, mock_session
    ):
        """Test domain pattern classification with no match."""
        # Mock database to return empty result
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        result = await classifier._classify_by_domain_patterns("completely-random.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_classify_by_keywords(self, classifier, mock_session, sample_company):
        """Test keyword-based classification."""
        # Mock database to return sample company
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_company
        mock_session.execute.return_value = mock_result

        result = await classifier._classify_by_keywords(
            "https://fake-paypal-verify.com/login"
        )

        assert result is not None
        company, confidence, impersonation_type = result
        assert company.name == "PayPal"
        assert impersonation_type == "keyword_impersonation"

    @pytest.mark.asyncio
    async def test_classify_by_keywords_new_company(self, classifier, mock_session):
        """Test keyword classification that creates new company."""
        # Mock database to return no existing company first, then succeed on commit
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await classifier._classify_by_keywords(
            "https://fake-paypal-verify.com/login"
        )

        # Should have created a new company
        assert result is not None
        assert mock_session.add.called

    @pytest.mark.asyncio
    async def test_classify_by_brand_patterns(
        self, classifier, mock_session, sample_company
    ):
        """Test brand pattern classification."""
        from phisherman.datastore.victim_models import BrandPattern

        # Create mock pattern
        mock_pattern = MagicMock()
        mock_pattern.pattern_type = "domain"
        mock_pattern.pattern_value = "paypal"
        mock_pattern.confidence = 0.85
        mock_pattern.victim_company_id = sample_company.id

        # Mock database responses
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_pattern]
        mock_session.execute.return_value = mock_result
        mock_session.get.return_value = sample_company

        result = await classifier._classify_by_brand_patterns(
            "https://paypal-fake.com/login"
        )

        assert result is not None
        company, confidence, impersonation_type = result
        assert confidence == 0.85
        assert impersonation_type == "pattern_match"

    @pytest.mark.asyncio
    async def test_classify_by_content(self, classifier, mock_session, sample_company):
        """Test content-based classification."""
        # Mock database to return sample company
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_company
        mock_session.execute.return_value = mock_result

        # Content with brand mention
        content = "<html><title>PayPal Login</title><body>Login to PayPal</body></html>"
        result = await classifier._classify_by_content(content)

        assert result is not None
        company, confidence, impersonation_type = result
        assert company.name == "PayPal"
        # Title mention should increase confidence
        assert confidence >= 0.9
        assert impersonation_type == "content_impersonation"

    @pytest.mark.asyncio
    async def test_classify_url_full_flow(
        self, classifier, mock_session, sample_company
    ):
        """Test full URL classification flow by mocking internal methods."""
        # Mock the classification methods directly to return results
        with patch.object(
            classifier,
            "_classify_by_domain_patterns",
            new_callable=AsyncMock,
            return_value=(sample_company, 0.85, "typosquatting"),
        ), patch.object(
            classifier,
            "_classify_by_keywords",
            new_callable=AsyncMock,
            return_value=None,
        ), patch.object(
            classifier,
            "_classify_by_brand_patterns",
            new_callable=AsyncMock,
            return_value=None,
        ), patch.object(
            classifier,
            "_find_or_create_campaign",
            new_callable=AsyncMock,
            return_value=None,
        ), patch.object(
            classifier,
            "_update_victim_statistics",
            new_callable=AsyncMock,
        ):
            url_scan_id = str(uuid4())
            result = await classifier.classify_url(
                "https://paypa1-login.com/verify", url_scan_id
            )

            # Should have called commit
            assert mock_session.commit.called
            # Should have added victim_url
            assert mock_session.add.called
            # Result should be a VictimUrl
            assert result is not None

    @pytest.mark.asyncio
    async def test_find_or_create_campaign_existing(
        self, classifier, mock_session, sample_company
    ):
        """Test finding existing campaign."""
        existing_campaign = MagicMock()
        existing_campaign.total_urls = 5
        existing_campaign.last_observed = None

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_campaign
        mock_session.execute.return_value = mock_result

        campaign = await classifier._find_or_create_campaign(
            sample_company, "https://fake.com/paypal", "fake.com"
        )

        assert campaign is existing_campaign
        assert campaign.total_urls == 6  # Incremented

    @pytest.mark.asyncio
    async def test_find_or_create_campaign_new(
        self, classifier, mock_session, sample_company
    ):
        """Test creating new campaign."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        campaign = await classifier._find_or_create_campaign(
            sample_company, "https://fake.com/paypal", "new-fake.com"
        )

        assert campaign is not None
        assert campaign.victim_company_id == sample_company.id
        assert mock_session.add.called

    @pytest.mark.asyncio
    async def test_update_victim_statistics(self, classifier, mock_session, sample_company):
        """Test victim statistics update."""
        # Mock URL count
        mock_urls_result = MagicMock()
        mock_urls_result.scalars.return_value.all.return_value = [MagicMock()] * 10  # 10 URLs

        # Mock campaign count
        mock_campaigns_result = MagicMock()
        mock_campaigns_result.scalars.return_value.all.return_value = [MagicMock()] * 2  # 2 campaigns

        call_count = 0

        def execute_side_effect(stmt):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_urls_result
            return mock_campaigns_result

        mock_session.execute.side_effect = execute_side_effect

        await classifier._update_victim_statistics(sample_company)

        assert sample_company.total_phishing_urls == 10
        assert sample_company.active_campaigns == 2
        assert sample_company.risk_score > 0
        assert mock_session.commit.called

