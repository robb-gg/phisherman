"""Integration tests for database operations.

These tests require PostgreSQL to be running.
Run with: pytest tests/test_integration_db.py -m integration
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from phisherman.datastore.models import Indicator, UrlScan, Verdict
from phisherman.datastore.victim_models import (
    BrandPattern,
    CampaignStatusEnum,
    IndustryEnum,
    PhishingCampaign,
    VictimCompany,
    VictimUrl,
)


@pytest.mark.integration
class TestUrlScanCRUD:
    """Integration tests for UrlScan model CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_url_scan(self, db_session, clean_db, sample_url_scan_data):
        """Test creating a URL scan record."""
        url_scan = UrlScan(**sample_url_scan_data)
        db_session.add(url_scan)
        await db_session.commit()

        # Verify it was saved
        result = await db_session.execute(
            select(UrlScan).where(UrlScan.id == sample_url_scan_data["id"])
        )
        saved_scan = result.scalar_one()

        assert saved_scan.url == sample_url_scan_data["url"]
        assert saved_scan.is_malicious is True
        assert saved_scan.risk_score == 75.0
        assert "suspicious_domain" in saved_scan.labels

    @pytest.mark.asyncio
    async def test_query_url_scans_by_domain(self, db_session, clean_db):
        """Test querying URL scans by domain."""
        # Create multiple scans
        domains = ["evil.com", "malicious.net", "evil.com"]
        for i, domain in enumerate(domains):
            scan = UrlScan(
                id=uuid4(),
                url=f"https://{domain}/page{i}",
                normalized_url=f"https://{domain}/page{i}",
                domain=domain,
                is_malicious=True,
                risk_score=50.0,
                confidence=0.8,
                labels=[],
                evidence={},
                analyzer_results={},
                scan_duration_ms=100.0,
            )
            db_session.add(scan)

        await db_session.commit()

        # Query by domain
        result = await db_session.execute(
            select(UrlScan).where(UrlScan.domain == "evil.com")
        )
        scans = result.scalars().all()

        assert len(scans) == 2

    @pytest.mark.asyncio
    async def test_update_url_scan(self, db_session, clean_db, sample_url_scan_data):
        """Test updating a URL scan record."""
        url_scan = UrlScan(**sample_url_scan_data)
        db_session.add(url_scan)
        await db_session.commit()

        # Update the scan
        url_scan.risk_score = 95.0
        url_scan.labels = ["confirmed_phishing"]
        await db_session.commit()

        # Verify update
        result = await db_session.execute(
            select(UrlScan).where(UrlScan.id == sample_url_scan_data["id"])
        )
        updated_scan = result.scalar_one()

        assert updated_scan.risk_score == 95.0
        assert "confirmed_phishing" in updated_scan.labels


@pytest.mark.integration
class TestVictimCompanyCRUD:
    """Integration tests for VictimCompany model CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_victim_company(self, db_session, clean_db):
        """Test creating a victim company."""
        company = VictimCompany(
            id=uuid4(),
            name="Test Bank",
            normalized_name="test_bank",
            brand_names=["Test Bank", "TestBank"],
            industry=IndustryEnum.BANKING,
            official_domains=["testbank.com"],
            official_tlds=["com"],
            brand_keywords=["testbank", "test-bank"],
            common_misspellings=["testb4nk"],
        )
        db_session.add(company)
        await db_session.commit()

        # Verify
        result = await db_session.execute(
            select(VictimCompany).where(VictimCompany.name == "Test Bank")
        )
        saved_company = result.scalar_one()

        assert saved_company.industry == IndustryEnum.BANKING
        assert "testbank.com" in saved_company.official_domains

    @pytest.mark.asyncio
    async def test_query_companies_by_industry(self, db_session, clean_db):
        """Test querying companies by industry."""
        industries = [
            IndustryEnum.BANKING,
            IndustryEnum.BANKING,
            IndustryEnum.TECHNOLOGY,
            IndustryEnum.ECOMMERCE,
        ]

        for i, industry in enumerate(industries):
            company = VictimCompany(
                id=uuid4(),
                name=f"Company {i}",
                normalized_name=f"company_{i}",
                industry=industry,
                official_domains=[f"company{i}.com"],
                official_tlds=["com"],
                brand_keywords=[f"company{i}"],
            )
            db_session.add(company)

        await db_session.commit()

        # Query banking companies
        result = await db_session.execute(
            select(VictimCompany).where(VictimCompany.industry == IndustryEnum.BANKING)
        )
        banking_companies = result.scalars().all()

        assert len(banking_companies) == 2


@pytest.mark.integration
class TestPhishingCampaignCRUD:
    """Integration tests for PhishingCampaign model CRUD operations."""

    @pytest_asyncio.fixture
    async def victim_company(self, db_session, clean_db):
        """Create a victim company for campaign tests."""
        company = VictimCompany(
            id=uuid4(),
            name="PayPal",
            normalized_name="paypal",
            industry=IndustryEnum.BANKING,
            official_domains=["paypal.com"],
            official_tlds=["com"],
            brand_keywords=["paypal"],
        )
        db_session.add(company)
        await db_session.commit()
        return company

    @pytest.mark.asyncio
    async def test_create_campaign(self, db_session, victim_company):
        """Test creating a phishing campaign."""
        campaign = PhishingCampaign(
            id=uuid4(),
            name="PayPal Credential Theft",
            campaign_hash="unique_hash_123",
            victim_company_id=victim_company.id,
            status=CampaignStatusEnum.ACTIVE,
            attack_vector="email",
            common_themes=["account_verification", "payment_update"],
            target_regions=["US", "UK"],
            total_urls=5,
            active_urls=3,
            domains_count=2,
            first_observed=datetime.now(timezone.utc),
            last_observed=datetime.now(timezone.utc),
        )
        db_session.add(campaign)
        await db_session.commit()

        # Verify
        result = await db_session.execute(
            select(PhishingCampaign).where(
                PhishingCampaign.campaign_hash == "unique_hash_123"
            )
        )
        saved_campaign = result.scalar_one()

        assert saved_campaign.name == "PayPal Credential Theft"
        assert saved_campaign.status == CampaignStatusEnum.ACTIVE
        assert "account_verification" in saved_campaign.common_themes

    @pytest.mark.asyncio
    async def test_campaign_company_relationship(self, db_session, victim_company):
        """Test campaign -> company relationship."""
        campaign = PhishingCampaign(
            id=uuid4(),
            name="Test Campaign",
            campaign_hash="rel_hash_123",
            victim_company_id=victim_company.id,
            attack_vector="web",
            first_observed=datetime.now(timezone.utc),
            last_observed=datetime.now(timezone.utc),
        )
        db_session.add(campaign)
        await db_session.commit()

        # Load campaign with relationship
        result = await db_session.execute(
            select(PhishingCampaign)
            .where(PhishingCampaign.id == campaign.id)
        )
        loaded_campaign = result.scalar_one()

        # Access relationship (may need refresh)
        await db_session.refresh(loaded_campaign, ["victim_company"])
        assert loaded_campaign.victim_company.name == "PayPal"


@pytest.mark.integration
class TestVictimUrlRelationships:
    """Integration tests for VictimUrl relationships."""

    @pytest_asyncio.fixture
    async def setup_data(self, db_session, clean_db):
        """Set up all required data for VictimUrl tests."""
        # Create URL scan
        url_scan = UrlScan(
            id=uuid4(),
            url="https://paypa1-login.evil.com/verify",
            normalized_url="https://paypa1-login.evil.com/verify",
            domain="paypa1-login.evil.com",
            is_malicious=True,
            risk_score=85.0,
            confidence=0.9,
            labels=["phishing"],
            evidence={},
            analyzer_results={},
            scan_duration_ms=150.0,
        )
        db_session.add(url_scan)

        # Create victim company
        company = VictimCompany(
            id=uuid4(),
            name="PayPal",
            normalized_name="paypal",
            industry=IndustryEnum.BANKING,
            official_domains=["paypal.com"],
            official_tlds=["com"],
            brand_keywords=["paypal"],
        )
        db_session.add(company)

        # Create campaign
        campaign = PhishingCampaign(
            id=uuid4(),
            name="PayPal - evil.com",
            campaign_hash="test_hash_456",
            victim_company_id=company.id,
            attack_vector="web",
            first_observed=datetime.now(timezone.utc),
            last_observed=datetime.now(timezone.utc),
        )
        db_session.add(campaign)

        await db_session.commit()

        return {"url_scan": url_scan, "company": company, "campaign": campaign}

    @pytest.mark.asyncio
    async def test_create_victim_url_with_relationships(self, db_session, setup_data):
        """Test creating VictimUrl with all relationships."""
        victim_url = VictimUrl(
            id=uuid4(),
            url_scan_id=setup_data["url_scan"].id,
            victim_company_id=setup_data["company"].id,
            campaign_id=setup_data["campaign"].id,
            impersonation_type="typosquatting",
            similarity_score=0.85,
            deception_techniques=["numeric_substitution", "suspicious_tld"],
            auto_classified=True,
            classification_confidence=0.9,
            classification_method="domain_pattern",
        )
        db_session.add(victim_url)
        await db_session.commit()

        # Query with relationships
        result = await db_session.execute(
            select(VictimUrl).where(VictimUrl.id == victim_url.id)
        )
        loaded_url = result.scalar_one()

        # Refresh to load relationships
        await db_session.refresh(loaded_url, ["url_scan", "victim_company", "campaign"])

        assert loaded_url.url_scan.url == "https://paypa1-login.evil.com/verify"
        assert loaded_url.victim_company.name == "PayPal"
        assert loaded_url.campaign.name == "PayPal - evil.com"

    @pytest.mark.asyncio
    async def test_query_victim_urls_with_joins(self, db_session, setup_data):
        """Test querying VictimUrls with eager loading."""
        from sqlalchemy.orm import selectinload

        # Create multiple victim URLs
        for i in range(3):
            victim_url = VictimUrl(
                id=uuid4(),
                url_scan_id=setup_data["url_scan"].id,
                victim_company_id=setup_data["company"].id,
                campaign_id=setup_data["campaign"].id if i % 2 == 0 else None,
                impersonation_type="typosquatting",
                similarity_score=0.8 + (i * 0.05),
                deception_techniques=["technique_" + str(i)],
                auto_classified=True,
                classification_confidence=0.85,
                classification_method="test",
            )
            db_session.add(victim_url)

        await db_session.commit()

        # Query with eager loading
        result = await db_session.execute(
            select(VictimUrl)
            .options(
                selectinload(VictimUrl.url_scan),
                selectinload(VictimUrl.victim_company),
                selectinload(VictimUrl.campaign),
            )
            .where(VictimUrl.victim_company_id == setup_data["company"].id)
        )
        victim_urls = result.scalars().all()

        assert len(victim_urls) == 3
        # Verify relationships are loaded
        for vu in victim_urls:
            assert vu.url_scan is not None
            assert vu.victim_company is not None


@pytest.mark.integration
class TestIndicatorCRUD:
    """Integration tests for Indicator model."""

    @pytest.mark.asyncio
    async def test_create_indicator(self, db_session, clean_db):
        """Test creating a threat indicator."""
        indicator = Indicator(
            id=uuid4(),
            indicator_type="url",
            indicator_value="https://malicious.com/phishing",
            threat_type="phishing",
            severity="high",
            confidence=0.95,
            source="phishtank",
            source_url="https://phishtank.org/123",
            tags=["phishing", "credential_theft"],
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            is_active=True,
        )
        db_session.add(indicator)
        await db_session.commit()

        # Verify
        result = await db_session.execute(
            select(Indicator).where(Indicator.source == "phishtank")
        )
        saved_indicator = result.scalar_one()

        assert saved_indicator.threat_type == "phishing"
        assert saved_indicator.severity == "high"
        assert "credential_theft" in saved_indicator.tags

    @pytest.mark.asyncio
    async def test_query_active_indicators(self, db_session, clean_db):
        """Test querying active indicators."""
        # Create active and inactive indicators
        for i, is_active in enumerate([True, True, False, True]):
            indicator = Indicator(
                id=uuid4(),
                indicator_type="domain",
                indicator_value=f"domain{i}.com",
                threat_type="malware",
                severity="medium",
                confidence=0.8,
                source="urlhaus",
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                is_active=is_active,
            )
            db_session.add(indicator)

        await db_session.commit()

        # Query active only
        result = await db_session.execute(
            select(Indicator).where(Indicator.is_active == True)  # noqa: E712
        )
        active_indicators = result.scalars().all()

        assert len(active_indicators) == 3


@pytest.mark.integration
class TestVerdictCache:
    """Integration tests for Verdict caching."""

    @pytest.mark.asyncio
    async def test_create_and_retrieve_verdict(self, db_session, clean_db):
        """Test verdict caching workflow."""
        from datetime import timedelta

        verdict = Verdict(
            id=uuid4(),
            url_hash="abc123def456",
            normalized_url="https://example.com/page",
            is_malicious=False,
            risk_score=15.0,
            confidence=0.9,
            labels=["safe"],
            analyzer_version="1.0.0",
            model_version="1.0.0",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            hit_count=0,
        )
        db_session.add(verdict)
        await db_session.commit()

        # Retrieve by hash
        result = await db_session.execute(
            select(Verdict).where(Verdict.url_hash == "abc123def456")
        )
        cached_verdict = result.scalar_one()

        assert cached_verdict.is_malicious is False
        assert cached_verdict.risk_score == 15.0

        # Increment hit count
        cached_verdict.hit_count += 1
        await db_session.commit()

        result = await db_session.execute(
            select(Verdict).where(Verdict.url_hash == "abc123def456")
        )
        updated_verdict = result.scalar_one()
        assert updated_verdict.hit_count == 1

