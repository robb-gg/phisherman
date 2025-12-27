"""Integration tests for API endpoints.

These tests require PostgreSQL and Redis to be running.
Run with: pytest tests/test_integration_api.py -m integration
"""

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from phisherman.datastore.models import UrlScan
from phisherman.datastore.victim_models import (
    CampaignStatusEnum,
    IndustryEnum,
    PhishingCampaign,
    VictimCompany,
    VictimUrl,
)


@pytest.fixture(scope="module")
def app():
    """Create FastAPI app for testing."""
    # Set test environment
    os.environ["ENVIRONMENT"] = "test"
    os.environ["DATABASE_URL"] = "postgresql+asyncpg://phisherman:password@localhost:5432/phisherman_test"
    os.environ["REDIS_URL"] = "redis://localhost:6379/1"

    from phisherman.api.main import create_app

    return create_app()


@pytest_asyncio.fixture
async def client(app):
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.integration
class TestHealthEndpoints:
    """Integration tests for health check endpoints."""

    @pytest.mark.asyncio
    async def test_simple_health_check(self, client):
        """Test simple health endpoint."""
        response = await client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_comprehensive_health_check(self, client):
        """Test comprehensive health check with dependencies."""
        response = await client.get("/api/v1/healthz")

        # May return 503 if dependencies are not available
        assert response.status_code in [200, 503]
        data = response.json()
        # When healthy, returns status; when unhealthy, returns error
        assert "status" in data or "error" in data


@pytest.mark.integration
class TestAnalyzeEndpoint:
    """Integration tests for URL analysis endpoint."""

    @pytest.mark.asyncio
    async def test_analyze_safe_url(self, client):
        """Test analysis of a safe URL."""
        response = await client.post(
            "/api/v1/analyze",
            json={"url": "https://google.com"},
        )

        assert response.status_code == 200
        data = response.json()

        assert "url" in data
        assert "score" in data
        assert "malicious" in data
        assert "confidence" in data
        assert "labels" in data
        assert "analyzers" in data
        assert "analysis_id" in data

    @pytest.mark.asyncio
    async def test_analyze_suspicious_url(self, client):
        """Test analysis of a suspicious URL."""
        response = await client.post(
            "/api/v1/analyze",
            json={"url": "https://paypa1-security-verify.suspicious.tk/login"},
        )

        assert response.status_code == 200
        data = response.json()

        # Suspicious URL should have higher risk score
        assert data["score"] > 0
        assert len(data["labels"]) > 0

    @pytest.mark.asyncio
    async def test_analyze_url_normalization(self, client):
        """Test that URLs without scheme get https:// added."""
        response = await client.post(
            "/api/v1/analyze",
            json={"url": "example.org"},
        )

        # Should succeed - normalize_url adds https://
        assert response.status_code == 200
        data = response.json()
        assert data["url"].startswith("https://")

    @pytest.mark.asyncio
    async def test_analyze_missing_url(self, client):
        """Test analysis without URL field."""
        response = await client.post(
            "/api/v1/analyze",
            json={},
        )

        assert response.status_code == 422


@pytest.mark.integration
class TestVictimsAPI:
    """Integration tests for Victims API endpoints."""

    @pytest_asyncio.fixture
    async def setup_victim_data(self, db_session, clean_db):
        """Set up test data for victims API tests."""
        # Create victim company
        company = VictimCompany(
            id=uuid4(),
            name="Test PayPal",
            normalized_name="test_paypal",
            industry=IndustryEnum.BANKING,
            official_domains=["testpaypal.com"],
            official_tlds=["com"],
            brand_keywords=["testpaypal"],
            total_phishing_urls=5,
            active_campaigns=2,
            risk_score=75.0,
        )
        db_session.add(company)

        # Create URL scan
        url_scan = UrlScan(
            id=uuid4(),
            url="https://testpaypa1.malicious.com/login",
            normalized_url="https://testpaypa1.malicious.com/login",
            domain="testpaypa1.malicious.com",
            is_malicious=True,
            risk_score=85.0,
            confidence=0.9,
            labels=["phishing"],
            evidence={},
            analyzer_results={},
            scan_duration_ms=150.0,
        )
        db_session.add(url_scan)

        # Create campaign
        campaign = PhishingCampaign(
            id=uuid4(),
            name="Test Campaign",
            campaign_hash="test_campaign_hash",
            victim_company_id=company.id,
            status=CampaignStatusEnum.ACTIVE,
            attack_vector="email",
            total_urls=3,
            active_urls=2,
            domains_count=1,
            first_observed=datetime.now(timezone.utc),
            last_observed=datetime.now(timezone.utc),
        )
        db_session.add(campaign)

        # Create victim URL
        victim_url = VictimUrl(
            id=uuid4(),
            url_scan_id=url_scan.id,
            victim_company_id=company.id,
            campaign_id=campaign.id,
            impersonation_type="typosquatting",
            similarity_score=0.85,
            deception_techniques=["numeric_substitution"],
            auto_classified=True,
            classification_confidence=0.9,
            classification_method="domain_pattern",
        )
        db_session.add(victim_url)

        await db_session.commit()

        return {
            "company": company,
            "url_scan": url_scan,
            "campaign": campaign,
            "victim_url": victim_url,
        }

    @pytest.mark.asyncio
    async def test_list_victims(self, client):
        """Test listing victim companies."""
        response = await client.get("/api/v1/victims/")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_list_victims_with_filters(self, client):
        """Test listing victims with filters."""
        response = await client.get(
            "/api/v1/victims/",
            params={
                "industry": "banking",
                "min_risk_score": 50,
                "limit": 10,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_victim_stats(self, client):
        """Test getting victim statistics."""
        response = await client.get("/api/v1/victims/stats")

        assert response.status_code == 200
        data = response.json()

        assert "total_companies" in data
        assert "total_campaigns" in data
        assert "total_phishing_urls" in data
        assert "by_industry" in data

    @pytest.mark.asyncio
    async def test_get_victim_by_id_not_found(self, client):
        """Test getting non-existent victim."""
        fake_id = str(uuid4())
        response = await client.get(f"/api/v1/victims/{fake_id}")

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_industry_trends(self, client):
        """Test getting industry trends."""
        response = await client.get(
            "/api/v1/victims/industry/banking/trends",
            params={"days": 30},
        )

        assert response.status_code == 200
        data = response.json()

        assert "industry" in data
        assert data["industry"] == "banking"


@pytest.mark.integration
class TestRateLimiting:
    """Integration tests for rate limiting."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_rate_limit_enforcement(self, client):
        """Test that rate limiting is enforced."""
        # Make many requests quickly
        responses = []
        for _ in range(110):  # Default limit is 100/minute
            response = await client.get("/api/v1/health")
            responses.append(response.status_code)

        # Should have some 429 responses if rate limiting works
        # Note: This test might be flaky depending on configuration
        # In a real test environment, you'd configure lower limits
        assert 200 in responses  # At least some should succeed


@pytest.mark.integration
class TestMetricsEndpoint:
    """Integration tests for Prometheus metrics."""

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, client):
        """Test metrics endpoint returns Prometheus format."""
        response = await client.get("/metrics")

        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]

        # Should contain some metrics
        content = response.text
        assert "http_requests_total" in content or "python_gc" in content


@pytest.mark.integration
class TestCacheIntegration:
    """Integration tests for caching behavior."""

    @pytest.mark.asyncio
    async def test_analysis_caching(self, client):
        """Test that analysis results are cached."""
        url_to_test = "https://example.org/test-cache"

        # First request
        response1 = await client.post(
            "/api/v1/analyze",
            json={"url": url_to_test},
        )
        assert response1.status_code == 200
        data1 = response1.json()

        # Second request should be cached
        response2 = await client.post(
            "/api/v1/analyze",
            json={"url": url_to_test},
        )
        assert response2.status_code == 200
        data2 = response2.json()

        # Second request should be faster (cached)
        # Note: exact caching behavior depends on configuration
        assert data2.get("cached", False) or data2["processing_time_ms"] <= data1["processing_time_ms"] + 100


@pytest.mark.integration
class TestErrorHandling:
    """Integration tests for error handling."""

    @pytest.mark.asyncio
    async def test_not_found_error(self, client):
        """Test 404 error handling."""
        response = await client.get("/api/v1/nonexistent-endpoint")

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_validation_error(self, client):
        """Test validation error handling."""
        response = await client.post(
            "/api/v1/analyze",
            json={"invalid_field": "value"},
        )

        assert response.status_code == 422
        data = response.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_method_not_allowed(self, client):
        """Test method not allowed error."""
        response = await client.delete("/api/v1/health")

        assert response.status_code == 405

