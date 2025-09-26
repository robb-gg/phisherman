"""Tests for API endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from phisherman.api.main import app


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_simple_health_check(self):
        """Test simple health endpoint."""
        with TestClient(app) as client:
            response = client.get("/api/v1/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_comprehensive_health_check(self):
        """Test comprehensive health check."""
        # Mock dependencies to avoid needing real database/redis
        with patch("phisherman.api.routers.health.get_db_session") as mock_db, patch(
            "phisherman.api.routers.health.get_redis_client"
        ) as mock_redis:
            # Mock successful database connection
            mock_db.return_value.__aenter__.return_value.execute.return_value.scalar.return_value = (
                1
            )

            # Mock successful Redis connection
            mock_redis.return_value.ping = AsyncMock(return_value=True)

            async with AsyncClient(app=app, base_url="http://test") as client:
                response = await client.get("/api/v1/healthz")

                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "healthy"
                assert data["database"]
                assert data["redis"]
                assert "uptime_seconds" in data


class TestAnalyzeEndpoint:
    """Tests for URL analysis endpoint."""

    @pytest.mark.asyncio
    async def test_analyze_valid_url(self):
        """Test URL analysis with valid input."""
        # Mock the analysis engine and scorer
        with patch(
            "phisherman.api.routers.analyze.AnalysisEngine"
        ) as mock_engine, patch(
            "phisherman.api.routers.analyze.LinearScorer"
        ) as mock_scorer, patch(
            "phisherman.api.routers.analyze.normalize_url"
        ) as mock_normalize:
            # Mock responses
            mock_normalize.return_value = "https://example.com"
            mock_engine.return_value.analyze.return_value = []
            mock_scorer.return_value.calculate_score.return_value.final_score = 25.0
            mock_scorer.return_value.calculate_score.return_value.confidence = 0.8

            test_payload = {"url": "https://example.com"}

            async with AsyncClient(app=app, base_url="http://test") as client:
                response = await client.post("/api/v1/analyze", json=test_payload)

                assert response.status_code == 200
                data = response.json()
                assert data["url"] == "https://example.com"
                assert "malicious" in data
                assert "score" in data
                assert "confidence" in data
                assert "labels" in data
                assert "evidence" in data
                assert "analyzers" in data

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        """Test URL analysis with invalid input."""
        test_payload = {"url": "not-a-valid-url"}

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post("/api/v1/analyze", json=test_payload)

            # Should return validation error
            assert response.status_code == 400
            data = response.json()
            assert "error" in data

    @pytest.mark.asyncio
    async def test_analyze_missing_url(self):
        """Test URL analysis with missing URL field."""
        test_payload = {}

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post("/api/v1/analyze", json=test_payload)

            # Should return validation error
            assert response.status_code == 422
