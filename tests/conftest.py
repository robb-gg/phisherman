"""Pytest configuration and shared fixtures."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Set test environment before importing app modules
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "DATABASE_URL", "postgresql://phisherman:password@localhost:5432/phisherman_test"
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def database_url() -> str:
    """Get database URL for tests."""
    return os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://phisherman:password@localhost:5432/phisherman_test",
    )


@pytest.fixture(scope="session")
def redis_url() -> str:
    """Get Redis URL for tests."""
    return os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/1")


@pytest_asyncio.fixture(scope="function")
async def async_engine(database_url: str):
    """Create async engine for integration tests."""
    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
    )
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(async_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session for integration tests."""
    async_session_factory = sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def clean_db(db_session: AsyncSession):
    """Clean database tables before test."""
    # Clean in reverse order of foreign key dependencies
    tables = [
        "victim_urls",
        "brand_patterns",
        "phishing_campaigns",
        "victim_companies",
        "verdicts",
        "indicators",
        "feed_entries",
        "url_scans",
    ]

    for table in tables:
        try:
            await db_session.execute(text(f"DELETE FROM {table}"))
        except Exception:
            pass  # Table might not exist

    await db_session.commit()
    yield
    # Cleanup after test
    for table in tables:
        try:
            await db_session.execute(text(f"DELETE FROM {table}"))
        except Exception:
            pass
    await db_session.commit()


@pytest.fixture
def sample_url_scan_data():
    """Sample URL scan data for tests."""
    return {
        "id": uuid4(),
        "url": "https://paypa1-login.malicious.com/verify",
        "normalized_url": "https://paypa1-login.malicious.com/verify",
        "domain": "paypa1-login.malicious.com",
        "is_malicious": True,
        "risk_score": 75.0,
        "confidence": 0.85,
        "labels": ["suspicious_domain", "typosquatting"],
        "evidence": {"domain_analysis": {"similar_to": "paypal.com"}},
        "analyzer_results": {},
        "scan_duration_ms": 250.5,
    }


@pytest.fixture
def sample_victim_company_data():
    """Sample victim company data for tests."""
    return {
        "id": uuid4(),
        "name": "PayPal",
        "normalized_name": "paypal",
        "brand_names": ["PayPal"],
        "industry": "banking",
        "official_domains": ["paypal.com", "paypal.me"],
        "official_tlds": ["com", "me"],
        "brand_keywords": ["paypal", "pay-pal"],
        "common_misspellings": ["payp4l", "paypaI"],
        "total_phishing_urls": 0,
        "active_campaigns": 0,
        "risk_score": 0.0,
    }


@pytest.fixture
def sample_campaign_data(sample_victim_company_data):
    """Sample phishing campaign data for tests."""
    return {
        "id": uuid4(),
        "name": "PayPal - malicious.com",
        "campaign_hash": "abc123def456",
        "victim_company_id": sample_victim_company_data["id"],
        "status": "active",
        "attack_vector": "web",
        "total_urls": 1,
        "active_urls": 1,
        "domains_count": 1,
        "first_observed": datetime.now(UTC),
        "last_observed": datetime.now(UTC),
    }
