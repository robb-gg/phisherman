#!/usr/bin/env python3
"""
Seed script for victim company cataloging system.

Creates sample victim companies, campaigns, and patterns for testing
the B2B/B2C phishing cataloging features.
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Load environment variables
load_dotenv()


class Settings:
    """Simple settings class that reads from environment variables."""

    @property
    def database_url(self) -> str:
        url = os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://phisherman:password@localhost:5432/phisherman",
        )
        # Ensure we use psycopg for async operations (consistent with main app)
        if "+psycopg" not in url and "postgresql" in url:
            url = url.replace("postgresql://", "postgresql+psycopg://")
        return url


settings = Settings()
from phisherman.datastore.victim_models import (
    BrandPattern,
    CampaignStatusEnum,
    IndustryEnum,
    PhishingCampaign,
    VictimCompany,
)


async def seed_victim_companies():
    """Create sample victim companies for demonstration."""

    engine = create_async_engine(settings.database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Sample companies based on real high-value targets
    companies_data = [
        {
            "name": "PayPal",
            "normalized_name": "paypal",
            "brand_names": ["PayPal", "PayPal Holdings"],
            "industry": IndustryEnum.BANKING,
            "country": "US",
            "market_cap": "large",
            "official_domains": ["paypal.com", "paypal.me", "paypalobjects.com"],
            "official_tlds": ["com", "me"],
            "brand_keywords": ["paypal", "pay-pal", "payp4l"],
            "common_misspellings": ["payp4l", "paypaI", "payp@l", "paypaII"],
            "description": "Digital payments platform frequently targeted by phishing",
            "is_premium": True,
            "risk_score": 85.0,
            "total_phishing_urls": 1247,
            "active_campaigns": 12,
        },
        {
            "name": "Apple Inc.",
            "normalized_name": "apple",
            "brand_names": ["Apple", "Apple Inc.", "iPhone", "iCloud"],
            "industry": IndustryEnum.TECHNOLOGY,
            "country": "US",
            "market_cap": "large",
            "official_domains": ["apple.com", "icloud.com", "me.com", "mac.com"],
            "official_tlds": ["com"],
            "brand_keywords": [
                "apple",
                "iphone",
                "ipad",
                "icloud",
                "itunes",
                "appstore",
            ],
            "common_misspellings": ["appl3", "appIe", "app1e", "applle"],
            "description": "Technology giant with premium brand recognition",
            "is_premium": True,
            "risk_score": 75.0,
            "total_phishing_urls": 892,
            "active_campaigns": 8,
        },
        {
            "name": "Microsoft Corporation",
            "normalized_name": "microsoft",
            "brand_names": ["Microsoft", "Outlook", "Office", "Teams"],
            "industry": IndustryEnum.TECHNOLOGY,
            "country": "US",
            "market_cap": "large",
            "official_domains": [
                "microsoft.com",
                "outlook.com",
                "live.com",
                "hotmail.com",
                "office.com",
            ],
            "official_tlds": ["com"],
            "brand_keywords": [
                "microsoft",
                "outlook",
                "office",
                "teams",
                "windows",
                "azure",
            ],
            "common_misspellings": ["micr0soft", "microsooft", "microsft", "mircosoft"],
            "description": "Cloud and productivity services provider",
            "is_premium": True,
            "risk_score": 70.0,
            "total_phishing_urls": 1156,
            "active_campaigns": 15,
        },
        {
            "name": "Amazon",
            "normalized_name": "amazon",
            "brand_names": ["Amazon", "AWS", "Prime"],
            "industry": IndustryEnum.ECOMMERCE,
            "country": "US",
            "market_cap": "large",
            "official_domains": [
                "amazon.com",
                "amazonaws.com",
                "amazon.co.uk",
                "amzn.to",
            ],
            "official_tlds": ["com", "co.uk", "to"],
            "brand_keywords": ["amazon", "aws", "prime", "kindle"],
            "common_misspellings": ["amazom", "am4zon", "amazone"],
            "description": "E-commerce and cloud computing giant",
            "is_premium": True,
            "risk_score": 80.0,
            "total_phishing_urls": 2341,
            "active_campaigns": 18,
        },
        {
            "name": "Meta Platforms",
            "normalized_name": "meta",
            "brand_names": ["Meta", "Facebook", "Instagram", "WhatsApp"],
            "industry": IndustryEnum.SOCIAL_MEDIA,
            "country": "US",
            "market_cap": "large",
            "official_domains": [
                "meta.com",
                "facebook.com",
                "instagram.com",
                "whatsapp.com",
            ],
            "official_tlds": ["com"],
            "brand_keywords": [
                "meta",
                "facebook",
                "instagram",
                "whatsapp",
                "messenger",
            ],
            "common_misspellings": ["metaa", "faceb00k", "inst4gram"],
            "description": "Social media and metaverse platform",
            "is_premium": True,
            "risk_score": 65.0,
            "total_phishing_urls": 1678,
            "active_campaigns": 22,
        },
        {
            "name": "Coinbase",
            "normalized_name": "coinbase",
            "brand_names": ["Coinbase", "Coinbase Pro"],
            "industry": IndustryEnum.CRYPTOCURRENCY,
            "country": "US",
            "market_cap": "large",
            "official_domains": ["coinbase.com", "pro.coinbase.com", "coinbase.blog"],
            "official_tlds": ["com", "blog"],
            "brand_keywords": ["coinbase", "crypto", "bitcoin", "ethereum"],
            "common_misspellings": ["coinb4se", "coinbas3", "coinbaze"],
            "description": "Cryptocurrency exchange and wallet",
            "is_premium": True,
            "risk_score": 90.0,
            "total_phishing_urls": 567,
            "active_campaigns": 7,
        },
        {
            "name": "Netflix",
            "normalized_name": "netflix",
            "brand_names": ["Netflix"],
            "industry": IndustryEnum.MEDIA,
            "country": "US",
            "market_cap": "large",
            "official_domains": ["netflix.com", "nflxso.net", "nflxext.com"],
            "official_tlds": ["com", "net"],
            "brand_keywords": ["netflix", "streaming"],
            "common_misspellings": ["netf1ix", "netfIix", "netflx"],
            "description": "Streaming entertainment service",
            "is_premium": False,
            "risk_score": 45.0,
            "total_phishing_urls": 234,
            "active_campaigns": 3,
        },
    ]

    async with async_session() as session:
        for company_data in companies_data:
            # Check if company already exists
            existing = await session.get(VictimCompany, company_data.get("id"))
            if existing:
                continue

            company = VictimCompany(
                id=uuid.uuid4(),
                name=company_data["name"],
                normalized_name=company_data["normalized_name"],
                brand_names=company_data["brand_names"],
                industry=company_data["industry"],
                country=company_data.get("country"),
                market_cap=company_data.get("market_cap"),
                official_domains=company_data["official_domains"],
                official_tlds=company_data["official_tlds"],
                brand_keywords=company_data["brand_keywords"],
                common_misspellings=company_data["common_misspellings"],
                description=company_data.get("description"),
                is_premium=company_data.get("is_premium", False),
                risk_score=company_data.get("risk_score", 0.0),
                total_phishing_urls=company_data.get("total_phishing_urls", 0),
                active_campaigns=company_data.get("active_campaigns", 0),
                source="seed_data",
                confidence=1.0,
                first_seen=datetime.now() - timedelta(days=30),
            )

            session.add(company)

        await session.commit()
        print(f"✅ Seeded {len(companies_data)} victim companies")

    await engine.dispose()


async def seed_phishing_campaigns():
    """Create sample phishing campaigns."""

    engine = create_async_engine(settings.database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # Get existing companies
        from sqlalchemy import select

        stmt = select(VictimCompany.id, VictimCompany.name).order_by(VictimCompany.name)
        result = await session.execute(stmt)
        companies = result.all()

        if not companies:
            print("❌ No victim companies found - run seed_victim_companies first")
            return

        # Sample campaigns
        campaigns_data = [
            {
                "company_name": "PayPal",
                "name": "PayPal Invoice Scam 2024",
                "attack_vector": "email",
                "status": CampaignStatusEnum.ACTIVE,
                "common_themes": [
                    "fake_invoice",
                    "account_suspension",
                    "urgent_action",
                ],
                "target_regions": ["US", "UK", "CA", "AU"],
                "languages": ["en"],
                "total_urls": 156,
                "active_urls": 89,
                "domains_count": 23,
                "complexity_level": "high",
                "severity": "high",
            },
            {
                "company_name": "Apple Inc.",
                "name": "iCloud Storage Phishing",
                "attack_vector": "sms",
                "status": CampaignStatusEnum.ACTIVE,
                "common_themes": ["storage_full", "account_locked", "verify_payment"],
                "target_regions": ["US", "UK", "DE", "FR"],
                "languages": ["en", "de", "fr"],
                "total_urls": 78,
                "active_urls": 45,
                "domains_count": 12,
                "complexity_level": "medium",
                "severity": "medium",
            },
            {
                "company_name": "Coinbase",
                "name": "Crypto Wallet Takeover",
                "attack_vector": "web",
                "status": CampaignStatusEnum.ACTIVE,
                "common_themes": [
                    "security_alert",
                    "unauthorized_access",
                    "verify_identity",
                ],
                "target_regions": ["US", "UK", "SG", "JP"],
                "languages": ["en", "ja"],
                "total_urls": 34,
                "active_urls": 28,
                "domains_count": 8,
                "complexity_level": "high",
                "severity": "critical",
            },
        ]

        for campaign_data in campaigns_data:
            # Find the victim company
            company = next(
                (c for c in companies if c.name == campaign_data["company_name"]), None
            )
            if not company:
                continue

            campaign = PhishingCampaign(
                id=uuid.uuid4(),
                name=campaign_data["name"],
                campaign_hash=f"campaign_{company.id}_{campaign_data['name']}"[:64],
                victim_company_id=company.id,
                status=campaign_data["status"],
                attack_vector=campaign_data["attack_vector"],
                complexity_level=campaign_data["complexity_level"],
                common_themes=campaign_data["common_themes"],
                target_regions=campaign_data["target_regions"],
                languages=campaign_data["languages"],
                total_urls=campaign_data["total_urls"],
                active_urls=campaign_data["active_urls"],
                domains_count=campaign_data["domains_count"],
                severity=campaign_data["severity"],
                first_observed=datetime.now() - timedelta(days=15),
                last_observed=datetime.now() - timedelta(hours=2),
                infrastructure_fingerprint={
                    "hosting_patterns": ["bulletproof", "compromised_sites"],
                    "certificate_authorities": ["letsencrypt", "self_signed"],
                    "dns_patterns": ["fast_flux", "domain_generation"],
                },
                ttps={
                    "initial_access": ["spear_phishing", "watering_hole"],
                    "persistence": ["malicious_redirects", "typosquatting"],
                    "evasion": ["url_shorteners", "base64_encoding"],
                },
            )

            session.add(campaign)

        await session.commit()
        print(f"✅ Seeded {len(campaigns_data)} phishing campaigns")

    await engine.dispose()


async def seed_brand_patterns():
    """Create brand detection patterns."""

    engine = create_async_engine(settings.database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # Get existing companies
        from sqlalchemy import select

        stmt = select(
            VictimCompany.id, VictimCompany.name, VictimCompany.brand_keywords
        )
        result = await session.execute(stmt)
        companies = result.all()

        patterns_created = 0

        for company in companies:
            company_id, company_name, brand_keywords = company

            # Create domain patterns for each brand keyword
            for keyword in brand_keywords:
                patterns = [
                    {
                        "pattern_type": "domain",
                        "pattern_value": keyword,
                        "confidence": 0.8,
                    },
                    {
                        "pattern_type": "regex",
                        "pattern_regex": rf"\b{keyword}[0-9]{{1,3}}\b",
                        "confidence": 0.9,
                    },
                    {
                        "pattern_type": "domain",
                        "pattern_value": f"{keyword}-",
                        "confidence": 0.7,
                    },
                ]

                for pattern_data in patterns:
                    pattern = BrandPattern(
                        id=uuid.uuid4(),
                        victim_company_id=company_id,
                        pattern_type=pattern_data["pattern_type"],
                        pattern_value=pattern_data.get("pattern_value", ""),
                        pattern_regex=pattern_data.get("pattern_regex"),
                        confidence=pattern_data["confidence"],
                        false_positive_rate=0.1,
                        is_active=True,
                        created_by="seed_script",
                        matches_count=0,
                        true_positives=0,
                        false_positives=0,
                    )

                    session.add(pattern)
                    patterns_created += 1

        await session.commit()
        print(f"✅ Seeded {patterns_created} brand patterns")

    await engine.dispose()


async def main():
    """Main seeding function."""

    print("🌱 Seeding victim cataloging data...")
    print("")

    try:
        await seed_victim_companies()
        await seed_phishing_campaigns()
        await seed_brand_patterns()

        print("")
        print("🎉 Victim cataloging seed data created successfully!")
        print("")
        print("📊 What was created:")
        print(
            "   - 7 victim companies (PayPal, Apple, Microsoft, Amazon, Meta, Coinbase, Netflix)"
        )
        print("   - 3 active phishing campaigns")
        print("   - Brand detection patterns for automatic classification")
        print("")
        print("🔍 Test the API:")
        print("   GET /api/v1/victims/")
        print("   GET /api/v1/victims/stats")
        print("   GET /api/v1/victims/industry/banking/trends")

    except Exception as e:
        print(f"❌ Error seeding data: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
