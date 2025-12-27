"""API endpoints for victim company cataloging and phishing campaign management."""

import uuid
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from phisherman.api.dependencies import get_db_session
from phisherman.datastore.victim_models import (
    CampaignStatusEnum,
    IndustryEnum,
    PhishingCampaign,
    VictimCompany,
    VictimUrl,
)

router = APIRouter(tags=["victims"], prefix="/victims")


# Pydantic schemas for API
class VictimCompanyResponse(BaseModel):
    """Response schema for victim company data."""

    id: str
    name: str
    normalized_name: str
    industry: IndustryEnum
    country: str | None = None
    total_phishing_urls: int
    active_campaigns: int
    risk_score: float
    official_domains: list[str]
    brand_keywords: list[str]
    first_seen: datetime
    last_updated: datetime

    class Config:
        from_attributes = True


class PhishingCampaignResponse(BaseModel):
    """Response schema for phishing campaign data."""

    id: str
    name: str
    victim_company_name: str
    status: CampaignStatusEnum
    attack_vector: str
    total_urls: int
    active_urls: int
    first_observed: datetime
    last_observed: datetime
    common_themes: list[str]
    target_regions: list[str]

    class Config:
        from_attributes = True


class VictimStatsResponse(BaseModel):
    """Response schema for victim statistics."""

    total_companies: int
    total_campaigns: int
    total_phishing_urls: int
    by_industry: dict[str, int]
    by_status: dict[str, int]
    trending_victims: list[dict[str, Any]]
    recent_campaigns: list[dict[str, Any]]


class VictimUrlResponse(BaseModel):
    """Response schema for victim URL associations."""

    id: str
    url: str  # From related UrlScan
    victim_company_name: str
    campaign_name: str | None
    impersonation_type: str
    similarity_score: float
    deception_techniques: list[str]
    auto_classified: bool
    classification_confidence: float
    human_verified: bool
    discovered_at: datetime


@router.get("/", response_model=list[VictimCompanyResponse])
async def list_victim_companies(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, le=100, description="Number of records to return"),
    industry: IndustryEnum | None = Query(None, description="Filter by industry"),
    min_risk_score: float
    | None = Query(None, ge=0, le=100, description="Minimum risk score"),
    search: str | None = Query(None, description="Search in company names"),
    sort_by: str = Query("risk_score", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    db: AsyncSession = Depends(get_db_session),
) -> list[VictimCompanyResponse]:
    """
    List victim companies with filtering and pagination.

    Provides comprehensive listing of companies being targeted by phishing attacks,
    with filtering options for B2B clients and research purposes.
    """

    # Build query
    stmt = select(VictimCompany)

    # Apply filters
    if industry:
        stmt = stmt.where(VictimCompany.industry == industry)

    if min_risk_score is not None:
        stmt = stmt.where(VictimCompany.risk_score >= min_risk_score)

    if search:
        search_pattern = f"%{search.lower()}%"
        stmt = stmt.where(
            VictimCompany.normalized_name.like(search_pattern)
            | VictimCompany.name.ilike(search_pattern)
        )

    # Apply sorting
    sort_column = getattr(VictimCompany, sort_by, VictimCompany.risk_score)
    if sort_order == "desc":
        stmt = stmt.order_by(sort_column.desc())
    else:
        stmt = stmt.order_by(sort_column.asc())

    # Apply pagination
    stmt = stmt.offset(skip).limit(limit)

    result = await db.execute(stmt)
    companies = result.scalars().all()

    return [
        VictimCompanyResponse(
            id=str(company.id),
            name=company.name,
            normalized_name=company.normalized_name,
            industry=company.industry,
            country=company.country,
            total_phishing_urls=company.total_phishing_urls,
            active_campaigns=company.active_campaigns,
            risk_score=company.risk_score,
            official_domains=company.official_domains,
            brand_keywords=company.brand_keywords,
            first_seen=company.first_seen,
            last_updated=company.last_updated,
        )
        for company in companies
    ]


@router.get("/stats", response_model=VictimStatsResponse)
async def get_victim_statistics(
    days: int = Query(30, ge=1, le=365, description="Time period in days"),
    db: AsyncSession = Depends(get_db_session),
) -> VictimStatsResponse:
    """
    Get comprehensive statistics about victim companies and phishing campaigns.

    Provides high-level metrics for dashboards and business intelligence.
    Useful for both internal monitoring and B2B reporting.
    """

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Total counts
    total_companies_result = await db.execute(select(func.count(VictimCompany.id)))
    total_companies = total_companies_result.scalar()

    total_campaigns_result = await db.execute(select(func.count(PhishingCampaign.id)))
    total_campaigns = total_campaigns_result.scalar()

    total_urls_result = await db.execute(select(func.count(VictimUrl.id)))
    total_urls = total_urls_result.scalar()

    # By industry
    industry_stats = await db.execute(
        select(VictimCompany.industry, func.count(VictimCompany.id)).group_by(
            VictimCompany.industry
        )
    )
    by_industry = {industry.value: count for industry, count in industry_stats}

    # By campaign status
    status_stats = await db.execute(
        select(PhishingCampaign.status, func.count(PhishingCampaign.id)).group_by(
            PhishingCampaign.status
        )
    )
    by_status = {status.value: count for status, count in status_stats}

    # Trending victims (most targeted recently)
    trending_stmt = (
        select(
            VictimCompany.name,
            VictimCompany.industry,
            func.count(VictimUrl.id).label("recent_urls"),
        )
        .join(VictimUrl)
        .where(VictimUrl.discovered_at >= cutoff_date)
        .group_by(VictimCompany.id, VictimCompany.name, VictimCompany.industry)
        .order_by(func.count(VictimUrl.id).desc())
        .limit(10)
    )

    trending_result = await db.execute(trending_stmt)
    trending_victims = [
        {"name": name, "industry": industry.value, "recent_urls": count}
        for name, industry, count in trending_result
    ]

    # Recent campaigns
    recent_campaigns_stmt = (
        select(
            PhishingCampaign.name,
            VictimCompany.name.label("victim_name"),
            PhishingCampaign.status,
            PhishingCampaign.total_urls,
            PhishingCampaign.first_observed,
        )
        .join(VictimCompany)
        .where(PhishingCampaign.first_observed >= cutoff_date)
        .order_by(PhishingCampaign.first_observed.desc())
        .limit(10)
    )

    recent_campaigns_result = await db.execute(recent_campaigns_stmt)
    recent_campaigns = [
        {
            "name": campaign_name,
            "victim_name": victim_name,
            "status": status.value,
            "total_urls": total_urls,
            "first_observed": first_observed.isoformat(),
        }
        for campaign_name, victim_name, status, total_urls, first_observed in recent_campaigns_result
    ]

    return VictimStatsResponse(
        total_companies=total_companies,
        total_campaigns=total_campaigns,
        total_phishing_urls=total_urls,
        by_industry=by_industry,
        by_status=by_status,
        trending_victims=trending_victims,
        recent_campaigns=recent_campaigns,
    )


@router.get("/{company_id}", response_model=VictimCompanyResponse)
async def get_victim_company(
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> VictimCompanyResponse:
    """
    Get detailed information about a specific victim company.

    Provides comprehensive data about a company being targeted,
    including all associated campaigns and statistics.
    """

    stmt = select(VictimCompany).where(VictimCompany.id == company_id)
    result = await db.execute(stmt)
    company = result.scalar_one_or_none()

    if not company:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Victim company not found"
        )

    return VictimCompanyResponse(
        id=str(company.id),
        name=company.name,
        normalized_name=company.normalized_name,
        industry=company.industry,
        country=company.country,
        total_phishing_urls=company.total_phishing_urls,
        active_campaigns=company.active_campaigns,
        risk_score=company.risk_score,
        official_domains=company.official_domains,
        brand_keywords=company.brand_keywords,
        first_seen=company.first_seen,
        last_updated=company.last_updated,
    )


@router.get("/{company_id}/campaigns", response_model=list[PhishingCampaignResponse])
async def get_victim_campaigns(
    company_id: uuid.UUID,
    status_filter: CampaignStatusEnum
    | None = Query(None, description="Filter by campaign status"),
    db: AsyncSession = Depends(get_db_session),
) -> list[PhishingCampaignResponse]:
    """
    Get all phishing campaigns targeting a specific company.

    Shows the organized campaigns and attack patterns against a victim company.
    Valuable for threat intelligence and security analysis.
    """

    stmt = (
        select(PhishingCampaign)
        .options(selectinload(PhishingCampaign.victim_company))
        .where(PhishingCampaign.victim_company_id == company_id)
    )

    if status_filter:
        stmt = stmt.where(PhishingCampaign.status == status_filter)

    stmt = stmt.order_by(PhishingCampaign.last_observed.desc())

    result = await db.execute(stmt)
    campaigns = result.scalars().all()

    return [
        PhishingCampaignResponse(
            id=str(campaign.id),
            name=campaign.name,
            victim_company_name=campaign.victim_company.name,
            status=campaign.status,
            attack_vector=campaign.attack_vector,
            total_urls=campaign.total_urls,
            active_urls=campaign.active_urls,
            first_observed=campaign.first_observed,
            last_observed=campaign.last_observed,
            common_themes=campaign.common_themes,
            target_regions=campaign.target_regions,
        )
        for campaign in campaigns
    ]


@router.get("/{company_id}/urls", response_model=list[VictimUrlResponse])
async def get_victim_urls(
    company_id: uuid.UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=100),
    verified_only: bool = Query(False, description="Only show human-verified URLs"),
    db: AsyncSession = Depends(get_db_session),
) -> list[VictimUrlResponse]:
    """
    Get phishing URLs targeting a specific company.

    Provides the actual malicious URLs with classification details.
    Essential for security teams and threat intelligence.
    """
    # Build query with eager loading of related entities
    stmt = (
        select(VictimUrl)
        .options(
            selectinload(VictimUrl.url_scan),
            selectinload(VictimUrl.victim_company),
            selectinload(VictimUrl.campaign),
        )
        .where(VictimUrl.victim_company_id == company_id)
    )

    if verified_only:
        stmt = stmt.where(VictimUrl.human_verified)

    stmt = stmt.order_by(VictimUrl.discovered_at.desc()).offset(skip).limit(limit)

    result = await db.execute(stmt)
    victim_urls = result.scalars().all()

    return [
        VictimUrlResponse(
            id=str(victim_url.id),
            url=victim_url.url_scan.url if victim_url.url_scan else "[URL not found]",
            victim_company_name=(
                victim_url.victim_company.name
                if victim_url.victim_company
                else "[Company not found]"
            ),
            campaign_name=(
                victim_url.campaign.name if victim_url.campaign else None
            ),
            impersonation_type=victim_url.impersonation_type,
            similarity_score=victim_url.similarity_score,
            deception_techniques=victim_url.deception_techniques,
            auto_classified=victim_url.auto_classified,
            classification_confidence=victim_url.classification_confidence,
            human_verified=victim_url.human_verified,
            discovered_at=victim_url.discovered_at,
        )
        for victim_url in victim_urls
    ]


@router.get("/industry/{industry}/trends", response_model=dict[str, Any])
async def get_industry_trends(
    industry: IndustryEnum,
    days: int = Query(90, ge=7, le=365, description="Time period for trend analysis"),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """
    Get phishing trends for a specific industry.

    Analyzes attack patterns, trending techniques, and threat evolution
    within an industry sector. Valuable for industry-specific threat intelligence.
    """

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Companies in this industry
    companies_stmt = select(VictimCompany).where(VictimCompany.industry == industry)
    companies_result = await db.execute(companies_stmt)
    companies = companies_result.scalars().all()
    company_ids = [c.id for c in companies]

    if not company_ids:
        return {
            "industry": industry.value,
            "message": "No companies found in this industry",
            "total_companies": 0,
        }

    # Trend analysis
    urls_stmt = (
        select(
            func.date_trunc("week", VictimUrl.discovered_at).label("week"),
            func.count(VictimUrl.id).label("url_count"),
        )
        .where(
            VictimUrl.victim_company_id.in_(company_ids),
            VictimUrl.discovered_at >= cutoff_date,
        )
        .group_by("week")
        .order_by("week")
    )

    trend_result = await db.execute(urls_stmt)
    weekly_trends = [
        {"week": week.isoformat(), "url_count": count} for week, count in trend_result
    ]

    # Top deception techniques in this industry
    techniques_stmt = (
        select(
            func.unnest(VictimUrl.deception_techniques).label("technique"),
            func.count().label("count"),
        )
        .where(
            VictimUrl.victim_company_id.in_(company_ids),
            VictimUrl.discovered_at >= cutoff_date,
        )
        .group_by("technique")
        .order_by(func.count().desc())
        .limit(10)
    )

    techniques_result = await db.execute(techniques_stmt)
    top_techniques = [
        {"technique": technique, "count": count}
        for technique, count in techniques_result
    ]

    return {
        "industry": industry.value,
        "period_days": days,
        "total_companies": len(companies),
        "weekly_trends": weekly_trends,
        "top_deception_techniques": top_techniques,
        "most_targeted_companies": [
            {
                "name": c.name,
                "risk_score": c.risk_score,
                "total_urls": c.total_phishing_urls,
            }
            for c in sorted(companies, key=lambda x: x.risk_score, reverse=True)[:5]
        ],
    }
