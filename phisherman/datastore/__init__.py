"""Database models and data access layer."""

# Import all models to register them with SQLAlchemy
from phisherman.datastore.models import FeedEntry, Indicator, UrlScan, Verdict
from phisherman.datastore.victim_models import (
    BrandPattern,
    CampaignStatusEnum,
    IndustryEnum,
    PhishingCampaign,
    VictimCompany,
    VictimUrl,
)

__all__ = [
    # Base models
    "UrlScan",
    "Indicator",
    "FeedEntry",
    "Verdict",
    # Victim models
    "VictimCompany",
    "PhishingCampaign",
    "VictimUrl",
    "BrandPattern",
    # Enums
    "IndustryEnum",
    "CampaignStatusEnum",
]
