"""Endpoints para consulta rápida de URLs en feeds."""

import logging
import os

# Importar desde el proyecto principal
import sys
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.append(os.path.join(os.path.dirname(__file__), "../../"))

from phisherman.datastore.database import AsyncSessionLocal
from phisherman.datastore.models import FeedEntry, Indicator
from phisherman.utils.url_normalizer import normalize_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["lookup"])


class URLLookupRequest(BaseModel):
    """Request para consulta de URL."""

    url: str = Field(..., description="URL a consultar")
    normalize: bool = Field(
        default=True, description="Normalizar URL antes de consultar"
    )


class ThreatMatch(BaseModel):
    """Información sobre una coincidencia de threat."""

    threat_type: str
    severity: str
    confidence: float
    source: str
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    extra_data: dict[str, Any] | None = None


class URLLookupResponse(BaseModel):
    """Response de consulta de URL."""

    url: str
    normalized_url: str | None = None
    is_threat: bool
    matches: list[ThreatMatch]
    total_matches: int
    last_checked: datetime


class BulkLookupRequest(BaseModel):
    """Request para consulta masiva de URLs."""

    urls: list[str] = Field(
        ..., max_items=100, description="Lista de URLs (máximo 100)"
    )
    normalize: bool = Field(
        default=True, description="Normalizar URLs antes de consultar"
    )


class BulkLookupResponse(BaseModel):
    """Response de consulta masiva."""

    results: list[URLLookupResponse]
    total_requested: int
    total_threats: int
    processing_time_ms: int


# Dependency para database session
async def get_db() -> AsyncSession:
    """Get database session."""
    async with AsyncSessionLocal() as session:
        yield session


@router.post("/lookup", response_model=URLLookupResponse)
async def lookup_url(
    request: URLLookupRequest, db: AsyncSession = Depends(get_db)
) -> URLLookupResponse:
    """
    Consultar si una URL está catalogada como threat en algún feed.

    Esta es la función principal que usa la API para verificar URLs.
    """
    original_url = request.url.strip()
    normalized_url = None

    try:
        if request.normalize:
            normalized_url = normalize_url(original_url)
            search_url = normalized_url
        else:
            search_url = original_url.lower()

    except Exception as e:
        logger.warning(f"Error normalizing URL {original_url}: {e}")
        search_url = original_url.lower()

    # Buscar en la tabla de indicadores
    stmt = select(Indicator).where(
        or_(
            Indicator.indicator_value == search_url,
            Indicator.indicator_value == original_url.lower(),
        )
    )

    result = await db.execute(stmt)
    indicators = result.scalars().all()

    # Convertir a ThreatMatch
    matches = []
    for indicator in indicators:
        matches.append(
            ThreatMatch(
                threat_type=indicator.threat_type,
                severity=indicator.severity,
                confidence=indicator.confidence,
                source=indicator.source,
                tags=indicator.tags or [],
                first_seen=indicator.first_seen,
                last_seen=indicator.last_seen,
                extra_data=indicator.extra_data,
            )
        )

    return URLLookupResponse(
        url=original_url,
        normalized_url=normalized_url,
        is_threat=len(matches) > 0,
        matches=matches,
        total_matches=len(matches),
        last_checked=datetime.now(UTC),
    )


@router.post("/bulk-lookup", response_model=BulkLookupResponse)
async def bulk_lookup_urls(
    request: BulkLookupRequest, db: AsyncSession = Depends(get_db)
) -> BulkLookupResponse:
    """
    Consulta masiva de URLs para análisis en lote.
    """
    start_time = datetime.now()
    results = []
    threats_found = 0

    for url in request.urls:
        try:
            lookup_request = URLLookupRequest(url=url, normalize=request.normalize)
            result = await lookup_url(lookup_request, db)
            results.append(result)

            if result.is_threat:
                threats_found += 1

        except Exception as e:
            logger.error(f"Error looking up URL {url}: {e}")
            # Añadir resultado vacío en caso de error
            results.append(
                URLLookupResponse(
                    url=url,
                    is_threat=False,
                    matches=[],
                    total_matches=0,
                    last_checked=datetime.now(UTC),
                )
            )

    processing_time = (datetime.now() - start_time).total_seconds() * 1000

    return BulkLookupResponse(
        results=results,
        total_requested=len(request.urls),
        total_threats=threats_found,
        processing_time_ms=int(processing_time),
    )


@router.get("/stats")
async def get_feed_stats(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """
    Obtener estadísticas de los feeds disponibles.
    """
    # Total de indicadores por fuente
    stmt = select(Indicator.source, Indicator.threat_type)
    result = await db.execute(stmt)
    indicators = result.all()

    # Contar por fuente y tipo
    stats_by_source = {}
    stats_by_type = {}

    for indicator in indicators:
        source = indicator.source
        threat_type = indicator.threat_type

        if source not in stats_by_source:
            stats_by_source[source] = 0
        stats_by_source[source] += 1

        if threat_type not in stats_by_type:
            stats_by_type[threat_type] = 0
        stats_by_type[threat_type] += 1

    # Última actualización por feed
    stmt = select(FeedEntry.feed_name, FeedEntry.feed_timestamp).order_by(
        FeedEntry.feed_name, FeedEntry.feed_timestamp.desc()
    )
    result = await db.execute(stmt)
    feed_entries = result.all()

    last_updates = {}
    for entry in feed_entries:
        if entry.feed_name not in last_updates:
            last_updates[entry.feed_name] = entry.feed_timestamp

    return {
        "total_indicators": len(indicators),
        "by_source": stats_by_source,
        "by_threat_type": stats_by_type,
        "last_updates": {
            name: timestamp.isoformat() if timestamp else None
            for name, timestamp in last_updates.items()
        },
        "available_sources": list(stats_by_source.keys()),
        "available_threat_types": list(stats_by_type.keys()),
    }


@router.get("/health")
async def health_check():
    """Health check para el microservicio."""
    return {
        "status": "healthy",
        "service": "feeds-lookup",
        "timestamp": datetime.now(UTC).isoformat(),
    }
