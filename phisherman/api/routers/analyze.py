"""URL analysis endpoint."""

import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from phisherman.analyzers.engine import AnalysisEngine
from phisherman.api.dependencies import get_db_session, rate_limit_dependency
from phisherman.api.metrics import ANALYSIS_COUNT
from phisherman.api.schemas import (
    AnalyzerResult,
    UrlAnalysisRequest,
    UrlAnalysisResponse,
)
from phisherman.scorer.linear_scorer import LinearScorer
from phisherman.utils.cache import AnalysisCache
from phisherman.utils.url_normalizer import normalize_url

router = APIRouter(tags=["analysis"], dependencies=[Depends(rate_limit_dependency)])


@router.post("/analyze", response_model=UrlAnalysisResponse)
async def analyze_url(
    request: UrlAnalysisRequest,
    db: AsyncSession = Depends(get_db_session),
) -> UrlAnalysisResponse:
    """
    Analyze a URL for phishing and malware indicators.

    This endpoint runs multiple analyzers against the provided URL and
    combines their results into a final risk score and verdict.

    The analysis includes:
    - DNS resolution and domain reputation
    - WHOIS/RDAP data analysis
    - Blacklist feed checks
    - URL structure heuristics
    - TLS certificate validation (if available)

    Returns a comprehensive analysis with individual analyzer results
    and an overall risk assessment.
    """
    start_time = time.time()
    analysis_id = str(uuid.uuid4())

    try:
        # Normalize the URL
        normalized_url = normalize_url(request.url)

        # Initialize cache
        cache = AnalysisCache(ttl_hours=24)

        # Check for cached result first
        cached_verdict = await cache.get_cached_result(db, normalized_url)

        if cached_verdict:
            # Return cached result
            processing_time = (time.time() - start_time) * 1000

            response = UrlAnalysisResponse(
                url=normalized_url,
                malicious=cached_verdict.is_malicious,
                score=cached_verdict.risk_score,
                confidence=cached_verdict.confidence,
                labels=cached_verdict.labels,
                evidence={},  # Don't store evidence in cache to save space
                analyzers=[],  # Don't store analyzer details in cache
                analysis_id=analysis_id,
                timestamp=datetime.utcnow().isoformat() + "Z",
                processing_time_ms=processing_time,
                cached=True,  # This is cached!
            )

            # Update metrics
            result_label = "malicious" if cached_verdict.is_malicious else "clean"
            ANALYSIS_COUNT.labels(result=result_label).inc()

            return response

        # No cache hit - run full analysis
        # Initialize analysis components
        engine = AnalysisEngine()
        scorer = LinearScorer()

        # Run analysis
        analyzer_results = await engine.analyze(normalized_url)

        # Convert to API schema format
        api_results: list[AnalyzerResult] = []
        for result in analyzer_results:
            api_results.append(
                AnalyzerResult(
                    name=result.analyzer_name,
                    score=result.risk_score,
                    confidence=result.confidence,
                    labels=result.labels,
                    evidence=result.evidence,
                    execution_time_ms=result.execution_time_ms,
                    error=result.error,
                )
            )

        # Calculate final score
        final_result = scorer.calculate_score(analyzer_results)

        # Determine if malicious (configurable threshold, default 70)
        is_malicious = final_result.final_score >= 70.0

        # Aggregate evidence from all analyzers
        aggregated_evidence: dict[str, Any] = {}
        all_labels: list[str] = []

        for result in analyzer_results:
            if result.evidence:
                aggregated_evidence[result.analyzer_name] = result.evidence
            all_labels.extend(result.labels)

        # Remove duplicates while preserving order
        unique_labels = list(dict.fromkeys(all_labels))

        processing_time = (time.time() - start_time) * 1000

        # Store result in cache (async, don't wait)
        try:
            await cache.store_result(
                db=db,
                normalized_url=normalized_url,
                is_malicious=is_malicious,
                risk_score=final_result.final_score,
                confidence=final_result.confidence,
                labels=unique_labels,
                analyzer_version="1.0.0",
                model_version="1.0.0",
            )
        except Exception as cache_error:
            # Log cache error but don't fail the request
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(
                f"Failed to cache result for {normalized_url}: {cache_error}"
            )

        response = UrlAnalysisResponse(
            url=normalized_url,
            malicious=is_malicious,
            score=final_result.final_score,
            confidence=final_result.confidence,
            labels=unique_labels,
            evidence=aggregated_evidence,
            analyzers=api_results,
            analysis_id=analysis_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            processing_time_ms=processing_time,
            cached=False,  # Fresh analysis
        )

        # Update metrics
        result_label = "malicious" if is_malicious else "clean"
        ANALYSIS_COUNT.labels(result=result_label).inc()

        return response

    except ValueError as e:
        # URL validation or normalization error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": 400,
                    "message": str(e),
                    "type": "validation_error",
                }
            },
        ) from e
    except Exception as e:
        # Log the error but don't expose internals
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Analysis failed for URL %s: %s", request.url, e)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": 500,
                    "message": "Analysis failed due to internal error",
                    "type": "analysis_error",
                }
            },
        ) from e
