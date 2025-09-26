"""Prometheus metrics for the API."""

from prometheus_client import Counter, Histogram

# HTTP metrics
REQUEST_COUNT = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)
REQUEST_DURATION = Histogram(
    "http_request_duration_seconds", "HTTP request duration", ["method", "endpoint"]
)

# Analysis metrics
ANALYSIS_COUNT = Counter("url_analyses_total", "Total URL analyses", ["result"])
