"""
Phisherman Feeds Module - Unified threat intelligence feed processing.

This module provides a shared implementation for parsing and processing
threat intelligence feeds from various sources (PhishTank, OpenPhish, URLhaus, etc.)
"""

from phisherman.feeds.models import FeedResult, ParsedEntry
from phisherman.feeds.processor import FeedProcessor

__all__ = [
    "FeedProcessor",
    "FeedResult",
    "ParsedEntry",
]

