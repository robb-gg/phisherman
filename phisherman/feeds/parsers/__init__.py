"""Feed parsers for various threat intelligence sources."""

from phisherman.feeds.parsers.base import BaseFeedParser
from phisherman.feeds.parsers.openphish import OpenPhishParser
from phisherman.feeds.parsers.phishtank import PhishTankParser
from phisherman.feeds.parsers.urlhaus import URLhausParser

__all__ = [
    "BaseFeedParser",
    "PhishTankParser",
    "OpenPhishParser",
    "URLhausParser",
]
