"""URLhaus feed parser."""

import json
import logging
import zipfile
from io import BytesIO
from typing import Any

import httpx

from phisherman.feeds.models import ParsedEntry
from phisherman.feeds.parsers.base import BaseFeedParser

logger = logging.getLogger(__name__)


class URLhausParser(BaseFeedParser):
    """
    Parser for URLhaus malware URL feed.

    URLhaus provides a JSON feed inside a ZIP archive containing
    malware distribution URLs.
    """

    FEED_URL = "https://urlhaus.abuse.ch/downloads/json/"

    @property
    def feed_name(self) -> str:
        return "urlhaus"

    @property
    def feed_url(self) -> str:
        return self.FEED_URL

    @property
    def timeout(self) -> int:
        """URLhaus can be large, use longer timeout."""
        return 120

    async def parse_response(self, response: httpx.Response) -> list[ParsedEntry]:
        """Parse URLhaus ZIP/JSON response."""
        entries: list[ParsedEntry] = []

        # URLhaus returns a ZIP containing JSON
        try:
            with zipfile.ZipFile(BytesIO(response.content)) as zf:
                json_filename = zf.namelist()[0]
                logger.debug(f"Extracting {json_filename} from ZIP")

                with zf.open(json_filename) as f:
                    json_content = f.read().decode("utf-8")
        except zipfile.BadZipFile:
            # Fallback: maybe it's raw JSON
            json_content = response.text

        data = json.loads(json_content)

        # URLhaus JSON has IDs as keys with arrays of URL entries
        for url_id, url_entries in data.items():
            # Normalize to list
            if not isinstance(url_entries, list):
                url_entries = [url_entries]

            for entry in url_entries:
                parsed = self._parse_entry(url_id, entry)
                if parsed:
                    entries.append(parsed)

        return entries

    def _parse_entry(self, url_id: str, entry: Any) -> ParsedEntry | None:
        """Parse a single URLhaus entry."""
        if not isinstance(entry, dict):
            return None

        url = entry.get("url", "").strip()
        if not url:
            return None

        # Extract tags
        threat_tags = entry.get("tags", [])
        if isinstance(threat_tags, str):
            threat_tags = [threat_tags]
        elif not isinstance(threat_tags, list):
            threat_tags = []

        return ParsedEntry(
            url=url,
            external_id=url_id,
            threat_type="malware",
            confidence=0.9,  # High confidence
            severity="high",
            tags=["malware", "urlhaus"] + threat_tags,
            metadata={
                "urlhaus_id": url_id,
                "dateadded": entry.get("dateadded"),
                "url_status": entry.get("url_status"),
                "threat": entry.get("threat"),
                "tags": threat_tags,
            },
        )
