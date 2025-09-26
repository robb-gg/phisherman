"""RDAP/WHOIS analyzer for domain registration information."""

import logging
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
import whois

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.config import settings

logger = logging.getLogger(__name__)


class RdapWhoisAnalyzer(BaseAnalyzer):
    """
    Analyzes domain registration data via RDAP (preferred) or WHOIS fallback.

    Performs the following checks:
    - Domain age analysis
    - Registration patterns
    - Contact information analysis
    - Registrar reputation
    - Privacy protection usage
    - Domain status flags
    """

    def __init__(self):
        super().__init__(timeout=settings.whois_timeout)
        # RDAP bootstrap servers for TLDs
        self.rdap_servers = {
            "com": "https://rdap.verisign.com/com/v1/",
            "net": "https://rdap.verisign.com/net/v1/",
            "org": "https://rdap.publicinterestregistry.org/rdap/",
            "info": "https://rdap.afilias.info/rdap/v1/",
            "biz": "https://rdap.afilias.info/rdap/v1/",
        }

    @property
    def name(self) -> str:
        return "rdap_whois"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.7

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Analyze domain registration data."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        risk_score = 0.0
        labels: list[str] = []
        evidence: dict[str, Any] = {
            "domain": domain,
            "method_used": None,
        }

        # Try RDAP first, fallback to WHOIS
        rdap_data = await self._query_rdap(domain)
        if rdap_data:
            evidence["method_used"] = "rdap"
            evidence["rdap_data"] = rdap_data
            risk_score, labels = self._analyze_rdap_data(rdap_data)
        else:
            # Fallback to WHOIS
            whois_data = await self._query_whois(domain)
            if whois_data:
                evidence["method_used"] = "whois"
                evidence["whois_data"] = whois_data
                risk_score, labels = self._analyze_whois_data(whois_data)
            else:
                risk_score = 40.0  # No registration data is suspicious
                labels.append("no_registration_data")
                evidence["error"] = "Unable to retrieve registration data"

        # Normalize risk score
        risk_score = min(risk_score, 100.0)
        confidence = 0.7 if evidence["method_used"] else 0.3

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,
        )

    async def _query_rdap(self, domain: str) -> dict[str, Any] | None:
        """Query RDAP server for domain information."""
        try:
            tld = domain.split(".")[-1]
            rdap_server = self.rdap_servers.get(tld)

            if not rdap_server:
                return None

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{rdap_server}domain/{domain}",
                    headers={
                        "User-Agent": settings.user_agent,
                        "Accept": "application/json",
                    },
                )

                if response.status_code == 200:
                    return response.json()

        except Exception as e:
            logger.debug(f"RDAP query failed for {domain}: {e}")

        return None

    async def _query_whois(self, domain: str) -> dict[str, Any] | None:
        """Query WHOIS for domain information."""
        try:
            # Use python-whois library
            w = whois.whois(domain)

            # Extract only useful data fields (not methods)
            useful_fields = [
                "domain_name",
                "registrar",
                "whois_server",
                "referral_url",
                "updated_date",
                "creation_date",
                "expiration_date",
                "name_servers",
                "status",
                "emails",
                "dnssec",
                "name",
                "org",
                "address",
                "city",
                "state",
                "zipcode",
                "country",
                "registrant_postal_code",
            ]

            whois_data = {}
            for key in useful_fields:
                if hasattr(w, key):
                    value = getattr(w, key)
                    if value is not None:
                        # Convert dates to ISO format
                        if isinstance(value, datetime):
                            whois_data[key] = value.isoformat()
                        elif isinstance(value, list) and value:
                            # Handle lists (convert dates)
                            converted_list = []
                            for item in value:
                                if isinstance(item, datetime):
                                    converted_list.append(item.isoformat())
                                elif callable(item):
                                    continue  # Skip callable objects
                                else:
                                    converted_list.append(str(item))
                            whois_data[key] = converted_list
                        elif callable(value):
                            continue  # Skip methods/functions
                        else:
                            whois_data[key] = str(value)

            return whois_data if whois_data else None

        except Exception as e:
            logger.debug(f"WHOIS query failed for {domain}: {e}")
            return None

    def _analyze_rdap_data(self, rdap_data: dict[str, Any]) -> tuple[float, list[str]]:
        """Analyze RDAP response data."""
        risk_score = 0.0
        labels: list[str] = []

        try:
            # Domain age analysis
            events = rdap_data.get("events", [])
            registration_date = None

            for event in events:
                if event.get("eventAction") == "registration":
                    registration_date = event.get("eventDate")
                    break

            if registration_date:
                risk_score += self._analyze_domain_age(registration_date, labels)

            # Status analysis
            status_list = rdap_data.get("status", [])
            for status in status_list:
                if "hold" in status.lower() or "lock" in status.lower():
                    risk_score += 5
                    labels.append("domain_locked")
                elif "pending" in status.lower():
                    risk_score += 10
                    labels.append("pending_transfer")

            # Registrar analysis
            entities = rdap_data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    registrar_name = entity.get("vcardArray", [[]])[1:]
                    if registrar_name:
                        # Extract registrar name from vCard
                        for field in registrar_name:
                            if field[0] == "fn":
                                reg_name = field[3].lower()
                                if "godaddy" in reg_name or "namecheap" in reg_name:
                                    # Common registrars, slightly lower risk
                                    risk_score -= 2
                                break

        except Exception as e:
            logger.debug(f"RDAP data analysis error: {e}")
            risk_score += 10
            labels.append("rdap_parse_error")

        return risk_score, labels

    def _analyze_whois_data(
        self, whois_data: dict[str, Any]
    ) -> tuple[float, list[str]]:
        """Analyze WHOIS response data."""
        risk_score = 0.0
        labels: list[str] = []

        try:
            # Domain age analysis
            creation_date = whois_data.get("creation_date")
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                risk_score += self._analyze_domain_age(creation_date, labels)

            # Privacy protection analysis
            registrant = whois_data.get("registrant", "").lower()
            admin_contact = whois_data.get("admin", "").lower()

            privacy_keywords = [
                "privacy",
                "private",
                "redacted",
                "whoisguard",
                "perfect privacy",
            ]
            if any(
                keyword in registrant or keyword in admin_contact
                for keyword in privacy_keywords
            ):
                risk_score += 5
                labels.append("privacy_protection")

            # Registrar analysis
            registrar = whois_data.get("registrar", "").lower()
            if registrar:
                suspicious_registrars = ["publicdomainregistry", "bizcn", "west263"]
                if any(susp in registrar for susp in suspicious_registrars):
                    risk_score += 15
                    labels.append("suspicious_registrar")

            # Contact information analysis
            email = whois_data.get("email", "").lower()
            if email:
                # Suspicious email patterns
                if re.search(r"\d{5,}@", email):  # Lots of numbers
                    risk_score += 10
                    labels.append("suspicious_email")
                elif any(
                    domain in email
                    for domain in ["gmail.com", "yahoo.com", "hotmail.com"]
                ):
                    risk_score += 5
                    labels.append("freemail_registration")

            # Domain status analysis
            status = whois_data.get("status", [])
            if isinstance(status, list):
                for s in status:
                    if "clienthold" in s.lower() or "serverhold" in s.lower():
                        risk_score += 20
                        labels.append("domain_on_hold")

        except Exception as e:
            logger.debug(f"WHOIS data analysis error: {e}")
            risk_score += 10
            labels.append("whois_parse_error")

        return risk_score, labels

    def _analyze_domain_age(self, creation_date: str, labels: list[str]) -> float:
        """Analyze domain age for risk assessment."""
        try:
            if isinstance(creation_date, str):
                # Parse ISO format or common date formats
                try:
                    # Try ISO format first
                    if "T" in creation_date:
                        created = datetime.fromisoformat(
                            creation_date.replace("Z", "+00:00")
                        )
                    else:
                        # Try parsing various date formats
                        created = datetime.strptime(
                            creation_date.split()[0], "%Y-%m-%d"
                        )
                except ValueError:
                    # Try other common formats
                    for fmt in ["%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y"]:
                        try:
                            created = datetime.strptime(creation_date.split()[0], fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        return 5  # Unable to parse, slight risk
            else:
                created = creation_date

            # Make timezone-aware if needed
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)

            now = datetime.now(UTC)
            age_days = (now - created).days

            # Very new domains are suspicious
            if age_days < 30:
                labels.append("very_new_domain")
                return 30
            elif age_days < 90:
                labels.append("new_domain")
                return 20
            elif age_days < 365:
                labels.append("young_domain")
                return 10
            else:
                # Older domains are generally more trustworthy
                labels.append("established_domain")
                return -5  # Slight risk reduction

        except Exception as e:
            logger.debug(f"Domain age analysis error: {e}")
            return 5  # Unable to determine, slight risk

        return 0
