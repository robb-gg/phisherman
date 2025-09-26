"""DNS resolver analyzer for domain reputation and infrastructure analysis."""

import logging
from typing import Any
from urllib.parse import urlparse

import dns.resolver

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.config import settings

logger = logging.getLogger(__name__)


class DnsResolverAnalyzer(BaseAnalyzer):
    """
    Analyzes DNS records to assess domain reputation and infrastructure.

    Performs the following checks:
    - A/AAAA record resolution
    - NS record analysis
    - MX record analysis
    - CNAME chain following
    - TTL analysis for suspicious values
    - SaaS detection via CNAME patterns
    """

    def __init__(self):
        super().__init__(timeout=settings.dns_timeout)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = settings.dns_timeout
        self.resolver.lifetime = settings.dns_timeout

    @property
    def name(self) -> str:
        return "dns_resolver"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.8

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Analyze DNS records for the URL's domain."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        risk_score = 0.0
        labels: list[str] = []
        evidence: dict[str, Any] = {
            "domain": domain,
            "dns_records": {},
        }

        try:
            # A Records
            a_records = await self._resolve_records(domain, "A")
            if a_records:
                evidence["dns_records"]["A"] = a_records
                risk_score += self._analyze_a_records(a_records, labels)
            else:
                risk_score += 30  # No A records is suspicious
                labels.append("no_a_records")

            # AAAA Records (IPv6)
            aaaa_records = await self._resolve_records(domain, "AAAA")
            if aaaa_records:
                evidence["dns_records"]["AAAA"] = aaaa_records

            # CNAME Records and chain following
            cname_info = await self._analyze_cname_chain(domain)
            evidence["dns_records"]["CNAME"] = cname_info
            if cname_info:
                risk_score += self._analyze_cnames(cname_info, labels)

            # NS Records
            ns_records = await self._resolve_records(domain, "NS")
            if ns_records:
                evidence["dns_records"]["NS"] = ns_records
                risk_score += self._analyze_ns_records(ns_records, labels)

            # MX Records
            mx_records = await self._resolve_records(domain, "MX")
            if mx_records:
                evidence["dns_records"]["MX"] = mx_records
                risk_score += self._analyze_mx_records(mx_records, labels)

            # TXT Records (for additional context)
            txt_records = await self._resolve_records(domain, "TXT")
            if txt_records:
                evidence["dns_records"]["TXT"] = txt_records[:5]  # Limit output

        except Exception as e:
            logger.error(f"DNS analysis error for {domain}: {e}")
            risk_score += 20  # DNS errors are mildly suspicious
            labels.append("dns_error")
            evidence["error"] = str(e)

        # Normalize risk score
        risk_score = min(risk_score, 100.0)
        confidence = 0.8 if risk_score > 0 else 0.3

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,  # Will be set by base class
        )

    async def _resolve_records(
        self, domain: str, record_type: str
    ) -> list[dict[str, Any]]:
        """Resolve DNS records of specified type."""
        try:
            answers = self.resolver.resolve(domain, record_type)
            records = []

            for rdata in answers:
                record = {
                    "value": str(rdata),
                    "ttl": answers.ttl,
                }

                # Add record-specific fields
                if record_type == "MX":
                    record["preference"] = rdata.preference
                    record["exchange"] = str(rdata.exchange)
                elif record_type == "NS":
                    record["nameserver"] = str(rdata)

                records.append(record)

            return records

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return []
        except Exception as e:
            logger.debug(f"DNS resolution error for {domain} {record_type}: {e}")
            return []

    async def _analyze_cname_chain(self, domain: str) -> dict[str, Any]:
        """Follow CNAME chain and detect SaaS providers."""
        cname_info = {
            "chain": [],
            "final_target": None,
            "saas_detected": None,
            "chain_length": 0,
        }

        current_domain = domain
        visited = set()

        try:
            while current_domain and current_domain not in visited:
                visited.add(current_domain)

                try:
                    cname_answers = self.resolver.resolve(current_domain, "CNAME")
                    target = str(cname_answers[0]).rstrip(".")

                    cname_info["chain"].append(
                        {
                            "source": current_domain,
                            "target": target,
                            "ttl": cname_answers.ttl,
                        }
                    )

                    # Check for SaaS patterns with PhishTank abuse data
                    saas_provider, risk_info = self._detect_saas_provider(target)
                    if saas_provider:
                        cname_info["saas_detected"] = saas_provider
                        cname_info["saas_risk_info"] = risk_info

                    current_domain = target

                    # Prevent infinite loops
                    if len(cname_info["chain"]) > 10:
                        break

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    break

            cname_info["final_target"] = current_domain
            cname_info["chain_length"] = len(cname_info["chain"])

        except Exception as e:
            logger.debug(f"CNAME chain analysis error for {domain}: {e}")

        return cname_info

    def _detect_saas_provider(self, cname_target: str) -> tuple[str | None, dict]:
        """
        Detect SaaS provider from CNAME target with PhishTank abuse data.

        Returns:
            Tuple of (provider_name, risk_info) where risk_info contains
            abuse data and risk adjustments from the SaaS catalog.
        """
        cname_target = cname_target.lower()

        # Enhanced SaaS provider patterns with PhishTank abuse data
        saas_patterns = {
            "cloudflare": {
                "patterns": ["pages.dev", "cloudflare.net", "cloudflare.com"],
                "risk_adjustment": -2,
                "abuse_frequency": 374,
                "confidence": 0.8,
            },
            "vercel": {
                "patterns": ["vercel-dns.com", "vercel.app", "now.sh"],
                "risk_adjustment": -3,
                "abuse_frequency": 153,
                "confidence": 0.8,
            },
            "netlify": {
                "patterns": ["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
                "risk_adjustment": -4,
                "abuse_frequency": 74,
                "confidence": 0.9,
            },
            "github": {
                "patterns": ["github.io", "github.com", "githubapp.com"],
                "risk_adjustment": -3,
                "abuse_frequency": 208,
                "confidence": 0.8,
            },
            "google": {
                "patterns": [
                    "googlehosted.com",
                    "ghs.google.com",
                    "firebaseapp.com",
                    "web.app",
                ],
                "risk_adjustment": 0,  # Neutral due to high abuse
                "abuse_frequency": 4326,
                "confidence": 0.6,
            },
            "weebly": {
                "patterns": ["weebly.com", "weeblysite.com"],
                "risk_adjustment": 2,  # Positive due to very high abuse
                "abuse_frequency": 4410,
                "confidence": 0.4,
            },
            "wix": {
                "patterns": ["wixsite.com"],
                "risk_adjustment": 0,
                "abuse_frequency": 796,
                "confidence": 0.6,
            },
            "webflow": {
                "patterns": ["webflow.io"],
                "risk_adjustment": 0,
                "abuse_frequency": 787,
                "confidence": 0.6,
            },
            "shopify": {
                "patterns": ["shopify.com", "myshopify.com"],
                "risk_adjustment": -3,
                "abuse_frequency": 3,
                "confidence": 0.9,
            },
            "aws": {
                "patterns": ["amazonaws.com", "cloudfront.net", "elb.amazonaws.com"],
                "risk_adjustment": 0,
                "abuse_frequency": 42,
                "confidence": 0.7,
            },
            "microsoft": {
                "patterns": ["azurefd.net", "trafficmanager.net", "azurewebsites.net"],
                "risk_adjustment": -3,
                "abuse_frequency": 18,
                "confidence": 0.8,
            },
        }

        for provider, provider_data in saas_patterns.items():
            if any(pattern in cname_target for pattern in provider_data["patterns"]):
                return provider, provider_data

        # Check for high-risk patterns from PhishTank data
        high_risk_patterns = {
            "qrco.de": {
                "risk_adjustment": 15,
                "abuse_frequency": 2548,
                "confidence": 0.9,
            },
            "bit.ly": {
                "risk_adjustment": 12,
                "abuse_frequency": 2447,
                "confidence": 0.8,
            },
            "r2.dev": {
                "risk_adjustment": 20,
                "abuse_frequency": 1979,
                "confidence": 0.9,
            },
            "ead.me": {
                "risk_adjustment": 20,
                "abuse_frequency": 1975,
                "confidence": 0.9,
            },
            "t.co": {"risk_adjustment": 8, "abuse_frequency": 413, "confidence": 0.7},
            "tinyurl.com": {
                "risk_adjustment": 8,
                "abuse_frequency": 176,
                "confidence": 0.7,
            },
            "dweb.link": {
                "risk_adjustment": 12,
                "abuse_frequency": 803,
                "confidence": 0.8,
            },
        }

        for pattern, risk_data in high_risk_patterns.items():
            if pattern in cname_target:
                return f"high_risk_{pattern.replace('.', '_')}", risk_data

        return None, {}

    def _analyze_a_records(
        self, a_records: list[dict[str, Any]], labels: list[str]
    ) -> float:
        """Analyze A records for suspicious patterns."""
        risk = 0.0

        # Check for very short TTLs (flux detection)
        min_ttl = min(record["ttl"] for record in a_records)
        if min_ttl < 300:  # Less than 5 minutes
            risk += 15
            labels.append("short_ttl")

        # Check for multiple A records (could indicate load balancing or flux)
        if len(a_records) > 5:
            risk += 10
            labels.append("many_a_records")

        # TODO: Add IP reputation checks, ASN analysis, geolocation checks

        return risk

    def _analyze_cnames(self, cname_info: dict[str, Any], labels: list[str]) -> float:
        """Analyze CNAME records for suspicious patterns with PhishTank data."""
        risk = 0.0

        # Long CNAME chains can be suspicious
        chain_length = cname_info["chain_length"]
        if chain_length > 5:
            risk += 20
            labels.append("long_cname_chain")

        # SaaS hosting analysis with PhishTank abuse data
        if cname_info.get("saas_detected"):
            saas_provider = cname_info["saas_detected"]
            risk_info = cname_info.get("saas_risk_info", {})

            # Apply PhishTank-based risk adjustment
            risk_adjustment = risk_info.get("risk_adjustment", 0)
            abuse_frequency = risk_info.get("abuse_frequency", 0)

            risk += risk_adjustment

            # Add specific labels based on abuse data
            if saas_provider.startswith("high_risk_"):
                labels.append("high_risk_service")
                labels.append(f"pattern_{saas_provider}")
            else:
                labels.append(f"hosted_on_{saas_provider}")

            # Additional risk based on abuse frequency
            if abuse_frequency > 2000:
                labels.append("very_high_abuse_service")
                risk += 5
            elif abuse_frequency > 500:
                labels.append("high_abuse_service")
                risk += 2
            elif abuse_frequency > 100:
                labels.append("moderate_abuse_service")
                risk += 1

        return risk

    def _analyze_ns_records(
        self, ns_records: list[dict[str, Any]], labels: list[str]
    ) -> float:
        """Analyze NS records for suspicious patterns."""
        risk = 0.0

        # Check for suspicious nameserver patterns
        suspicious_ns_patterns = [
            "afraid.org",
            "dynamic",
            "dyn",
            "temp",
            "free",
        ]

        for record in ns_records:
            ns_value = record["value"].lower()
            if any(pattern in ns_value for pattern in suspicious_ns_patterns):
                risk += 10
                labels.append("suspicious_nameserver")
                break

        return risk

    def _analyze_mx_records(
        self, mx_records: list[dict[str, Any]], labels: list[str]
    ) -> float:
        """Analyze MX records for suspicious patterns."""
        risk = 0.0

        # No MX records might indicate a domain not meant for email
        if not mx_records:
            risk += 5
            labels.append("no_mx_records")

        return risk
