"""Tests for TLS Probe analyzer."""

from datetime import UTC
from unittest.mock import AsyncMock, patch

import pytest

from phisherman.analyzers.tls_probe import TlsProbeAnalyzer


class TestTlsProbeAnalyzer:
    """Tests for TLS certificate analyzer."""

    @pytest.fixture
    def analyzer(self):
        return TlsProbeAnalyzer()

    @pytest.mark.asyncio
    async def test_analyzer_properties(self, analyzer):
        """Test analyzer basic properties."""
        assert analyzer.name == "tls_probe"
        assert analyzer.version == "1.0.0"
        assert analyzer.weight == 0.6

    @pytest.mark.asyncio
    async def test_analyze_http_url(self, analyzer):
        """Test analysis of HTTP (non-TLS) URL."""
        result = await analyzer.analyze("http://example.com")

        assert result.analyzer_name == "tls_probe"
        assert result.risk_score == 15.0
        assert "no_tls" in result.labels
        assert result.evidence["tls_available"] is False
        assert result.confidence == 0.9

    @pytest.mark.asyncio
    async def test_analyze_https_url_success(self, analyzer):
        """Test analysis of HTTPS URL with mocked certificate."""
        mock_cert_data = {
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2025-01-01T00:00:00+00:00",
            "age_days": 180,
            "days_until_expiry": 185,
            "subject": {"commonName": "example.com"},
            "common_name": "example.com",
            "issuer": {"commonName": "R3", "organizationName": "Let's Encrypt"},
            "issuer_cn": "R3",
            "issuer_org": "Let's Encrypt",
            "is_self_signed": False,
            "sans": ["example.com", "www.example.com"],
            "serial_number": "abc123",
            "signature_algorithm": "sha256WithRSAEncryption",
        }

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.return_value = mock_cert_data

            result = await analyzer.analyze("https://example.com")

            assert result.analyzer_name == "tls_probe"
            assert result.evidence["tls_available"] is True
            assert "hostname_valid" in result.labels
            assert "issuer_free_ca" in result.labels
            assert result.confidence == 0.85

    @pytest.mark.asyncio
    async def test_analyze_self_signed_certificate(self, analyzer):
        """Test analysis with self-signed certificate."""
        mock_cert_data = {
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2025-01-01T00:00:00+00:00",
            "age_days": 180,
            "days_until_expiry": 185,
            "subject": {"commonName": "malicious.com"},
            "common_name": "malicious.com",
            "issuer": {"commonName": "malicious.com", "organizationName": "Self"},
            "issuer_cn": "malicious.com",
            "issuer_org": "Self",
            "is_self_signed": True,
            "sans": ["malicious.com"],
            "serial_number": "abc123",
            "signature_algorithm": "sha256WithRSAEncryption",
        }

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.return_value = mock_cert_data

            result = await analyzer.analyze("https://malicious.com")

            assert "self_signed" in result.labels
            assert result.risk_score >= 35.0  # Self-signed adds 35 risk

    @pytest.mark.asyncio
    async def test_analyze_expired_certificate(self, analyzer):
        """Test analysis with expired certificate."""
        mock_cert_data = {
            "not_before": "2022-01-01T00:00:00+00:00",
            "not_after": "2023-01-01T00:00:00+00:00",  # Expired
            "age_days": 900,
            "days_until_expiry": -365,
            "subject": {"commonName": "expired.com"},
            "common_name": "expired.com",
            "issuer": {"commonName": "Fake CA", "organizationName": "Unknown"},
            "issuer_cn": "Fake CA",
            "issuer_org": "Unknown",
            "is_self_signed": False,
            "sans": ["expired.com"],
            "serial_number": "abc123",
            "signature_algorithm": "sha256WithRSAEncryption",
        }

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.return_value = mock_cert_data

            result = await analyzer.analyze("https://expired.com")

            assert "expired_certificate" in result.labels
            assert result.risk_score >= 50.0  # Expired adds 50 risk

    @pytest.mark.asyncio
    async def test_analyze_hostname_mismatch(self, analyzer):
        """Test analysis with hostname mismatch."""
        mock_cert_data = {
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2025-01-01T00:00:00+00:00",
            "age_days": 180,
            "days_until_expiry": 185,
            "subject": {"commonName": "different.com"},
            "common_name": "different.com",
            "issuer": {"commonName": "DigiCert", "organizationName": "DigiCert"},
            "issuer_cn": "DigiCert",
            "issuer_org": "DigiCert",
            "is_self_signed": False,
            "sans": ["different.com", "www.different.com"],
            "serial_number": "abc123",
            "signature_algorithm": "sha256WithRSAEncryption",
        }

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.return_value = mock_cert_data

            result = await analyzer.analyze("https://mismatch.com")

            assert "hostname_mismatch" in result.labels
            assert result.risk_score >= 40.0  # Mismatch adds 40 risk

    @pytest.mark.asyncio
    async def test_analyze_newly_issued_certificate(self, analyzer):
        """Test analysis with newly issued certificate."""
        from datetime import datetime, timedelta

        now = datetime.now(UTC)
        recent = now - timedelta(days=3)
        future = now + timedelta(days=365)

        mock_cert_data = {
            "not_before": recent.isoformat(),
            "not_after": future.isoformat(),
            "age_days": 3,
            "days_until_expiry": 365,
            "subject": {"commonName": "new-domain.com"},
            "common_name": "new-domain.com",
            "issuer": {"commonName": "ZeroSSL", "organizationName": "ZeroSSL"},
            "issuer_cn": "ZeroSSL",
            "issuer_org": "ZeroSSL",
            "is_self_signed": False,
            "sans": ["new-domain.com"],
            "serial_number": "abc123",
            "signature_algorithm": "sha256WithRSAEncryption",
        }

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.return_value = mock_cert_data

            result = await analyzer.analyze("https://new-domain.com")

            assert "newly_issued_cert" in result.labels
            assert result.risk_score > 0  # Should add some risk

    @pytest.mark.asyncio
    async def test_analyze_ssl_error(self, analyzer):
        """Test handling of SSL errors."""
        import ssl

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.side_effect = ssl.SSLError("SSL handshake failed")

            result = await analyzer.analyze("https://bad-ssl.com")

            assert "ssl_error" in result.labels
            assert result.risk_score >= 30.0
            assert result.evidence.get("ssl_error") is not None

    @pytest.mark.asyncio
    async def test_analyze_connection_timeout(self, analyzer):
        """Test handling of connection timeout."""
        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.side_effect = TimeoutError()

            result = await analyzer.analyze("https://slow-server.com")

            assert "tls_timeout" in result.labels
            assert result.confidence == 0.5

    @pytest.mark.asyncio
    async def test_analyze_enterprise_ca(self, analyzer):
        """Test analysis with enterprise CA certificate."""
        # Use future dates to avoid expiration
        mock_cert_data = {
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2026-01-01T00:00:00+00:00",  # Future date
            "age_days": 180,
            "days_until_expiry": 365,
            "subject": {"commonName": "secure-bank.com"},
            "common_name": "secure-bank.com",
            "issuer": {
                "commonName": "DigiCert SHA2",
                "organizationName": "DigiCert Inc",
            },
            "issuer_cn": "DigiCert SHA2",
            "issuer_org": "DigiCert Inc",
            "is_self_signed": False,
            "sans": ["secure-bank.com", "www.secure-bank.com"],
            "serial_number": "abc123",
            "signature_algorithm": "sha256WithRSAEncryption",
        }

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.return_value = mock_cert_data

            result = await analyzer.analyze("https://secure-bank.com")

            assert "issuer_enterprise" in result.labels
            # Enterprise CA reduces risk (DigiCert = -10)
            assert result.risk_score < 5

    @pytest.mark.asyncio
    async def test_wildcard_certificate_detection(self, analyzer):
        """Test detection of wildcard certificates."""
        mock_cert_data = {
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2025-01-01T00:00:00+00:00",
            "age_days": 180,
            "days_until_expiry": 185,
            "subject": {"commonName": "*.example.com"},
            "common_name": "*.example.com",
            "issuer": {"commonName": "R3", "organizationName": "Let's Encrypt"},
            "issuer_cn": "R3",
            "issuer_org": "Let's Encrypt",
            "is_self_signed": False,
            "sans": ["*.example.com", "example.com"],
            "serial_number": "abc123",
            "signature_algorithm": "sha256WithRSAEncryption",
        }

        with patch.object(
            analyzer, "_get_certificate", new_callable=AsyncMock
        ) as mock_get_cert:
            mock_get_cert.return_value = mock_cert_data

            result = await analyzer.analyze("https://sub.example.com")

            assert "wildcard_cert" in result.labels
            assert "hostname_valid" in result.labels  # Wildcard should match

    def test_hostname_match_exact(self, analyzer):
        """Test exact hostname matching."""
        assert analyzer._matches_pattern("example.com", "example.com") is True
        assert analyzer._matches_pattern("example.com", "other.com") is False

    def test_hostname_match_wildcard(self, analyzer):
        """Test wildcard hostname matching."""
        assert analyzer._matches_pattern("sub.example.com", "*.example.com") is True
        assert analyzer._matches_pattern("example.com", "*.example.com") is False
        # Wildcard doesn't match multiple levels
        assert analyzer._matches_pattern("a.b.example.com", "*.example.com") is False

    def test_check_hostname_match_with_sans(self, analyzer):
        """Test hostname matching with SANs."""
        assert (
            analyzer._check_hostname_match(
                "www.example.com",
                "example.com",
                ["example.com", "www.example.com"],
            )
            is True
        )
        assert (
            analyzer._check_hostname_match(
                "api.example.com",
                "example.com",
                ["example.com", "www.example.com"],
            )
            is False
        )
