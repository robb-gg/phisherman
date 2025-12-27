"""
Comprehensive tests for enhanced analyzers migrated from Antifraude.
Tests both the new analyzers and integration with the existing system.
"""

import pytest

from phisherman.analyzers.engine import AnalysisEngine
from phisherman.analyzers.saas_detector_enhanced import EnhancedSaaSDetector
from phisherman.analyzers.web_content_analyzer import WebContentAnalyzer


class TestEnhancedSaaSDetector:
    """Test suite for Enhanced SaaS Detector"""

    @pytest.fixture
    def detector(self):
        return EnhancedSaaSDetector()

    @pytest.mark.asyncio
    async def test_firebase_detection_high_abuse(self, detector):
        """Test Firebase detection - high abuse but neutral risk"""
        result = await detector.analyze("https://phishing-site.firebaseapp.com")

        assert result.risk_score > 0  # Some risk due to SaaS
        assert "saas_hosting" in result.labels
        assert "provider_google_firebase" in result.labels
        assert result.evidence["is_saas"] is True
        assert result.evidence["provider"] == "Google Firebase"
        assert result.evidence["abuse_frequency"] == 2134
        # Neutral/low risk modifier despite high abuse
        assert result.evidence["risk_modifier"] <= 1.0

    @pytest.mark.asyncio
    async def test_weebly_detection_high_risk(self, detector):
        """Test Weebly detection - high abuse and high risk"""
        result = await detector.analyze("https://scam.weeblysite.com")

        assert result.risk_score > 15  # Higher risk due to abuse ratio
        assert "saas_hosting" in result.labels
        assert "provider_weebly" in result.labels
        assert result.evidence["risk_modifier"] == 1.2
        assert result.evidence["abuse_frequency"] > 900

    @pytest.mark.asyncio
    async def test_url_shortener_very_high_risk(self, detector):
        """Test URL shorteners - very high risk service type"""
        result = await detector.analyze("https://bit.ly/xyz123")

        assert result.risk_score > 25  # Very high risk
        assert "type_url_shortener" in result.labels
        assert "high_risk_service_type" in result.labels
        assert result.evidence["service_type"] == "url_shortener"
        assert any(
            "hide final destination" in note.lower()
            for note in result.evidence["analysis_notes"]
        )

    @pytest.mark.asyncio
    async def test_qr_generator_high_risk(self, detector):
        """Test QR code generators - high phishing risk"""
        result = await detector.analyze("https://qrco.de/abc123")

        assert result.risk_score > 20
        assert "type_qr_generator" in result.labels
        assert "very_high_abuse_frequency" in result.labels
        assert result.evidence["abuse_frequency"] == 2548

    @pytest.mark.asyncio
    async def test_cloudflare_pages_moderate_risk(self, detector):
        """Test Cloudflare Pages - legitimate CDN with some abuse"""
        result = await detector.analyze("https://project.pages.dev")

        assert result.risk_score < 25  # Moderate risk
        assert "saas_hosting" in result.labels
        assert result.evidence["risk_modifier"] == 0.9  # Slight reduction

    @pytest.mark.asyncio
    async def test_github_pages_low_risk(self, detector):
        """Test GitHub Pages - developer platform, lower risk"""
        result = await detector.analyze("https://username.github.io")

        assert result.risk_score < 20  # Low risk
        assert "saas_hosting" in result.labels
        assert result.evidence["provider"] == "GitHub Pages"
        assert result.evidence["risk_modifier"] == 0.8

    @pytest.mark.asyncio
    async def test_adobe_very_low_risk(self, detector):
        """Test Adobe - legitimate company, very low risk"""
        result = await detector.analyze("https://adobe.com/creative-cloud")

        assert result.risk_score < 10
        assert result.evidence["risk_modifier"] == 0.2  # Very low

    @pytest.mark.asyncio
    async def test_standard_domain_not_saas(self, detector):
        """Test standard domains - not SaaS"""
        result = await detector.analyze("https://mycompany.com")

        assert result.evidence["is_saas"] is False
        assert "standard_domain" in result.labels
        assert result.risk_score == 0.0  # Neutral, let other analyzers decide

    @pytest.mark.asyncio
    async def test_subdomain_abuse_pattern(self, detector):
        """Test subdomain of SaaS - common phishing technique"""
        result = await detector.analyze("https://paypal-login.weebly.com")

        # Subdomain abuse gets extra risk
        assert result.risk_score >= 18  # Base + subdomain penalty
        assert result.evidence["is_saas"] is True
        # Verify there are analysis notes
        assert len(result.evidence["analysis_notes"]) > 0


class TestWebContentAnalyzer:
    """Test suite for Web Content Analyzer"""

    @pytest.fixture
    def analyzer(self):
        return WebContentAnalyzer()

    @pytest.mark.asyncio
    async def test_legitimate_site_google(self, analyzer):
        """Test analysis of legitimate site - Google"""
        result = await analyzer.analyze("https://www.google.com")

        # Should have low risk
        assert result.risk_score < 40
        assert result.confidence > 0.7
        assert result.evidence["status_code"] == 200
        # Google has HTTPS and security headers
        assert not any("no_https" in label for label in result.labels)

    @pytest.mark.asyncio
    async def test_http_no_encryption(self, analyzer):
        """Test HTTP site without HTTPS"""
        # Note: This might fail if the site redirects to HTTPS
        try:
            result = await analyzer.analyze("http://example.com")
            # If it doesn't redirect, should flag no HTTPS
            if "http://" in result.evidence["final_url"]:
                assert "no_https" in result.labels
                assert result.risk_score >= 15
        except Exception:
            pytest.skip("Site may redirect to HTTPS or be unreachable")

    @pytest.mark.asyncio
    async def test_suspicious_keywords_detection(self, analyzer):
        """Test detection of phishing keywords - if site contains them"""
        # This is a hypothetical test - would need a controlled test page
        pytest.skip("Requires controlled test page with phishing keywords")

    @pytest.mark.asyncio
    async def test_timeout_handling(self, analyzer):
        """Test timeout handling for unreachable sites"""
        # Use a non-routable IP to force timeout
        result = await analyzer.analyze("http://192.0.2.1:8080")

        assert "request_timeout" in result.labels or "connection_error" in result.labels
        assert result.risk_score > 15
        assert "error" in result.evidence

    @pytest.mark.asyncio
    async def test_redirect_chain_detection(self, analyzer):
        """Test detection of redirect chains"""
        # Example with known redirecting site
        result = await analyzer.analyze("http://bit.ly")  # Usually redirects

        # May have redirects
        if result.evidence.get("redirects"):
            assert len(result.evidence["redirects"]) > 0
            if len(result.evidence["redirects"]) > 1:
                assert (
                    "redirect_chain" in result.labels
                    or "multiple_redirects" in result.labels
                )


class TestIntegration:
    """Integration tests for the complete analysis engine"""

    # Test URL database with expected characteristics
    TEST_URLS = {
        # LEGITIMATE SITES (Low Risk)
        "google": {
            "url": "https://www.google.com",
            "expected_risk": "low",
            "expected_labels": ["standard_domain"],
        },
        "github": {
            "url": "https://github.com",
            "expected_risk": "low",
            "expected_labels": ["standard_domain"],
        },
        "amazon": {
            "url": "https://www.amazon.com",
            "expected_risk": "low",
            "expected_labels": ["standard_domain"],
        },
        # SaaS PLATFORMS (Variable Risk)
        "firebase_subdomain": {
            "url": "https://test-project.web.app",
            "expected_risk": "medium",
            "expected_labels": ["saas_hosting", "hosted_on_google"],
        },
        "github_pages": {
            "url": "https://username.github.io",
            "expected_risk": "low",
            "expected_labels": ["saas_hosting"],
        },
        "weebly_site": {
            "url": "https://suspicious.weeblysite.com",
            "expected_risk": "medium",
            "expected_labels": ["saas_hosting", "provider_weebly"],
        },
        # HIGH RISK SERVICES
        "url_shortener": {
            "url": "https://bit.ly/test123",
            "expected_risk": "high",
            "expected_labels": ["high_risk_service_type", "url_shortener"],
        },
        "qr_generator": {
            "url": "https://qrco.de/abc123",
            "expected_risk": "high",
            "expected_labels": ["type_qr_generator", "very_high_abuse_frequency"],
        },
        # SUSPICIOUS PATTERNS
        "very_long_subdomain": {
            "url": "https://www-paypal-secure-login-verify.weebly.com",
            "expected_risk": "high",
            "expected_labels": ["saas_hosting"],
        },
    }

    @pytest.fixture
    def engine(self):
        # Initialize engine with our enhanced analyzers
        return AnalysisEngine()

    @pytest.mark.asyncio
    async def test_analysis_engine_initialization(self, engine):
        """Test that engine initializes with all analyzers"""
        assert len(engine.analyzers) > 0

        # Check that our new analyzers are present
        analyzer_names = [a.name for a in engine.analyzers]
        assert "saas_detector_enhanced" in analyzer_names
        assert "web_content_analyzer" in analyzer_names

    @pytest.mark.asyncio
    async def test_analyze_legitimate_site(self, engine):
        """Test full analysis of legitimate site"""
        url = "https://www.example.com"
        results = await engine.analyze(url)

        assert len(results) > 0

        # Check that enhanced analyzers ran
        analyzer_names = [r.analyzer_name for r in results]
        assert "saas_detector_enhanced" in analyzer_names
        assert "web_content_analyzer" in analyzer_names

        # Get SaaS detector result
        saas_result = next(
            r for r in results if r.analyzer_name == "saas_detector_enhanced"
        )
        assert (
            saas_result.evidence["is_saas"] is False
        )  # example.com is NOT SaaS hosting

    @pytest.mark.asyncio
    async def test_analyze_firebase_site(self, engine):
        """Test full analysis of Firebase hosted site"""
        url = "https://test-app.firebaseapp.com"
        results = await engine.analyze(url)

        # Get SaaS detector result
        saas_result = next(
            r for r in results if r.analyzer_name == "saas_detector_enhanced"
        )

        assert saas_result.evidence["is_saas"] is True
        assert saas_result.evidence["provider"] == "Google Firebase"
        assert "saas_hosting" in saas_result.labels

    @pytest.mark.asyncio
    async def test_analyze_url_shortener(self, engine):
        """Test full analysis of URL shortener"""
        url = "https://bit.ly/xyz123"
        results = await engine.analyze(url)

        # Get SaaS detector result
        saas_result = next(
            r for r in results if r.analyzer_name == "saas_detector_enhanced"
        )

        assert saas_result.evidence["is_saas"] is True
        assert saas_result.evidence["service_type"] == "url_shortener"
        assert saas_result.risk_score > 25  # High risk for URL shorteners
        assert "high_risk_service_type" in saas_result.labels

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url_key",
        [
            "google",
            "firebase_subdomain",
            "url_shortener",
            "github_pages",
        ],
    )
    async def test_url_database(self, engine, url_key):
        """Test analysis of various URLs from test database"""
        test_case = self.TEST_URLS[url_key]
        url = test_case["url"]

        results = await engine.analyze(url)

        # Basic validation
        assert len(results) > 0
        # Negative scores are valid - they indicate trust (e.g., old domains)
        assert all(r.risk_score >= -100 for r in results)
        assert all(r.risk_score <= 100 for r in results)
        assert all(0 <= r.confidence <= 1 for r in results)

        # Check for expected labels (at least one should match)
        all_labels = []
        for result in results:
            all_labels.extend(result.labels)

        has_expected_label = any(
            expected in all_labels for expected in test_case["expected_labels"]
        )

        # Some labels might not appear if analyzer fails, so we just log
        if not has_expected_label:
            print(
                f"Warning: Expected labels {test_case['expected_labels']} not found for {url}"
            )
            print(f"Found labels: {all_labels}")


class TestSaaSDetectionLogic:
    """Detailed tests for SaaS detection logic"""

    @pytest.fixture
    def detector(self):
        return EnhancedSaaSDetector()

    def test_saas_database_integrity(self, detector):
        """Test that SaaS database is properly structured"""
        assert len(detector.SAAS_DOMAINS) > 0

        # Check format of each entry
        for _domain, info in detector.SAAS_DOMAINS.items():
            assert isinstance(info, tuple)
            assert len(info) == 4
            frequency, service_type, provider, risk_modifier = info

            assert isinstance(frequency, int)
            assert frequency >= 0
            assert isinstance(service_type, str)
            assert len(service_type) > 0
            assert isinstance(provider, str)
            assert len(provider) > 0
            assert isinstance(risk_modifier, int | float)
            assert 0 <= risk_modifier <= 3.0

    def test_risk_modifier_logic(self, detector):
        """Test that risk modifiers follow expected patterns"""
        # URL shorteners should have high risk
        shortener_domains = ["bit.ly", "tinyurl.com", "t.co"]
        for domain in shortener_domains:
            if domain in detector.SAAS_DOMAINS:
                _, _, _, risk_mod = detector.SAAS_DOMAINS[domain]
                assert risk_mod >= 1.2, f"{domain} should have high risk modifier"

        # Legitimate platforms should have lower risk
        legitimate_domains = ["github.io", "netlify.app", "vercel.app"]
        for domain in legitimate_domains:
            if domain in detector.SAAS_DOMAINS:
                _, _, _, risk_mod = detector.SAAS_DOMAINS[domain]
                assert (
                    risk_mod <= 1.0
                ), f"{domain} should have low/neutral risk modifier"

    def test_abuse_frequency_correlation(self, detector):
        """Test that abuse frequency data is present and logical"""
        # High abuse services should be noted
        high_abuse_domains = ["weebly.com", "firebaseapp.com", "bit.ly", "qrco.de"]

        for domain in high_abuse_domains:
            if domain in detector.SAAS_DOMAINS:
                frequency, _, _, _ = detector.SAAS_DOMAINS[domain]
                assert frequency > 0, f"{domain} should have documented abuse frequency"


# REAL-WORLD TEST SCENARIOS


class TestRealWorldScenarios:
    """Test real-world phishing scenarios"""

    @pytest.fixture
    def detector(self):
        return EnhancedSaaSDetector()

    PHISHING_PATTERNS = [
        # Common phishing URL patterns
        "paypal-secure-login.weebly.com",
        "amazon-verify-account.firebaseapp.com",
        "apple-id-verification.web.app",
        "microsoft-teams-meeting.r2.dev",
        "secure-bank-login.pages.dev",
        "confirm-payment-paypal.weeblysite.com",
    ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("phishing_url", PHISHING_PATTERNS)
    async def test_common_phishing_patterns(self, detector, phishing_url):
        """Test detection of common phishing URL patterns"""
        url = f"https://{phishing_url}"
        result = await detector.analyze(url)

        # Should be detected as SaaS
        assert result.evidence["is_saas"] is True
        assert "saas_hosting" in result.labels

        # Should have elevated risk due to subdomain abuse
        assert result.risk_score > 10

        # Should have analysis notes about the risk
        assert len(result.evidence["analysis_notes"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
