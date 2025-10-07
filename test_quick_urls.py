#!/usr/bin/env python3
"""
Quick URL testing script - Test the enhanced analyzers with real URLs
Usage: poetry run python test_quick_urls.py
"""

import asyncio
import sys

from phisherman.analyzers.engine import AnalysisEngine
from phisherman.scorer.linear_scorer import LinearScorer

# Test URL database with diverse examples
TEST_URLS = [
    # LEGITIMATE SITES
    ("https://www.google.com", "Legitimate - Google"),
    ("https://github.com", "Legitimate - GitHub"),
    ("https://www.amazon.com", "Legitimate - Amazon"),
    # SAAS PLATFORMS - LOW RISK
    ("https://github.io", "SaaS - GitHub Pages (low risk)"),
    ("https://netlify.app", "SaaS - Netlify (low risk)"),
    ("https://vercel.app", "SaaS - Vercel (low risk)"),
    # SAAS PLATFORMS - MEDIUM RISK
    ("https://test.firebaseapp.com", "SaaS - Firebase (neutral risk)"),
    ("https://test.web.app", "SaaS - Firebase Web.app"),
    ("https://example.pages.dev", "SaaS - Cloudflare Pages"),
    # SAAS PLATFORMS - HIGH RISK
    ("https://suspicious.weebly.com", "SaaS - Weebly (high abuse)"),
    ("https://test.weeblysite.com", "SaaS - Weebly subdomain"),
    # URL SHORTENERS - VERY HIGH RISK
    ("https://bit.ly", "URL Shortener - Bitly"),
    ("https://tinyurl.com", "URL Shortener - TinyURL"),
    # QR GENERATORS - HIGH RISK
    ("https://qrco.de", "QR Generator - High risk"),
    # SUSPICIOUS PATTERNS (if they exist)
    ("https://paypal-verify.weebly.com", "SUSPICIOUS - Paypal on Weebly"),
    ("https://amazon-login.firebaseapp.com", "SUSPICIOUS - Amazon on Firebase"),
    ("https://apple-id-verify.web.app", "SUSPICIOUS - Apple on Firebase"),
    ("https://airdrop-plasma.top/", "SUSPICIOUS - Airdrop Plasma"),
    ("https://b-tvoice360.framer.website/", "SUSPICIOUS - B-T Voice 360"),
]


def print_banner():
    """Print test banner"""
    print("=" * 80)
    print("🎣 PHISHERMAN - Enhanced Analyzer Test Suite")
    print("=" * 80)
    print()


def print_separator():
    """Print separator"""
    print("-" * 80)


async def test_single_url(engine, scorer, url, description):
    """Test a single URL and display results"""
    print(f"\n📊 Testing: {description}")
    print(f"🔗 URL: {url}")
    print_separator()

    try:
        # Run analysis
        results = await engine.analyze(url)

        # Calculate score
        scoring = scorer.calculate_score(results)

        # Display analyzer results
        print(f"\n🔍 Analyzer Results ({len(results)} analyzers):\n")

        for result in results:
            # Focus on our enhanced analyzers
            if result.analyzer_name in [
                "saas_detector_enhanced",
                "web_content_analyzer",
            ]:
                print(f"  ⭐ {result.analyzer_name}:")
                print(f"     • Risk Score: {result.risk_score:.1f}/100")
                print(f"     • Confidence: {result.confidence:.2f}")
                print(
                    f"     • Labels: {', '.join(result.labels[:5])}"
                )  # First 5 labels

                # Show key evidence
                if result.analyzer_name == "saas_detector_enhanced":
                    if result.evidence.get("is_saas"):
                        print(f"     • Provider: {result.evidence.get('provider')}")
                        print(
                            f"     • Service Type: {result.evidence.get('service_type')}"
                        )
                        print(
                            f"     • Risk Modifier: {result.evidence.get('risk_modifier')}"
                        )
                        print(
                            f"     • Abuse Freq: {result.evidence.get('abuse_frequency')}"
                        )

                print()

        # Display final score
        print("📈 Final Scoring:")
        print(f"   • Score: {scoring.final_score:.2f}/100")
        print(f"   • Confidence: {scoring.confidence:.2f}")
        print(
            f"   • Risk Level: {scoring.details.get('risk_level', 'unknown').upper()}"
        )

        # Risk interpretation
        risk_level = scoring.details.get("risk_level", "unknown")
        if risk_level == "high":
            print("   • ⚠️  WARNING: HIGH RISK - Do not proceed")
        elif risk_level == "medium":
            print("   • ⚠️  CAUTION: Medium risk - Verify carefully")
        elif risk_level == "low":
            print("   • ℹ️  LOW RISK: Proceed with normal caution")
        else:
            print("   • ✅ VERY LOW RISK: Appears legitimate")

        print_separator()

        return True

    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        print_separator()
        return False


async def run_all_tests():
    """Run all URL tests"""
    print_banner()

    print("🚀 Initializing analysis engine...")
    engine = AnalysisEngine()
    scorer = LinearScorer()

    print(f"✅ Loaded {len(engine.analyzers)} analyzers")

    analyzer_names = [a.name for a in engine.analyzers]
    if "saas_detector_enhanced" in analyzer_names:
        print("✅ Enhanced SaaS Detector loaded")
    if "web_content_analyzer" in analyzer_names:
        print("✅ Web Content Analyzer loaded")

    print("\n" + "=" * 80)
    print("🧪 Starting URL Tests")
    print("=" * 80)

    success_count = 0
    total_count = len(TEST_URLS)

    for url, description in TEST_URLS:
        success = await test_single_url(engine, scorer, url, description)
        if success:
            success_count += 1

        # Small delay between tests
        await asyncio.sleep(0.5)

    # Summary
    print("\n" + "=" * 80)
    print("📊 TEST SUMMARY")
    print("=" * 80)
    print(f"✅ Successful: {success_count}/{total_count}")
    print(f"❌ Failed: {total_count - success_count}/{total_count}")
    print()

    if success_count == total_count:
        print("🎉 All tests completed successfully!")
    else:
        print("⚠️  Some tests failed. Review errors above.")

    print("=" * 80)


async def test_custom_url(url):
    """Test a custom URL provided by user"""
    print_banner()

    print("🚀 Initializing analysis engine for custom URL...")
    engine = AnalysisEngine()
    scorer = LinearScorer()

    await test_single_url(engine, scorer, url, "Custom URL")


def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        # Test custom URL
        custom_url = sys.argv[1]
        print(f"Testing custom URL: {custom_url}\n")
        asyncio.run(test_custom_url(custom_url))
    else:
        # Run full test suite
        asyncio.run(run_all_tests())


if __name__ == "__main__":
    main()
