#!/usr/bin/env python3
"""
Headless browser for URL analysis with proxy support
Processes large lists of URLs with concurrent requests
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class BrowserConfig:
    """Browser configuration"""

    proxy_url: str = "http://127.0.0.1:8080"
    ignore_ssl: bool = True
    headless: bool = True
    timeout: int = 30000  # 30 seconds
    concurrent_browsers: int = 5  # Number of browser instances
    contexts_per_browser: int = 10  # Contexts per browser (total = browsers * contexts)


@dataclass
class URLResult:
    """Result of URL visit"""

    url: str
    success: bool
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    error: Optional[str] = None
    timestamp: Optional[datetime] = None


class HeadlessBrowserPool:
    """Manages a pool of headless browsers for concurrent URL processing"""

    def __init__(self, config: BrowserConfig):
        self.config = config
        self.browsers: list[Browser] = []
        self.results: list[URLResult] = []

    async def initialize(self):
        """Initialize playwright and multiple browsers"""
        self.playwright = await async_playwright().start()

        # Launch multiple browser instances
        for i in range(self.config.concurrent_browsers):
            browser = await self.playwright.chromium.launch(
                headless=self.config.headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--ignore-certificate-errors",
                ],
            )
            self.browsers.append(browser)

        total_capacity = (
            self.config.concurrent_browsers * self.config.contexts_per_browser
        )
        logger.info(
            f"Initialized {self.config.concurrent_browsers} browsers with {self.config.contexts_per_browser} contexts each (total capacity: {total_capacity})"
        )

    async def close(self):
        """Close all browsers and playwright"""
        for browser in self.browsers:
            await browser.close()
        if hasattr(self, "playwright"):
            await self.playwright.stop()
        logger.info("All browsers closed")

    async def create_context(self, browser: Browser) -> BrowserContext:
        """Create a new browser context with proxy and SSL settings"""
        context = await browser.new_context(
            proxy={"server": self.config.proxy_url},
            ignore_https_errors=self.config.ignore_ssl,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            viewport={"width": 1920, "height": 1080},
            java_script_enabled=True,
        )
        return context

    async def visit_url(self, url: str, context: BrowserContext) -> URLResult:
        """Visit a single URL and capture result"""
        page: Optional[Page] = None
        try:
            page = await context.new_page()

            # Navigate to URL - wait for all resources to load
            response = await page.goto(
                url,
                timeout=self.config.timeout,
                wait_until="load",  # Loads all static resources (JS, CSS, images, etc.)
            )

            # Get final URL after redirects
            final_url = page.url
            status_code = response.status if response else None

            result = URLResult(
                url=url,
                success=True,
                status_code=status_code,
                final_url=final_url,
                timestamp=datetime.now(),
            )

            logger.info(f"✓ {url} -> {status_code} ({final_url})")
            return result

        except Exception as e:
            result = URLResult(
                url=url, success=False, error=str(e), timestamp=datetime.now()
            )
            logger.error(f"✗ {url} -> Error: {str(e)}")
            return result

        finally:
            if page:
                await page.close()

    async def process_batch(
        self, urls: list[str], browser: Browser, batch_num: int
    ) -> list[URLResult]:
        """Process a batch of URLs with a single context"""
        context = await self.create_context(browser)
        results = []

        try:
            for idx, url in enumerate(urls, 1):
                result = await self.visit_url(url, context)
                results.append(result)

                if idx % 10 == 0:
                    logger.info(f"Batch {batch_num}: Processed {idx}/{len(urls)} URLs")

        finally:
            await context.close()

        return results

    async def process_urls(self, urls: list[str]) -> list[URLResult]:
        """Process all URLs with concurrent browser contexts"""
        total_urls = len(urls)
        total_workers = (
            self.config.concurrent_browsers * self.config.contexts_per_browser
        )
        logger.info(
            f"Starting to process {total_urls} URLs with {total_workers} concurrent workers ({self.config.concurrent_browsers} browsers x {self.config.contexts_per_browser} contexts)"
        )

        # Split URLs into batches (one per context)
        batch_size = max(1, total_urls // total_workers)
        batches = [urls[i : i + batch_size] for i in range(0, total_urls, batch_size)]

        logger.info(
            f"Created {len(batches)} batches (approx {batch_size} URLs per batch)"
        )

        # Distribute batches across browsers
        tasks = []
        batch_num = 1

        for browser_idx, browser in enumerate(self.browsers):
            # Each browser gets contexts_per_browser batches
            browser_batches = batches[browser_idx :: self.config.concurrent_browsers]

            for batch in browser_batches:
                if batch:  # Skip empty batches
                    tasks.append(self.process_batch(batch, browser, batch_num))
                    batch_num += 1

        # Process all batches concurrently
        batch_results = await asyncio.gather(*tasks)

        # Flatten results
        all_results = []
        for batch_result in batch_results:
            all_results.extend(batch_result)

        self.results = all_results
        return all_results


def load_urls_from_file(filepath: str) -> list[str]:
    """Load URLs from a text file (one URL per line)"""
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"URL file not found: {filepath}")

    with open(path) as f:
        urls = [line.strip() for line in f if line.strip()]

    logger.info(f"Loaded {len(urls)} URLs from {filepath}")
    return urls


def save_results(results: list[URLResult], output_file: str = "browser_results.txt"):
    """Save results to file"""
    output_path = Path(output_file)

    with open(output_path, "w") as f:
        f.write(f"URL Processing Results - {datetime.now()}\n")
        f.write("=" * 80 + "\n\n")

        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful

        f.write(f"Total URLs: {len(results)}\n")
        f.write(f"Successful: {successful}\n")
        f.write(f"Failed: {failed}\n")
        f.write("=" * 80 + "\n\n")

        for result in results:
            f.write(f"URL: {result.url}\n")
            f.write(f"Success: {result.success}\n")
            if result.status_code:
                f.write(f"Status: {result.status_code}\n")
            if result.final_url and result.final_url != result.url:
                f.write(f"Redirected to: {result.final_url}\n")
            if result.error:
                f.write(f"Error: {result.error}\n")
            f.write("-" * 80 + "\n")

    logger.info(f"Results saved to {output_path}")
    logger.info(f"Summary - Success: {successful}, Failed: {failed}")


async def main():
    """Main execution function"""
    # Configuration
    config = BrowserConfig(
        proxy_url="http://127.0.0.1:8080",
        ignore_ssl=True,
        headless=True,
        timeout=30000,
        concurrent_browsers=5,  # Number of browser instances
        contexts_per_browser=10,  # Contexts per browser (total workers = 5 * 10 = 50)
    )

    # Load URLs - Update with your actual file path
    url_file = (
        "../zipalerts.com_wayback.txt"  # Path relative to headless_browser directory
    )

    try:
        urls = load_urls_from_file(url_file)
    except FileNotFoundError as e:
        logger.error(str(e))
        logger.info("Please update the url_file variable with your URL list file")
        return

    # Initialize browser pool
    pool = HeadlessBrowserPool(config)

    try:
        await pool.initialize()

        # Process all URLs
        start_time = datetime.now()
        results = await pool.process_urls(urls)
        end_time = datetime.now()

        # Save results
        save_results(results, "../browser_results.txt")

        # Print summary
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Processing completed in {duration:.2f} seconds")
        logger.info(f"Average: {len(urls)/duration:.2f} URLs/second")

    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
