"""Patchright browser launcher with stealth configuration.

Uses Patchright (undetected Playwright fork) for Chromium automation
that bypasses common bot detection (Cloudflare, Datadome, Kasada).

This module uses Patchright pages directly (Option A from RESEARCH.md),
bypassing Crawlee's browser pool for full stealth control.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from patchright.async_api import Browser, BrowserContext, Playwright

logger = structlog.get_logger()


async def get_patchright_browser() -> tuple["Browser", "Playwright"]:
    """Launch Patchright Chromium in headless mode with stealth args.

    Returns:
        Tuple of (Browser, Playwright) instances. Caller must close both.

    Raises:
        ImportError: If patchright is not installed.
        Exception: If browser fails to launch.
    """
    from patchright.async_api import async_playwright

    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-infobars",
            "--window-size=1920,1080",
        ],
    )
    logger.info("Patchright browser launched", headless=True)
    return browser, playwright


async def create_stealth_context(
    browser: "Browser", accept_downloads: bool = False
) -> "BrowserContext":
    """Create a new browser context with realistic fingerprint settings.

    Configures viewport, locale, timezone, and user agent to appear
    as a normal user browsing from UAE.

    Args:
        browser: Patchright Browser instance.
        accept_downloads: Enable browser download events for PDF missions.

    Returns:
        BrowserContext configured for stealth operation.
    """
    context = await browser.new_context(
        viewport={"width": 1920, "height": 1080},
        locale="en-US",
        timezone_id="Asia/Dubai",
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        java_script_enabled=True,
        bypass_csp=False,
        ignore_https_errors=False,
        has_touch=False,
        is_mobile=False,
        color_scheme="light",
        accept_downloads=accept_downloads,
    )
    logger.debug("Stealth browser context created", locale="en-US", timezone="Asia/Dubai")
    return context
