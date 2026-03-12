"""Mission execution engine.

Provides run_http_mission() for CSV/API downloads via httpx and
run_browser_mission() for stealth browser scraping via Patchright.

Uses Option A from RESEARCH.md: Patchright pages directly, bypassing
Crawlee's browser pool for full stealth control.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import structlog

from ninja_scraper.engine.mission import Mission
from ninja_scraper.engine.storage import ensure_output_dir, get_output_path
from ninja_scraper.stealth.browser import create_stealth_context, get_patchright_browser
from ninja_scraper.utils.retry import retry_with_jitter

logger = structlog.get_logger()


@dataclass
class MissionResult:
    """Result of a mission execution."""

    success: bool
    file_path: str | None = None
    row_count: int = 0
    duration_ms: int = 0
    error: str | None = None
    mission_name: str = ""


async def run_http_mission(mission: Mission, output_dir: str | None = None) -> MissionResult:
    """Execute an http_download mission using httpx.

    Downloads CSV/JSON data from the source URL with retry logic
    and saves to the output path.

    Args:
        mission: Validated Mission spec.
        output_dir: Override output directory (default: from storage module).

    Returns:
        MissionResult with success status and file info.
    """
    start_time = time.monotonic()
    log = logger.bind(mission=mission.name, type=mission.type)
    log.info("Starting HTTP mission")

    try:
        async with asyncio.timeout(mission.timeout_ms / 1000):
            # Determine output path
            output_format = mission.output.get("format", "csv")
            if output_dir:
                out_dir = Path(output_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / f"{date.today().isoformat()}.{output_format}"
            else:
                out_path = get_output_path(mission.name, output_format)

            # Build request parameters
            url = mission.source.get("url", "")
            method = mission.source.get("method", "GET").upper()
            headers = mission.source.get("headers", {})
            params = mission.source.get("params", {})

            async def do_download() -> httpx.Response:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(
                        connect=10.0,
                        read=60.0,
                        write=10.0,
                        pool=10.0,
                    ),
                    follow_redirects=True,
                ) as client:
                    if method == "GET":
                        return await client.get(url, headers=headers, params=params)
                    elif method == "POST":
                        body = mission.source.get("body", {})
                        return await client.post(url, headers=headers, json=body, params=params)
                    else:
                        raise ValueError(f"Unsupported HTTP method: {method}")

            # Execute with retry
            response = await retry_with_jitter(do_download, mission.retry, log)
            response.raise_for_status()

            # Write response to file
            content = response.content
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(content)

            # Count rows for CSV, items for JSON
            row_count = 0
            if output_format == "csv":
                # Count non-empty lines minus header
                lines = content.decode("utf-8", errors="replace").strip().split("\n")
                row_count = max(0, len(lines) - 1)
            elif output_format == "json":
                try:
                    data = json.loads(content)
                    row_count = len(data) if isinstance(data, list) else 1
                except json.JSONDecodeError:
                    row_count = 0

            duration_ms = int((time.monotonic() - start_time) * 1000)
            log.info(
                "HTTP mission completed",
                file_path=str(out_path),
                row_count=row_count,
                duration_ms=duration_ms,
            )

            return MissionResult(
                success=True,
                file_path=str(out_path),
                row_count=row_count,
                duration_ms=duration_ms,
                mission_name=mission.name,
            )

    except asyncio.TimeoutError:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        error = f"Mission timed out after {mission.timeout_ms}ms"
        log.error("HTTP mission timeout", duration_ms=duration_ms)
        return MissionResult(
            success=False,
            duration_ms=duration_ms,
            error=error,
            mission_name=mission.name,
        )
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        log.error("HTTP mission failed", error=str(e), duration_ms=duration_ms)
        return MissionResult(
            success=False,
            duration_ms=duration_ms,
            error=str(e),
            mission_name=mission.name,
        )


async def run_browser_mission(mission: Mission, output_dir: str | None = None) -> MissionResult:
    """Execute a browser_scrape mission using Patchright.

    Uses Patchright for stealth browser automation. Navigates to source URL(s),
    extracts data using CSS selectors from the mission spec, and saves as JSON.

    For missions with areas, iterates over each area with random delay.

    Args:
        mission: Validated Mission spec.
        output_dir: Override output directory (default: from storage module).

    Returns:
        MissionResult with success status and file info.
    """
    start_time = time.monotonic()
    log = logger.bind(mission=mission.name, type=mission.type)
    log.info("Starting browser mission")

    browser = None
    playwright = None

    try:
        async with asyncio.timeout(mission.timeout_ms / 1000):
            # Determine output path
            output_format = mission.output.get("format", "json")
            if output_dir:
                out_dir = Path(output_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / f"{date.today().isoformat()}.{output_format}"
            else:
                out_path = get_output_path(mission.name, output_format)

            # Launch stealth browser
            browser, playwright = await get_patchright_browser()
            context = await create_stealth_context(browser)

            all_data: list[dict[str, Any]] = []
            base_url = mission.source.get("url", "")
            wait_until = mission.source.get("wait_until", "networkidle")
            selectors = mission.extraction.get("selectors", {})

            # Determine URLs to visit
            urls: list[str] = []
            if mission.areas:
                for area in mission.areas:
                    urls.append(base_url.replace("{area}", area))
            else:
                urls.append(base_url)

            # Playwright default timeout (30s)
            playwright_timeout = 30_000

            for i, url in enumerate(urls):
                log.info("Navigating to URL", url=url, index=i, total=len(urls))
                page = await context.new_page()
                page.set_default_timeout(playwright_timeout)

                try:
                    response = await page.goto(url, wait_until=wait_until, timeout=playwright_timeout)

                    # Check for 403/CAPTCHA
                    if response and response.status == 403:
                        if mission.retry.skip_on_403:
                            log.warning("403 detected, skipping per mission config", url=url)
                            await page.close()
                            continue
                        else:
                            log.warning("403 detected, will retry", url=url)

                    # Extract data using selectors
                    page_data: dict[str, Any] = {"url": url}

                    for field_name, selector in selectors.items():
                        try:
                            elements = await page.query_selector_all(selector)
                            if len(elements) == 1:
                                text = await elements[0].text_content()
                                page_data[field_name] = text.strip() if text else None
                            elif len(elements) > 1:
                                texts = []
                                for el in elements:
                                    text = await el.text_content()
                                    texts.append(text.strip() if text else "")
                                page_data[field_name] = texts
                            else:
                                page_data[field_name] = None
                        except Exception as e:
                            log.warning(
                                "Selector extraction failed",
                                field=field_name,
                                selector=selector,
                                error=str(e),
                            )
                            page_data[field_name] = None

                    all_data.append(page_data)

                except Exception as e:
                    log.error("Page navigation failed", url=url, error=str(e))
                    all_data.append({"url": url, "error": str(e)})

                finally:
                    await page.close()

                # Random delay between requests (skip after last)
                if i < len(urls) - 1:
                    delay_range = mission.concurrency.delay_between_requests_ms
                    min_delay = delay_range[0] if len(delay_range) > 0 else 2000
                    max_delay = delay_range[1] if len(delay_range) > 1 else 6000
                    delay_ms = random.randint(min_delay, max_delay)
                    log.debug("Delaying between requests", delay_ms=delay_ms)
                    await asyncio.sleep(delay_ms / 1000)

            # Save extracted data
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w") as f:
                json.dump(all_data, f, indent=2, ensure_ascii=False)

            row_count = len(all_data)
            duration_ms = int((time.monotonic() - start_time) * 1000)
            log.info(
                "Browser mission completed",
                file_path=str(out_path),
                row_count=row_count,
                duration_ms=duration_ms,
            )

            return MissionResult(
                success=True,
                file_path=str(out_path),
                row_count=row_count,
                duration_ms=duration_ms,
                mission_name=mission.name,
            )

    except asyncio.TimeoutError:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        error = f"Mission timed out after {mission.timeout_ms}ms"
        log.error("Browser mission timeout", duration_ms=duration_ms)
        return MissionResult(
            success=False,
            duration_ms=duration_ms,
            error=error,
            mission_name=mission.name,
        )
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        log.error("Browser mission failed", error=str(e), duration_ms=duration_ms)
        return MissionResult(
            success=False,
            duration_ms=duration_ms,
            error=str(e),
            mission_name=mission.name,
        )
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
        if playwright:
            try:
                await playwright.stop()
            except Exception:
                pass
