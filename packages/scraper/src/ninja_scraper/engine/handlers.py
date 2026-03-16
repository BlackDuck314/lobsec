"""Mission-type-specific execution handlers.

Dispatches mission execution based on type (http_download, browser_scrape,
api_call). Handles area iteration for browser missions with configurable
delays. Enforces mission-level timeouts via asyncio.timeout.

This module sits between the API layer (api/main.py) and the crawler
engine (crawler.py), providing a single entry point for mission execution.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from pathlib import Path
from typing import Any

import structlog

from ninja_scraper.engine.crawler import (
    MissionResult,
    _extract_page_cards,
    paginate_and_extract,
    run_browser_mission,
    run_http_mission,
)
from ninja_scraper.engine.mission import Mission, load_all_missions, load_mission
from ninja_scraper.engine.storage import ensure_output_dir, get_output_path

logger = structlog.get_logger()


async def execute_mission(
    mission: Mission,
    output_base_dir: str = "/opt/lobsec/data/raw",
) -> MissionResult:
    """Execute a mission based on its type.

    Dispatches to the correct execution strategy:
    - http_download: HTTP GET/POST via httpx
    - api_call: Same as http_download with API-specific headers
    - browser_scrape: Patchright stealth browser automation

    For browser missions with areas, iterates sequentially over each area
    with random delay between navigations. All extracted records are combined
    into a single JSON array with the area field preserved in each record.

    Args:
        mission: Validated Mission spec to execute.
        output_base_dir: Base directory for output files.

    Returns:
        MissionResult with success status and file info.
        Never raises — all exceptions are caught and wrapped.
    """
    start_time = time.monotonic()
    log = logger.bind(
        mission=mission.name,
        type=mission.type,
        priority=mission.priority,
        frequency=mission.frequency,
    )
    log.info("Mission execution starting")

    # Ensure output directory exists
    output_dir = Path(output_base_dir) / mission.name
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir_str = str(output_dir)

    try:
        async with asyncio.timeout(mission.timeout_ms / 1000):
            if mission.type in ("http_download", "api_call"):
                result = await run_http_mission(mission, output_dir_str)
            elif mission.type == "browser_scrape":
                if mission.areas:
                    result = await _execute_area_browser_mission(
                        mission, output_dir_str, log
                    )
                else:
                    result = await run_browser_mission(mission, output_dir_str)
            else:
                raise ValueError(f"Unknown mission type: {mission.type}")

    except asyncio.TimeoutError:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        error = f"Mission timed out after {mission.timeout_ms}ms"
        log.error("Mission execution timeout", duration_ms=duration_ms)
        return MissionResult(
            success=False,
            duration_ms=duration_ms,
            error=error,
            mission_name=mission.name,
        )
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        log.error("Mission execution failed", error=str(e), duration_ms=duration_ms)
        return MissionResult(
            success=False,
            duration_ms=duration_ms,
            error=str(e),
            mission_name=mission.name,
        )

    # Post-processing: log results
    duration_ms = int((time.monotonic() - start_time) * 1000)
    result.duration_ms = duration_ms

    log.info(
        "Mission execution completed",
        success=result.success,
        mission_name=result.mission_name,
        duration_ms=result.duration_ms,
        row_count=result.row_count,
        file_path=result.file_path,
        error=result.error,
    )

    return result


async def _execute_area_browser_mission(
    mission: Mission,
    output_dir: str,
    log: Any,
) -> MissionResult:
    """Execute a browser mission that iterates over multiple areas.

    Each area is visited sequentially (max_concurrent applies to concurrent
    missions, NOT concurrent areas within a single mission). For each area:
    1. Substitute {area} in source.url
    2. Navigate and extract data
    3. Append extracted records to combined list with area field preserved
    4. Apply random delay before next area

    After all areas complete, writes the combined list as a single JSON
    array to the output file.

    Args:
        mission: Validated Mission spec with non-empty areas list.
        output_dir: Directory for output file.
        log: Bound structlog logger.

    Returns:
        MissionResult with combined data from all areas.
    """
    from datetime import date

    from ninja_scraper.stealth.browser import create_stealth_context, get_patchright_browser

    start_time = time.monotonic()
    all_records: list[dict[str, Any]] = []
    areas = mission.areas or []
    base_url = mission.source.get("url", "")
    wait_until = mission.source.get("wait_until", "networkidle")
    selectors = mission.extraction.get("selectors", {})
    playwright_timeout = 30_000

    browser = None
    playwright_instance = None

    try:
        browser, playwright_instance = await get_patchright_browser()
        context = await create_stealth_context(browser)

        for i, area in enumerate(areas):
            url = base_url.replace("{area}", area)
            log.info(
                "Processing area",
                area=area,
                url=url,
                index=i + 1,
                total=len(areas),
            )

            page = await context.new_page()
            page.set_default_timeout(playwright_timeout)

            try:
                response = await page.goto(
                    url, wait_until=wait_until, timeout=playwright_timeout
                )

                # Check for 403/CAPTCHA
                if response and response.status == 403:
                    if mission.retry.skip_on_403:
                        log.warning(
                            "403 detected, skipping area per mission config",
                            area=area,
                            url=url,
                        )
                        await page.close()
                        continue
                    else:
                        log.warning("403 detected for area", area=area, url=url)

                # Post-load wait (lets SPAs render)
                post_load_wait = mission.source.get("post_load_wait_ms", 0)
                if post_load_wait > 0:
                    await asyncio.sleep(post_load_wait / 1000)

                # Wait for specific selector before extracting
                wait_sel = mission.source.get("wait_for_selector")
                if wait_sel:
                    try:
                        await page.wait_for_selector(wait_sel, timeout=15000)
                    except Exception:
                        log.warning("wait_for_selector timeout", selector=wait_sel, area=area)

                # Run pre-extraction JavaScript
                pre_js = mission.extraction.get("pre_extract_js")
                if pre_js:
                    try:
                        await page.evaluate(pre_js)
                        await asyncio.sleep(1)
                    except Exception as e:
                        log.warning("pre_extract_js failed", error=str(e), area=area)

                # Extract data using selectors
                page_data: dict[str, Any] = {"area": area, "url": url}

                container_sel = mission.extraction.get("container_selector")
                if container_sel:
                    # Per-card structured extraction
                    cards = await _extract_page_cards(page, container_sel, selectors)
                    log.info("Container extraction", area=area, card_count=len(cards))

                    # Follow pagination if configured
                    if mission.pagination:
                        cards = await paginate_and_extract(page, mission, cards, url, log)

                    page_data["cards"] = cards
                    page_data["card_count"] = len(cards)

                    # Extract page-level selectors separately
                    for field_name, selector in mission.extraction.get("page_selectors", {}).items():
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
                            log.warning("Page selector failed", field=field_name, error=str(e))
                            page_data[field_name] = None
                else:
                    # Flat extraction (backward compatible)
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
                                area=area,
                                field=field_name,
                                selector=selector,
                                error=str(e),
                            )
                            page_data[field_name] = None

                all_records.append(page_data)

            except Exception as e:
                log.error(
                    "Area navigation failed",
                    area=area,
                    url=url,
                    error=str(e),
                )
                all_records.append({"area": area, "url": url, "error": str(e)})

            finally:
                await page.close()

            # Random delay between areas (skip after last)
            if i < len(areas) - 1:
                delay_range = mission.concurrency.delay_between_requests_ms
                min_delay = delay_range[0] if len(delay_range) > 0 else 2000
                max_delay = delay_range[1] if len(delay_range) > 1 else 6000
                delay_ms = random.randint(min_delay, max_delay)
                log.debug("Delaying between areas", delay_ms=delay_ms)
                await asyncio.sleep(delay_ms / 1000)

        # Write combined data as single JSON array
        output_format = mission.output.get("format", "json")
        out_path = Path(output_dir) / f"{date.today().isoformat()}.{output_format}"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w") as f:
            json.dump(all_records, f, indent=2, ensure_ascii=False)

        duration_ms = int((time.monotonic() - start_time) * 1000)

        return MissionResult(
            success=True,
            file_path=str(out_path),
            row_count=len(all_records),
            duration_ms=duration_ms,
            mission_name=mission.name,
        )

    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        log.error("Area browser mission failed", error=str(e), duration_ms=duration_ms)
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
        if playwright_instance:
            try:
                await playwright_instance.stop()
            except Exception:
                pass
