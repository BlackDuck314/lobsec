"""Mission-type-specific execution handlers.

Dispatches mission execution based on type (http_download, browser_scrape,
api_call). Handles area iteration for browser missions with configurable
delays. Enforces mission-level timeouts via asyncio.timeout.

Supports optional proxy routing (mission.proxy=True + NINJA_PROXY_URL env var)
and User-Agent rotation (mission.user_agent_rotation=True) for anti-bot
evasion. Both features are "build now, activate later" — no-op when env
var is absent or flag is False.

This module sits between the API layer (api/main.py) and the crawler
engine (crawler.py), providing a single entry point for mission execution.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from pathlib import Path
from typing import Any

import structlog

from ninja_scraper.engine.crawler import MissionResult, run_browser_mission, run_http_mission
from ninja_scraper.engine.mission import Mission, load_all_missions, load_mission
from ninja_scraper.engine.storage import ensure_output_dir, get_output_path

logger = structlog.get_logger()

# Read proxy URL from env at module load time.
# When present and mission.proxy=True, this is passed to browser/http contexts.
PROXY_URL: str = os.environ.get("NINJA_PROXY_URL", "")

# Curated list of realistic desktop User-Agent strings (Chrome/Edge on Windows/Mac).
# Used when mission.user_agent_rotation=True.
UA_LIST: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]


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

    Proxy support: if mission.proxy=True and NINJA_PROXY_URL env var is set,
    routes traffic through the proxy. Logs a warning and proceeds without
    proxy if env var is absent.

    UA rotation: if mission.user_agent_rotation=True, picks a random UA from
    UA_LIST for each browser context creation.

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

    # Warn if proxy requested but env var absent
    if mission.proxy and not PROXY_URL:
        log.warning(
            "Mission requests proxy but NINJA_PROXY_URL env var is not set — proceeding without proxy",
            mission=mission.name,
        )

    # Ensure output directory exists
    output_dir = Path(output_base_dir) / mission.name
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir_str = str(output_dir)

    try:
        async with asyncio.timeout(mission.timeout_ms / 1000):
            if mission.type in ("http_download", "api_call"):
                result = await _execute_http_mission_with_proxy(
                    mission, output_dir_str, log
                )
            elif mission.type == "browser_scrape":
                if mission.areas:
                    result = await _execute_area_browser_mission(
                        mission, output_dir_str, log
                    )
                else:
                    result = await _execute_browser_mission_with_proxy(
                        mission, output_dir_str, log
                    )
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


async def _execute_http_mission_with_proxy(
    mission: Mission,
    output_dir: str,
    log: Any,
) -> MissionResult:
    """Execute an http_download/api_call mission with optional proxy support.

    When mission.proxy=True and NINJA_PROXY_URL is set, injects the proxy
    into the httpx client. Falls back to direct connection when env var absent.

    Args:
        mission: Validated Mission spec.
        output_dir: Directory for output file.
        log: Bound structlog logger.

    Returns:
        MissionResult from run_http_mission.
    """
    import httpx
    from pathlib import Path
    from datetime import date

    if mission.proxy and PROXY_URL:
        log.info("Using proxy for HTTP mission", proxy=PROXY_URL)

        # Build a patched mission-like execution with proxy
        start_time = time.monotonic()
        try:
            output_format = mission.output.get("format", "csv")
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{date.today().isoformat()}.{output_format}"

            url = mission.source.get("url", "")
            method = mission.source.get("method", "GET").upper()
            headers = mission.source.get("headers", {})
            params = mission.source.get("params", {})

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
                follow_redirects=True,
                proxies={"all://": PROXY_URL},
            ) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=params)
                elif method == "POST":
                    body = mission.source.get("body", {})
                    response = await client.post(url, headers=headers, json=body, params=params)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                response.raise_for_status()

            content = response.content
            out_path.write_bytes(content)

            row_count = 0
            if output_format == "csv":
                lines = content.decode("utf-8", errors="replace").strip().split("\n")
                row_count = max(0, len(lines) - 1)
            elif output_format == "json":
                try:
                    data = json.loads(content)
                    row_count = len(data) if isinstance(data, list) else 1
                except json.JSONDecodeError:
                    row_count = 0

            duration_ms = int((time.monotonic() - start_time) * 1000)
            return MissionResult(
                success=True,
                file_path=str(out_path),
                row_count=row_count,
                duration_ms=duration_ms,
                mission_name=mission.name,
            )

        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            log.error("Proxied HTTP mission failed", error=str(e), duration_ms=duration_ms)
            return MissionResult(
                success=False,
                duration_ms=duration_ms,
                error=str(e),
                mission_name=mission.name,
            )
    else:
        # No proxy: delegate to standard crawler
        return await run_http_mission(mission, output_dir)


async def _execute_browser_mission_with_proxy(
    mission: Mission,
    output_dir: str,
    log: Any,
) -> MissionResult:
    """Execute a single-URL browser mission with optional proxy and UA rotation.

    When mission.proxy=True and NINJA_PROXY_URL is set, passes the proxy
    to the browser context. When mission.user_agent_rotation=True, selects
    a random UA from UA_LIST.

    Falls back to run_browser_mission (no proxy, default UA) when neither
    flag is True.

    Args:
        mission: Validated Mission spec (no areas).
        output_dir: Directory for output file.
        log: Bound structlog logger.

    Returns:
        MissionResult from browser execution.
    """
    if not mission.proxy and not mission.user_agent_rotation:
        return await run_browser_mission(mission, output_dir)

    from ninja_scraper.stealth.browser import get_patchright_browser
    import json
    from datetime import date

    start_time = time.monotonic()
    browser = None
    playwright_instance = None

    try:
        browser, playwright_instance = await get_patchright_browser()

        # Build context kwargs with proxy and/or UA rotation
        context_kwargs: dict[str, Any] = {}
        if mission.proxy and PROXY_URL:
            context_kwargs["proxy"] = {"server": PROXY_URL}
            log.info("Browser context using proxy", proxy=PROXY_URL)
        if mission.user_agent_rotation:
            context_kwargs["user_agent"] = random.choice(UA_LIST)
            log.debug("Browser context using rotated UA", ua=context_kwargs["user_agent"])

        context = await browser.new_context(**context_kwargs)

        output_format = mission.output.get("format", "json")
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{date.today().isoformat()}.{output_format}"

        base_url = mission.source.get("url", "")
        wait_until = mission.source.get("wait_until", "networkidle")
        selectors = mission.extraction.get("selectors", {})
        playwright_timeout = 30_000

        page = await context.new_page()
        page.set_default_timeout(playwright_timeout)
        all_data: list[dict[str, Any]] = []

        try:
            response = await page.goto(base_url, wait_until=wait_until, timeout=playwright_timeout)

            if response and response.status == 403:
                if mission.retry.skip_on_403:
                    log.warning("403 detected, skipping per mission config", url=base_url)
                    await page.close()
                else:
                    log.warning("403 detected", url=base_url)

            page_data: dict[str, Any] = {"url": base_url}
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
                    log.warning("Selector extraction failed", field=field_name, error=str(e))
                    page_data[field_name] = None

            all_data.append(page_data)

        except Exception as e:
            log.error("Page navigation failed", url=base_url, error=str(e))
            all_data.append({"url": base_url, "error": str(e)})
        finally:
            await page.close()

        out_path.write_text(json.dumps(all_data, indent=2, ensure_ascii=False))
        duration_ms = int((time.monotonic() - start_time) * 1000)
        return MissionResult(
            success=True,
            file_path=str(out_path),
            row_count=len(all_data),
            duration_ms=duration_ms,
            mission_name=mission.name,
        )

    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        log.error("Browser mission with proxy/UA failed", error=str(e))
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

    Proxy support: if mission.proxy=True and NINJA_PROXY_URL is set, passes
    proxy to browser.new_context(). UA rotation: if mission.user_agent_rotation
    is True, picks random UA per context.

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

        # Build context kwargs with optional proxy and UA rotation
        context_kwargs: dict[str, Any] = {}
        if mission.proxy and PROXY_URL:
            context_kwargs["proxy"] = {"server": PROXY_URL}
            log.info("Area browser using proxy", proxy=PROXY_URL)
        if mission.user_agent_rotation:
            context_kwargs["user_agent"] = random.choice(UA_LIST)
            log.debug("Area browser using rotated UA", ua=context_kwargs["user_agent"])

        if context_kwargs:
            context = await browser.new_context(**context_kwargs)
        else:
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

                # Extract data using selectors
                page_data: dict[str, Any] = {"area": area, "url": url}

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
