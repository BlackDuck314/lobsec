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
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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


async def _extract_page_cards(page: Any, container_sel: str, selectors: dict[str, str]) -> list[dict[str, Any]]:
    """Extract structured card records from the current page state."""
    containers = await page.query_selector_all(container_sel)
    cards: list[dict[str, Any]] = []
    for container in containers:
        record: dict[str, Any] = {}
        for field_name, selector in selectors.items():
            try:
                el = await container.query_selector(selector)
                record[field_name] = (await el.text_content()).strip() if el else None
            except Exception:
                record[field_name] = None
        cards.append(record)
    return cards


def _build_page_url(base_url: str, page_num: int, param_name: str) -> str:
    """Append or replace page parameter in URL."""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)
    params[param_name] = [str(page_num)]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def paginate_and_extract(
    page: Any,
    mission: Mission,
    initial_cards: list[dict[str, Any]],
    url: str,
    log: Any,
) -> list[dict[str, Any]]:
    """Follow pagination and extract additional cards beyond page 1.

    Supports two strategies:
    - click_next: Click a next-page button, wait, re-extract from same page
    - page_param: Navigate to URL?page=N for each subsequent page

    Returns combined list of all cards across all pages.
    """
    pagination = mission.pagination
    container_sel = mission.extraction.get("container_selector")
    if not pagination or not container_sel:
        return initial_cards

    all_cards = list(initial_cards)
    selectors = mission.extraction.get("selectors", {})
    wait_until = mission.source.get("wait_until", "networkidle")
    post_load_wait = mission.source.get("post_load_wait_ms", 0)
    wait_sel = mission.source.get("wait_for_selector")

    for page_num in range(2, pagination.max_pages + 1):
        if pagination.strategy == "click_next":
            next_btn = await page.query_selector(pagination.next_selector)
            if not next_btn:
                log.info("No next button found", pages_scraped=page_num - 1)
                break

            # Check disabled states
            aria_disabled = await next_btn.get_attribute("aria-disabled")
            if aria_disabled == "true":
                log.info("Next button disabled", pages_scraped=page_num - 1)
                break
            classes = await next_btn.get_attribute("class") or ""
            if "disabled" in classes.lower():
                log.info("Next button has disabled class", pages_scraped=page_num - 1)
                break

            try:
                await next_btn.click(timeout=10000)
            except Exception:
                # Fallback: JS click bypasses overlay/pointer interception
                try:
                    await page.evaluate("el => el.click()", next_btn)
                except Exception as e:
                    log.warning("Click next failed", error=str(e))
                    break

            await asyncio.sleep(pagination.wait_after_ms / 1000)

            if wait_sel:
                try:
                    await page.wait_for_selector(wait_sel, timeout=15000)
                except Exception:
                    log.warning("Wait for selector after pagination failed", page=page_num)
                    break

        elif pagination.strategy == "page_param":
            param_value = (page_num - 1) * pagination.page_size if pagination.page_size > 0 else page_num
            page_url = _build_page_url(url, param_value, pagination.page_param)
            try:
                response = await page.goto(page_url, wait_until=wait_until, timeout=30000)
                if response and response.status in (403, 404):
                    log.info("Pagination stopped on error status", page=page_num, status=response.status)
                    break
            except Exception as e:
                log.warning("Page navigation failed", page=page_num, error=str(e))
                break

            if post_load_wait > 0:
                await asyncio.sleep(post_load_wait / 1000)

            if wait_sel:
                try:
                    await page.wait_for_selector(wait_sel, timeout=15000)
                except Exception:
                    log.info("No content on page", page=page_num)
                    break

        # Extract cards from this page
        new_cards = await _extract_page_cards(page, container_sel, selectors)
        if not new_cards:
            log.info("No cards found, pagination done", pages_scraped=page_num - 1)
            break

        all_cards.extend(new_cards)
        log.info("Pagination", page=page_num, new_cards=len(new_cards), total_cards=len(all_cards))

    return all_cards


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
                            log.warning("wait_for_selector timeout", selector=wait_sel, url=url)

                    # Run pre-extraction JavaScript
                    pre_js = mission.extraction.get("pre_extract_js")
                    if pre_js:
                        try:
                            await page.evaluate(pre_js)
                            await asyncio.sleep(1)
                        except Exception as e:
                            log.warning("pre_extract_js failed", error=str(e), url=url)

                    # Extract data using selectors
                    page_data: dict[str, Any] = {"url": url}

                    container_sel = mission.extraction.get("container_selector")
                    if container_sel:
                        # Per-card structured extraction
                        cards = await _extract_page_cards(page, container_sel, selectors)
                        log.info("Container extraction", url=url, card_count=len(cards))

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


async def run_pdf_download_mission(mission: Mission, output_dir: str | None = None) -> MissionResult:
    """Execute a browser mission that finds and downloads PDF files.

    Navigates to the source page, finds PDF links matching selector and keyword
    filter, downloads the first matching PDF via the browser download event.

    Args:
        mission: Validated Mission spec with extraction.format == "pdf".
        output_dir: Override output directory.

    Returns:
        MissionResult with downloaded PDF path.
    """
    start_time = time.monotonic()
    log = logger.bind(mission=mission.name, type=mission.type)
    log.info("Starting PDF download mission")

    browser = None
    playwright_inst = None

    try:
        async with asyncio.timeout(mission.timeout_ms / 1000):
            # Output path
            if output_dir:
                out_dir = Path(output_dir)
            else:
                out_dir = Path("/opt/lobsec/data/raw") / mission.name
            out_dir.mkdir(parents=True, exist_ok=True)

            browser, playwright_inst = await get_patchright_browser()
            context = await create_stealth_context(browser, accept_downloads=True)
            page = await context.new_page()
            page.set_default_timeout(30_000)

            url = mission.source.get("url", "")
            wait_until = mission.source.get("wait_until", "networkidle")

            await page.goto(url, wait_until=wait_until, timeout=30_000)

            post_load_wait = mission.source.get("post_load_wait_ms", 0)
            if post_load_wait > 0:
                await asyncio.sleep(post_load_wait / 1000)

            # Find PDF links
            selectors = mission.extraction.get("selectors", {})
            link_selector = selectors.get("pdf_links", "a[href$='.pdf']")
            elements = await page.query_selector_all(link_selector)

            # Build list of (text, href) tuples
            pdf_links: list[tuple[str, str]] = []
            for el in elements:
                href = await el.get_attribute("href") or ""
                text = (await el.text_content() or "").strip()
                if href:
                    pdf_links.append((text, href))

            log.info("Found PDF links", count=len(pdf_links))

            if not pdf_links:
                duration_ms = int((time.monotonic() - start_time) * 1000)
                return MissionResult(
                    success=False,
                    duration_ms=duration_ms,
                    error="No PDF links found on page",
                    mission_name=mission.name,
                )

            # Apply keyword filter if specified
            filter_key = next(
                (k for k in selectors if k.endswith("_filter") or k == "filter_text"),
                None,
            )
            if filter_key:
                filter_spec = selectors[filter_key]
                # Parse keywords from either format:
                #   "text*='Keyword1' | text*='Keyword2'" (structured)
                #   "Keyword1|Keyword2" (simple pipe-separated)
                keywords = []
                if "text*='" in filter_spec:
                    for part in filter_spec.split("|"):
                        part = part.strip()
                        if "text*='" in part:
                            kw = part.split("text*='")[1].rstrip("'")
                            keywords.append(kw.lower())
                else:
                    for part in filter_spec.split("|"):
                        part = part.strip()
                        if part:
                            keywords.append(part.lower())

                if keywords:
                    filtered = [
                        (t, h) for t, h in pdf_links
                        if any(kw in t.lower() for kw in keywords)
                    ]
                    log.info(
                        "Filtered PDF links",
                        keywords=keywords,
                        before=len(pdf_links),
                        after=len(filtered),
                    )
                    if filtered:
                        pdf_links = filtered

            # Download the first matching PDF
            target_text, target_href = pdf_links[0]
            log.info("Downloading PDF", text=target_text, href=target_href[:100])

            # Use httpx to download the PDF (simpler than browser download events)
            import httpx

            # Resolve relative URLs
            from urllib.parse import urljoin
            full_url = urljoin(url, target_href)

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=10.0),
                follow_redirects=True,
            ) as client:
                response = await client.get(full_url)
                response.raise_for_status()

            out_path = out_dir / f"{date.today().isoformat()}.pdf"
            out_path.write_bytes(response.content)

            # Save metadata alongside
            meta_path = out_dir / f"{date.today().isoformat()}.meta.json"
            meta = {
                "source_url": url,
                "pdf_url": full_url,
                "pdf_title": target_text,
                "pdf_size_bytes": len(response.content),
                "all_pdf_links": [
                    {"text": t, "href": h} for t, h in pdf_links
                ],
            }
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)

            duration_ms = int((time.monotonic() - start_time) * 1000)
            log.info(
                "PDF download completed",
                file_path=str(out_path),
                size_bytes=len(response.content),
                duration_ms=duration_ms,
            )

            return MissionResult(
                success=True,
                file_path=str(out_path),
                row_count=1,
                duration_ms=duration_ms,
                mission_name=mission.name,
            )

    except asyncio.TimeoutError:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        log.error("PDF download mission timeout", duration_ms=duration_ms)
        return MissionResult(
            success=False,
            duration_ms=duration_ms,
            error=f"Mission timed out after {mission.timeout_ms}ms",
            mission_name=mission.name,
        )
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        log.error("PDF download mission failed", error=str(e), duration_ms=duration_ms)
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
        if playwright_inst:
            try:
                await playwright_inst.stop()
            except Exception:
                pass
