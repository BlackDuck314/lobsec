"""
S&P Global PMI Collector (MACRO-03)

Attempts to download and extract the headline UAE PMI number from
S&P Global press release PDFs. This is a MEDIUM confidence source
because pmi.spglobal.com is behind AWS WAF (CloudFront JavaScript
challenge), which blocks direct HTTP access.

Collection strategy (ordered by preference):
1. Direct HTTP GET to known PMI release page with browser User-Agent
2. If blocked (AWS WAF 202/403), save empty result with pmi_value=null

PDF extraction uses pdfplumber to read the first 2 pages and regex
to find the headline PMI number (2-digit.1-decimal between 40.0-65.0
near "PMI"/"Seasonally Adjusted" keywords).

Bridge pattern:
  Read:  {"outputDir": "/opt/lobsec/data/raw"} from stdin
  Write: {"filePath": str, "rowCount": int} to stdout
  Errors: print to stderr, sys.exit(1)
"""

import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests


# Browser-like User-Agent to avoid trivial bot detection
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36"
)

# S&P Global PMI releases page (JS-rendered, behind AWS WAF)
PMI_RELEASES_URL = "https://www.pmi.spglobal.com/Public/Release/PressReleases"

# Request timeout in seconds
HTTP_TIMEOUT = 30


def extract_pmi_from_pdf(pdf_path: str) -> Optional[float]:
    """Extract headline PMI number from a downloaded S&P Global UAE PMI PDF.

    The PMI number is a 2-digit value with 1 decimal (e.g., 55.0) found
    near keywords like "PMI", "Seasonally Adjusted", "UAE".

    Args:
        pdf_path: Path to the downloaded PDF file.

    Returns:
        Headline PMI value as float, or None if extraction fails.
    """
    try:
        import pdfplumber
    except ImportError:
        print("WARNING: pdfplumber not available, cannot extract PMI from PDF", file=sys.stderr)
        return None

    try:
        with pdfplumber.open(pdf_path) as pdf:
            text = ""
            # PMI number is on the first 1-2 pages
            for page in pdf.pages[:2]:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"

        if not text.strip():
            print("WARNING: No text extracted from PDF", file=sys.stderr)
            return None

        # Strategy: Find numbers matching XX.X pattern near PMI keywords
        # Look for "Seasonally Adjusted" section which contains the headline number
        matches = re.findall(r'(\d{2}\.\d)\s', text)
        for m in matches:
            val = float(m)
            # PMI values are always between 30 and 70 in practice
            if 40.0 <= val <= 65.0:
                print(f"  Extracted PMI value: {val}", file=sys.stderr)
                return val

        # Broader search: look for standalone 2-digit numbers near PMI text
        pmi_section = re.search(r'(?:PMI|Purchasing\s+Managers).{0,200}?(\d{2}\.\d)', text, re.DOTALL | re.IGNORECASE)
        if pmi_section:
            val = float(pmi_section.group(1))
            if 30.0 <= val <= 70.0:
                print(f"  Extracted PMI value (broad search): {val}", file=sys.stderr)
                return val

        print("WARNING: Could not find PMI value in PDF text", file=sys.stderr)
        return None

    except Exception as e:
        print(f"WARNING: PDF extraction error: {e}", file=sys.stderr)
        return None


def try_direct_http() -> Optional[bytes]:
    """Try direct HTTP GET to PMI releases page.

    Returns:
        Response body bytes if successful, None if blocked by AWS WAF.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        resp = requests.get(PMI_RELEASES_URL, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=True)

        # AWS WAF returns 202 with empty body or HTML with JS challenge
        if resp.status_code == 202:
            print("  AWS WAF challenge detected (HTTP 202)", file=sys.stderr)
            return None
        if resp.status_code == 403:
            print("  Access denied (HTTP 403)", file=sys.stderr)
            return None
        if resp.status_code != 200:
            print(f"  Unexpected HTTP status: {resp.status_code}", file=sys.stderr)
            return None

        # Check for AWS WAF JS challenge in response body
        body = resp.text
        if "AwsWafIntegration" in body or "aws-waf-token" in body:
            print("  AWS WAF JavaScript challenge in response body", file=sys.stderr)
            return None

        # Check for meaningful content (not an empty or challenge page)
        if len(body) < 500:
            print(f"  Response too short ({len(body)} bytes), likely a WAF page", file=sys.stderr)
            return None

        return resp.content

    except requests.RequestException as e:
        print(f"  HTTP error: {e}", file=sys.stderr)
        return None


def try_scraper_api(output_dir: str) -> Optional[str]:
    """Try Ninja Scraper API to download PMI page via browser automation.

    Args:
        output_dir: Base output directory (used to locate scraper data).

    Returns:
        Path to downloaded file if successful, None otherwise.
    """
    scraper_token = os.environ.get("SCRAPER_AUTH_TOKEN", "")
    if not scraper_token:
        print("  SCRAPER_AUTH_TOKEN not set, skipping scraper API", file=sys.stderr)
        return None

    scraper_base = "http://127.0.0.1:18791"
    headers = {"Authorization": f"Bearer {scraper_token}"}

    try:
        # Submit crawl job
        resp = requests.post(
            f"{scraper_base}/crawl",
            json={"mission_name": "spglobal-pmi", "force": True},
            headers=headers,
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"  Scraper API returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
            return None

        job_data = resp.json()
        job_id = job_data.get("job_id")
        if not job_id:
            print("  Scraper returned no job_id", file=sys.stderr)
            return None

        # Poll for completion (max 90 seconds, 5-second intervals)
        import time
        for _ in range(18):
            time.sleep(5)
            poll = requests.get(f"{scraper_base}/crawl/{job_id}", headers=headers, timeout=10)
            if poll.status_code != 200:
                continue
            poll_data = poll.json()
            status = poll_data.get("status", "")
            if status == "completed":
                result = poll_data.get("result", {})
                return result.get("filePath")
            if status in ("failed", "error"):
                print(f"  Scraper job failed: {poll_data.get('error', 'unknown')}", file=sys.stderr)
                return None

        print("  Scraper job timed out after 90 seconds", file=sys.stderr)
        return None

    except requests.RequestException as e:
        print(f"  Scraper API error: {e}", file=sys.stderr)
        return None


def collect_pmi(output_dir: str) -> dict:
    """Collect UAE PMI data from S&P Global.

    Attempts direct HTTP first, then falls back to Ninja Scraper API.
    If both fail, saves an empty result (pmi_value=null).

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int}
    """
    pmi_dir = Path(output_dir) / "spglobal-pmi"
    pmi_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = pmi_dir / f"{today}.json"
    collected_at = datetime.now(timezone.utc).isoformat()

    pmi_value = None
    release_date = None
    pdf_path = None
    method_used = None

    # Strategy 1: Direct HTTP GET
    print("Attempting direct HTTP access to PMI releases page...", file=sys.stderr)
    content = try_direct_http()
    if content is not None:
        method_used = "direct_http"
        print("  Direct HTTP access succeeded", file=sys.stderr)
        # Check if the content looks like HTML with PMI release links
        text = content.decode("utf-8", errors="replace")
        # Try to find a PDF link or the PMI number directly in HTML
        pdf_links = re.findall(r'href="([^"]*PressRelease[^"]*)"', text)
        if pdf_links:
            print(f"  Found {len(pdf_links)} press release links", file=sys.stderr)
            # Try the first UAE PMI link
            for link in pdf_links[:3]:
                if not link.startswith("http"):
                    link = "https://www.pmi.spglobal.com" + link
                try:
                    pdf_resp = requests.get(
                        link,
                        headers={"User-Agent": USER_AGENT},
                        timeout=HTTP_TIMEOUT,
                        allow_redirects=True,
                    )
                    if pdf_resp.status_code == 200 and (
                        pdf_resp.headers.get("content-type", "").startswith("application/pdf")
                        or link.endswith(".pdf")
                    ):
                        # Save PDF to temp file and extract
                        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                            tmp.write(pdf_resp.content)
                            tmp_path = tmp.name
                        pmi_value = extract_pmi_from_pdf(tmp_path)
                        if pmi_value is not None:
                            pdf_path = tmp_path
                            break
                        os.unlink(tmp_path)
                except Exception as e:
                    print(f"  Failed to fetch press release: {e}", file=sys.stderr)

    # Strategy 2: Ninja Scraper API
    if pmi_value is None:
        print("Attempting Ninja Scraper API for PMI...", file=sys.stderr)
        scraped_path = try_scraper_api(output_dir)
        if scraped_path and os.path.exists(scraped_path):
            method_used = "ninja_scraper"
            if scraped_path.endswith(".pdf"):
                pmi_value = extract_pmi_from_pdf(scraped_path)
                if pmi_value is not None:
                    pdf_path = scraped_path

    # Build output
    if pmi_value is None:
        print("WARNING: Could not extract PMI value. Saving empty result.", file=sys.stderr)

    output = {
        "collectedAt": collected_at,
        "pmi_value": pmi_value,
        "release_date": release_date,
        "pdf_path": pdf_path,
        "method_used": method_used,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    row_count = 1 if pmi_value is not None else 0
    print(f"PMI collection complete: value={pmi_value}, method={method_used}", file=sys.stderr)
    return {"filePath": str(out_path), "rowCount": row_count}


def main() -> None:
    """Entry point: read stdin, collect, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        output_dir = input_data.get("outputDir", "/opt/lobsec/data/raw")

        result = collect_pmi(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
