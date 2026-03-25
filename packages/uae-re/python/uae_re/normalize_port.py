#!/usr/bin/env python3
"""
Jebel Ali port / DP World cargo normalization module.

Reads scraped DP World newsroom HTML (contains __NEXT_DATA__ with RSS feed)
and extracts Jebel Ali port statistics from press release descriptions.

Dubai-level metrics:
- dubai|port_container_throughput_teu  (annual TEU at Jebel Ali)
- dubai|port_breakbulk_cargo_mt       (annual breakbulk in million tonnes)

All metrics include available_date (NORM-02 compliance).

The raw data is HTML from dpworld.com/en/news. The __NEXT_DATA__ script tag
contains a JSON payload with an RSS feed under componentProps → params →
feedData. We parse the RSS items, find Jebel Ali throughput articles, and
extract TEU and cargo figures from the article descriptions.
"""

import json
import re
import sys
from typing import Any

import pandas as pd


def _strip_html(text: str) -> str:
    """Strip HTML tags and normalize whitespace."""
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&nbsp;', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _extract_number(text: str, pattern: str) -> float | None:
    """
    Extract a number near a keyword pattern.

    Args:
        text: Plain text to search
        pattern: Regex pattern to find (must have a capture group for the number)

    Returns:
        Extracted float or None
    """
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        num_str = match.group(1).replace(',', '')
        try:
            return float(num_str)
        except ValueError:
            return None
    return None


def extract_from_html(file_path: str) -> list[dict[str, Any]]:
    """
    Extract Jebel Ali port data from DP World newsroom HTML.

    Parses __NEXT_DATA__ → RSS feed → finds Jebel Ali articles →
    extracts TEU and cargo figures from article descriptions.

    Returns list of extracted data dicts with keys:
      year, teu_millions, breakbulk_mt_millions, pub_date
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract __NEXT_DATA__ JSON
    idx = content.find('__NEXT_DATA__')
    if idx < 0:
        return []

    start = content.find('>', idx) + 1
    end = content.find('</script>', start)
    if end < 0:
        return []

    data = json.loads(content[start:end])

    # Navigate to RSS feed data
    try:
        cp = data['props']['pageProps']['componentProps']
        # Find the component with feedData
        feed_str = None
        for comp_key in cp:
            params = cp[comp_key].get('params', {})
            if 'feedData' in params:
                feed_str = params['feedData']
                break
        if not feed_str:
            return []

        feed = json.loads(feed_str)
        items = feed.get('channel', {}).get('item', [])
    except (KeyError, json.JSONDecodeError):
        return []

    results = []

    # Search for Jebel Ali throughput articles
    for item in items:
        title = item.get('title', '')
        if isinstance(title, dict):
            title = title.get('#text', str(title))
        title_str = str(title).lower()

        # Only process Jebel Ali articles about volumes/throughput
        if 'jebel ali' not in title_str:
            continue
        if not any(kw in title_str for kw in ['volume', 'throughput', 'cargo', 'record', 'teu', 'highest']):
            continue

        desc = item.get('description', '')
        if isinstance(desc, dict):
            desc = desc.get('#text', str(desc))
        desc_text = _strip_html(str(desc))

        pub_date = item.get('pubDate', '')

        # Extract TEU figure (e.g. "15.5 million twenty-foot equivalent units (TEUs)")
        teu = _extract_number(
            desc_text,
            r'(\d+\.?\d*)\s*million\s+(?:twenty-foot equivalent units|TEUs?)',
        )
        if teu is None:
            # Try alternate pattern: "X million TEU"
            teu = _extract_number(desc_text, r'(\d+\.?\d*)\s*million\s+TEU')

        # Extract year from article (e.g. "in 2024")
        year_match = re.search(r'in\s+(20\d{2})', desc_text)
        year = int(year_match.group(1)) if year_match else None

        # Extract breakbulk cargo (e.g. "5.4 million metric tonnes")
        breakbulk = _extract_number(
            desc_text,
            r'(\d+\.?\d*)\s*million\s+metric\s+tonn',
        )

        if teu is not None and year is not None:
            results.append({
                'year': year,
                'teu_millions': teu,
                'breakbulk_mt_millions': breakbulk,
                'pub_date': pub_date,
            })

    return results


def normalize_port(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize Jebel Ali port data to annual metrics.

    Args:
        file_path: Path to DP World newsroom HTML file
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records
    """
    extracted = extract_from_html(file_path)
    metrics = []

    for item in extracted:
        year = item['year']
        measurement_date = f"{year}-01-01"

        # Container throughput (convert millions to absolute)
        if item['teu_millions'] is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|port_container_throughput_teu",
                "value": item['teu_millions'] * 1_000_000,
                "available_date": collected_at,
            })

        # Breakbulk cargo (convert millions of MT to absolute)
        if item.get('breakbulk_mt_millions') is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|port_breakbulk_cargo_mt",
                "value": item['breakbulk_mt_millions'] * 1_000_000,
                "available_date": collected_at,
            })

    return metrics


def main():
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads HTML, normalizes, and outputs to stdout.
    """
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        normalized = normalize_port(file_path, collected_at)

        for record in normalized:
            record["source"] = input_data["source"]

        json.dump(normalized, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
