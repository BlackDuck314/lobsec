#!/usr/bin/env python3
"""
Job postings normalization module.

Aggregates job postings from all 4 platforms (LinkedIn, Bayt, Indeed, GulfTalent)
into weekly counts per sector/seniority. NOT individual listings (too large).

Output metrics per platform:
- uae|{platform}_total_postings (e.g., uae|linkedin_total_postings)
- uae|{platform}_postings_tech, _finance, _hospitality, _construction, _healthcare, _retail, _other
- uae|{platform}_postings_junior, _mid, _senior, _executive, _unspecified
- uae|{platform}_median_salary (if salary data available)

Seniority classification from salary range brackets:
- Junior: < 10,000 AED/month
- Mid: 10,000 - 25,000
- Senior: 25,000 - 50,000
- Executive: > 50,000

Sector classification from job title keywords.
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.jobs_schema import validate_jobs_json


def classify_seniority(salary_min: int, salary_max: int) -> str:
    """
    Classify job seniority based on posted salary range (AED/month).

    Args:
        salary_min: Minimum salary in AED/month
        salary_max: Maximum salary in AED/month

    Returns:
        Seniority level: junior, mid, senior, executive, or unspecified
    """
    if salary_min == 0 and salary_max == 0:
        return "unspecified"

    # Use midpoint of range
    avg_salary = (salary_min + salary_max) / 2

    if avg_salary < 10_000:
        return "junior"
    elif avg_salary < 25_000:
        return "mid"
    elif avg_salary < 50_000:
        return "senior"
    else:
        return "executive"


def classify_sector(job_title: str) -> str:
    """
    Classify job sector from title keywords.

    Sectors: tech, finance, hospitality, construction, healthcare, retail, other

    Args:
        job_title: Job title string

    Returns:
        Sector classification
    """
    title_lower = job_title.lower()

    tech_keywords = [
        "software",
        "developer",
        "engineer",
        "data",
        "cloud",
        "devops",
        "ai",
        "ml",
        "tech",
        "it ",
        "programmer",
        "architect",
        "system",
    ]
    finance_keywords = [
        "finance",
        "accounting",
        "audit",
        "banking",
        "investment",
        "risk",
        "analyst",
        "cfo",
        "accountant",
        "financial",
    ]
    hospitality_keywords = [
        "hotel",
        "restaurant",
        "chef",
        "waiter",
        "hospitality",
        "tourism",
        "resort",
        "catering",
        "concierge",
    ]
    construction_keywords = [
        "construction",
        "civil",
        "architect",
        "builder",
        "contractor",
        "foreman",
        "surveyor",
        "structural",
    ]
    healthcare_keywords = [
        "doctor",
        "nurse",
        "medical",
        "healthcare",
        "clinic",
        "hospital",
        "physician",
        "surgeon",
        "paramedic",
    ]
    retail_keywords = [
        "retail",
        "sales",
        "cashier",
        "store",
        "shop",
        "merchandis",
        "customer service",
    ]

    if any(kw in title_lower for kw in tech_keywords):
        return "tech"
    elif any(kw in title_lower for kw in finance_keywords):
        return "finance"
    elif any(kw in title_lower for kw in hospitality_keywords):
        return "hospitality"
    elif any(kw in title_lower for kw in construction_keywords):
        return "construction"
    elif any(kw in title_lower for kw in healthcare_keywords):
        return "healthcare"
    elif any(kw in title_lower for kw in retail_keywords):
        return "retail"
    else:
        return "other"


def normalize_jobs(data: dict, collected_at: str, platform: str) -> list[dict[str, Any]]:
    """
    Normalize job postings data to aggregated weekly metrics.

    Args:
        data: Raw job postings JSON from platform
        collected_at: Collection timestamp (ISO format)
        platform: Platform name (linkedin, bayt, indeed, gulftalent)

    Returns:
        List of normalized metric dicts
    """
    # Validate JSON structure
    validate_jobs_json(data)

    # Extract measurement date (start of week - Monday)
    scraped_at = pd.to_datetime(collected_at)
    measurement_date = (
        scraped_at.to_period("W-MON").to_timestamp().strftime("%Y-%m-%d")
    )

    metrics = []

    # Extract listings - try multiple possible keys
    listings = []
    for key in ["listings", "jobs", "results"]:
        if key in data and isinstance(data[key], list):
            listings = data[key]
            break

    # If no listings but have total_count, create metric with count only
    if not listings:
        total_count = data.get("total_count", 0) or data.get("count", 0) or 0

        if total_count == 0:
            # Graceful failure - platform returned empty (403 or no data)
            # Return empty metrics (will trigger empty collection warning)
            return metrics

        # Total count only - no breakdown available
        metrics.append(
            {
                "measurement_date": measurement_date,
                "metric_name": f"uae|{platform}_total_postings",
                "value": total_count,
                "available_date": collected_at,
            }
        )
        return metrics

    # Aggregate counts
    total_postings = len(listings)
    sector_counts: dict[str, int] = {}
    seniority_counts: dict[str, int] = {}
    salaries = []

    for listing in listings:
        # Classify sector from job title
        job_title = listing.get("job_title") or listing.get("title") or ""
        if job_title:
            sector = classify_sector(job_title)
            sector_counts[sector] = sector_counts.get(sector, 0) + 1

        # Classify seniority from salary range
        salary_min = listing.get("salary_min", 0) or 0
        salary_max = listing.get("salary_max", 0) or 0

        # Use explicit seniority level if available (GulfTalent)
        explicit_seniority = listing.get("seniority_level")
        if explicit_seniority:
            seniority = explicit_seniority.lower()
        else:
            seniority = classify_seniority(salary_min, salary_max)

        seniority_counts[seniority] = seniority_counts.get(seniority, 0) + 1

        # Collect salaries for median calculation
        if salary_min > 0 and salary_max > 0:
            avg_salary = (salary_min + salary_max) / 2
            salaries.append(avg_salary)

    # Generate metrics
    # Total postings
    metrics.append(
        {
            "measurement_date": measurement_date,
            "metric_name": f"uae|{platform}_total_postings",
            "value": total_postings,
            "available_date": collected_at,
        }
    )

    # Postings by sector
    for sector, count in sector_counts.items():
        metrics.append(
            {
                "measurement_date": measurement_date,
                "metric_name": f"uae|{platform}_postings_{sector}",
                "value": count,
                "available_date": collected_at,
            }
        )

    # Postings by seniority
    for seniority, count in seniority_counts.items():
        metrics.append(
            {
                "measurement_date": measurement_date,
                "metric_name": f"uae|{platform}_postings_{seniority}",
                "value": count,
                "available_date": collected_at,
            }
        )

    # Median salary (if available)
    if salaries:
        median_salary = int(pd.Series(salaries).median())
        metrics.append(
            {
                "measurement_date": measurement_date,
                "metric_name": f"uae|{platform}_median_salary",
                "value": median_salary,
                "available_date": collected_at,
            }
        )

    return metrics


def main():
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads raw data, normalizes, and outputs to stdout.
    """
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]
        source = input_data["source"]

        # Detect platform from source field
        # linkedin-jobs -> linkedin, bayt-jobs -> bayt, etc.
        platform = source.replace("-jobs", "").replace("_", "-")

        # Load raw job postings data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Normalize
        normalized = normalize_jobs(raw_data, collected_at, platform)

        # Add source field to each record
        for record in normalized:
            record["source"] = source

        # Output to stdout
        json.dump(normalized, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
