#!/usr/bin/env python3
"""
Salary survey normalization module.

Extracts median salaries from annual PDF reports by Cooper Fitch, Hays, and Robert Half.
Uses pdfplumber for table extraction, with descriptive error output for manual fallback.

Output metrics per firm:
- uae|{firm}_median_salary_junior
- uae|{firm}_median_salary_mid
- uae|{firm}_median_salary_senior
- uae|{firm}_median_salary_executive
- uae|{firm}_sample_size (number of roles surveyed)

Measurement date: January 1st of report year (annual data).
"""

import json
import sys
from typing import Any

import pandas as pd
import pdfplumber

from .schemas.salary_schema import validate_salary_extraction


def extract_salary_tables(pdf_path: str, firm: str) -> dict[str, Any]:
    """
    Extract salary data from PDF using pdfplumber.

    Targets pages with salary tables (typically pages 5-20 in reports).
    Detects tables by headers containing "Salary", "Compensation", "Role", "Position".

    Args:
        pdf_path: Path to PDF file
        firm: Firm name (cooper-fitch, hays, roberthalf)

    Returns:
        Dict with extracted salary data by role/seniority

    Raises:
        ValueError: If no salary tables found or extraction fails
    """
    extracted_data = {"salaries": [], "report_year": None}

    try:
        with pdfplumber.open(pdf_path) as pdf:
            # Extract report year from metadata or first page
            if pdf.metadata and pdf.metadata.get("CreationDate"):
                # CreationDate format: D:20260215... -> extract year
                creation_date = pdf.metadata["CreationDate"]
                if "202" in creation_date:
                    year_str = creation_date[2:6]  # Extract 4-digit year
                    extracted_data["report_year"] = int(year_str)

            # Target pages 5-20 (salary data typically here)
            page_range = range(min(4, len(pdf.pages)), min(20, len(pdf.pages)))

            for page_num in page_range:
                page = pdf.pages[page_num]
                tables = page.extract_tables()

                for table in tables:
                    if not table or len(table) < 2:
                        continue

                    # Identify salary table by header keywords
                    header = " ".join(str(cell or "") for cell in table[0]).lower()

                    # Check if this is a salary table
                    salary_indicators = [
                        "salary",
                        "compensation",
                        "role",
                        "position",
                        "job title",
                        "aed",
                        "monthly",
                    ]
                    if not any(indicator in header for indicator in salary_indicators):
                        continue

                    # Extract salary data from rows
                    for row in table[1:]:  # Skip header
                        if len(row) < 2:
                            continue

                        # Extract role name (usually first column)
                        role = str(row[0] or "").strip()
                        if not role or len(role) < 3:
                            continue

                        # Try to extract salary values from remaining columns
                        salary_values = []
                        for cell in row[1:]:
                            cell_str = str(cell or "").replace(",", "").replace(" ", "")
                            # Look for numeric values (salaries)
                            try:
                                # Extract numbers from strings like "15,000" or "15000-20000"
                                import re

                                numbers = re.findall(r"\d+", cell_str)
                                for num_str in numbers:
                                    num = int(num_str)
                                    # Filter reasonable salary range (AED/month)
                                    if 1_000 <= num <= 500_000:
                                        salary_values.append(num)
                            except (ValueError, AttributeError):
                                continue

                        if salary_values:
                            # Infer seniority from role title keywords
                            role_lower = role.lower()
                            if any(
                                kw in role_lower
                                for kw in ["junior", "assistant", "entry", "graduate"]
                            ):
                                seniority = "junior"
                            elif any(
                                kw in role_lower
                                for kw in [
                                    "senior",
                                    "lead",
                                    "principal",
                                    "head",
                                    "chief",
                                    "director",
                                    "vp",
                                ]
                            ):
                                seniority = "senior"
                            elif any(
                                kw in role_lower
                                for kw in [
                                    "executive",
                                    "ceo",
                                    "cfo",
                                    "cto",
                                    "president",
                                    "c-level",
                                ]
                            ):
                                seniority = "executive"
                            else:
                                seniority = "mid"

                            # Calculate median salary from extracted values
                            median_salary = int(pd.Series(salary_values).median())

                            extracted_data["salaries"].append(
                                {
                                    "role": role,
                                    "seniority": seniority,
                                    "salary_min": min(salary_values),
                                    "salary_max": max(salary_values),
                                    "median_salary": median_salary,
                                }
                            )

    except Exception as e:
        # Provide descriptive error for Telegram manual-entry fallback
        error_msg = (
            f"PDF extraction failed for {firm} salary survey.\n"
            f"Error: {str(e)}\n"
            f"PDF path: {pdf_path}\n\n"
            f"Please provide manually:\n"
            f"- median_salary_junior: [AED/month]\n"
            f"- median_salary_mid: [AED/month]\n"
            f"- median_salary_senior: [AED/month]\n"
            f"- median_salary_executive: [AED/month]\n"
            f"- sample_size: [number of roles surveyed]"
        )
        raise ValueError(error_msg) from e

    if not extracted_data["salaries"]:
        raise ValueError(
            f"No salary tables found in {firm} PDF at {pdf_path}. "
            f"Manual extraction needed."
        )

    return extracted_data


def normalize_salary(
    data: dict, collected_at: str, firm: str
) -> list[dict[str, Any]]:
    """
    Normalize salary survey data to median salaries per seniority bracket.

    Args:
        data: Extracted salary data from PDF
        collected_at: Collection timestamp (ISO format)
        firm: Firm name (cooper-fitch, hays, roberthalf)

    Returns:
        List of normalized metric dicts
    """
    # Validate extraction result
    validate_salary_extraction(data)

    # Measurement date: January 1st of report year
    report_year = data.get("report_year")
    if not report_year:
        # Fallback: use collection year
        scraped_at = pd.to_datetime(collected_at)
        report_year = scraped_at.year

    measurement_date = f"{report_year}-01-01"

    metrics = []

    # Aggregate salaries by seniority
    seniority_salaries: dict[str, list[int]] = {
        "junior": [],
        "mid": [],
        "senior": [],
        "executive": [],
    }

    for entry in data["salaries"]:
        seniority = entry.get("seniority", "mid")
        median_salary = entry.get("median_salary")

        if median_salary and seniority in seniority_salaries:
            seniority_salaries[seniority].append(median_salary)

    # Generate median salary metrics per seniority
    for seniority, salaries in seniority_salaries.items():
        if salaries:
            median_value = int(pd.Series(salaries).median())
            metrics.append(
                {
                    "measurement_date": measurement_date,
                    "metric_name": f"uae|{firm}_median_salary_{seniority}",
                    "value": median_value,
                    "available_date": collected_at,
                }
            )

    # Sample size
    sample_size = len(data["salaries"])
    metrics.append(
        {
            "measurement_date": measurement_date,
            "metric_name": f"uae|{firm}_sample_size",
            "value": sample_size,
            "available_date": collected_at,
        }
    )

    return metrics


def main():
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads PDF via pdfplumber, normalizes, and outputs to stdout.
    """
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]
        source = input_data["source"]

        # Detect firm from source field
        # cooper-fitch-salary -> cooper-fitch, hays-salary -> hays, etc.
        firm = source.replace("-salary", "").replace("_", "-")

        # Extract salary data from PDF
        extracted_data = extract_salary_tables(file_path, firm)

        # Normalize
        normalized = normalize_salary(extracted_data, collected_at, firm)

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
