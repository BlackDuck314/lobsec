"""
Pandera schema for commercial office reports data validation (COLL-28).

Office report data comes from JLL, CBRE, and Savills website browser scrapes.
We validate the JSON structure containing multi-source office market metrics.
"""


_VALID_SOURCES = {"jll", "cbre", "savills"}


def validate_office_json(data: dict) -> None:
    """
    Validate commercial office reports scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp
    - reports: list of report records (may be empty if all firms gate content)

    Each report record should have:
    - report_source: one of "jll", "cbre", "savills"
    - source_url: URL string

    Optional per-report fields (may be None if not extractable from summary page):
    - vacancy_rate_pct: float (0-100)
    - absorption_sqft: float (can be negative — negative absorption = more space returned)
    - prime_rent_aed_sqft: float (positive)
    - total_stock_sqft: float (positive)
    - report_date: string (quarter identifier)
    - pdf_url: string (URL to gated PDF, if identified)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Office reports data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "reports" not in data:
        raise ValueError("Missing required field: reports")

    reports = data["reports"]
    if not isinstance(reports, list):
        raise ValueError("reports must be a list")

    # Validate each report record
    for i, report in enumerate(reports):
        if not isinstance(report, dict):
            raise ValueError(f"Report record {i} must be a dictionary")

        source = report.get("report_source", "").lower()
        if source and source not in _VALID_SOURCES:
            raise ValueError(
                f"Report record {i} report_source '{source}' must be one of {_VALID_SOURCES}"
            )

        # Validate numeric ranges if present
        vacancy = report.get("vacancy_rate_pct")
        if vacancy is not None:
            if not isinstance(vacancy, (int, float)):
                raise ValueError(f"Report {i} vacancy_rate_pct must be numeric")
            if not (0 <= vacancy <= 100):
                raise ValueError(
                    f"Report {i} vacancy_rate_pct out of range [0, 100]: {vacancy}"
                )

        rent = report.get("prime_rent_aed_sqft")
        if rent is not None:
            if not isinstance(rent, (int, float)):
                raise ValueError(f"Report {i} prime_rent_aed_sqft must be numeric")
            if rent < 0:
                raise ValueError(
                    f"Report {i} prime_rent_aed_sqft cannot be negative: {rent}"
                )

        total_stock = report.get("total_stock_sqft")
        if total_stock is not None:
            if not isinstance(total_stock, (int, float)):
                raise ValueError(f"Report {i} total_stock_sqft must be numeric")
            if total_stock < 0:
                raise ValueError(
                    f"Report {i} total_stock_sqft cannot be negative: {total_stock}"
                )
