"""
pandera schema for DTCM tourism statistics data validation (NORM-04).

DTCM data comes from browser-extracted JSON (tourism research page).
Validates top-level structure, required fields, and value ranges.
"""


def validate_tourism_json(data: dict) -> None:
    """
    Validate DTCM tourism scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp string
    - source_url: URL string

    Optional numeric fields (at least one must be present):
    - hotel_occupancy_pct: hotel occupancy rate (0-100)
    - visitor_count: international visitor arrivals (positive)
    - hotel_revenue_aed: hotel establishment revenue in AED (positive)
    - average_length_of_stay: average nights per visitor (positive)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Tourism data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "source_url" not in data:
        raise ValueError("Missing required field: source_url")

    if not isinstance(data.get("source_url"), str):
        raise ValueError("source_url must be a string")

    # At least one tourism metric must be present
    tourism_fields = ["hotel_occupancy_pct", "visitor_count", "hotel_revenue_aed", "average_length_of_stay"]
    present_fields = [f for f in tourism_fields if data.get(f) is not None]

    if not present_fields:
        raise ValueError(
            f"No tourism metrics found. Expected at least one of: {tourism_fields}"
        )

    # Validate occupancy is 0-100 if present
    if data.get("hotel_occupancy_pct") is not None:
        occ = data["hotel_occupancy_pct"]
        if not isinstance(occ, (int, float)):
            raise ValueError(f"hotel_occupancy_pct must be a number, got: {type(occ).__name__}")
        if occ < 0 or occ > 100:
            raise ValueError(f"hotel_occupancy_pct {occ} outside valid range (0-100)")

    # Validate visitor count is positive if present
    if data.get("visitor_count") is not None:
        vc = data["visitor_count"]
        if not isinstance(vc, (int, float)):
            raise ValueError(f"visitor_count must be a number, got: {type(vc).__name__}")
        if vc <= 0:
            raise ValueError(f"visitor_count must be positive, got: {vc}")
