"""
pandera schema for RTA metro ridership data validation (NORM-04).

Metro data comes from browser-extracted JSON (RTA statistics page).
Validates top-level structure and required fields.
"""


def validate_metro_json(data: dict) -> None:
    """
    Validate RTA metro scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp string
    - source_url: URL string

    Optional numeric fields (at least one must be present):
    - total_ridership: total public transport riders (non-negative)
    - metro_ridership: metro rail riders (non-negative)
    - tram_ridership: Dubai Tram riders (non-negative)
    - bus_ridership: bus network riders (non-negative)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Metro data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "source_url" not in data:
        raise ValueError("Missing required field: source_url")

    if not isinstance(data.get("source_url"), str):
        raise ValueError("source_url must be a string")

    # At least one ridership metric must be present
    ridership_fields = ["total_ridership", "metro_ridership", "tram_ridership", "bus_ridership"]
    present_fields = [f for f in ridership_fields if data.get(f) is not None]

    if not present_fields:
        raise ValueError(
            f"No ridership metrics found. Expected at least one of: {ridership_fields}"
        )

    # Validate types and ranges for present numeric fields
    for field in present_fields:
        value = data[field]
        if not isinstance(value, (int, float)):
            raise ValueError(f"{field} must be a number, got: {type(value).__name__}")
        if value < 0:
            raise ValueError(f"{field} cannot be negative: {value}")
