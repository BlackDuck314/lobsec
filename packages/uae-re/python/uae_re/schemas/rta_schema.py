"""
pandera schema for RTA vehicle registrations data validation (NORM-04).

RTA data is JSON from browser-extracted tables, so we validate basic structure.
"""


def validate_rta_json(data: dict) -> None:
    """
    Validate RTA scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp
    - source_url: URL string
    - new_registrations: number (non-negative)
    - deregistrations: number (non-negative)
    - total_registered: number (non-negative)

    Raises:
        ValueError: If validation fails
    """
    # Top-level structure
    if not isinstance(data, dict):
        raise ValueError("RTA data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "source_url" not in data:
        raise ValueError("Missing required field: source_url")

    if not isinstance(data.get("source_url"), str):
        raise ValueError("source_url must be a string")

    # Required numeric fields
    required_fields = ["new_registrations", "deregistrations", "total_registered"]

    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")

        if not isinstance(data[field], (int, float)):
            raise ValueError(f"{field} must be a number")

        if data[field] < 0:
            raise ValueError(f"{field} cannot be negative: {data[field]}")
