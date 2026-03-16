"""
pandera schema for DED business license data validation (NORM-04).

DED license data comes from browser-extracted JSON (Dubai Pulse).
Validates top-level structure, required fields, and count non-negativity.
"""


def validate_licenses_json(data: dict) -> None:
    """
    Validate DED business licenses scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp string
    - source_url: URL string

    Optional numeric fields (at least one must be present):
    - new_licenses: new licenses issued (non-negative integer)
    - cancelled_licenses: cancelled/suspended licenses (non-negative integer)

    Optional fields:
    - by_sector: dict of sector name -> count (if breakdown available)
    - by_type: dict of license type -> count (if breakdown available)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Licenses data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "source_url" not in data:
        raise ValueError("Missing required field: source_url")

    if not isinstance(data.get("source_url"), str):
        raise ValueError("source_url must be a string")

    # At least one license metric must be present
    license_fields = ["new_licenses", "cancelled_licenses"]
    present_fields = [f for f in license_fields if data.get(f) is not None]

    if not present_fields:
        raise ValueError(
            f"No license count metrics found. Expected at least one of: {license_fields}"
        )

    # Validate non-negative counts
    for field in present_fields:
        value = data[field]
        if not isinstance(value, (int, float)):
            raise ValueError(f"{field} must be a number, got: {type(value).__name__}")
        if value < 0:
            raise ValueError(f"{field} cannot be negative: {value}")

    # Validate by_sector if present
    if data.get("by_sector") is not None:
        if not isinstance(data["by_sector"], dict):
            raise ValueError("by_sector must be a dictionary")

    # Validate by_type if present
    if data.get("by_type") is not None:
        if not isinstance(data["by_type"], dict):
            raise ValueError("by_type must be a dictionary")
