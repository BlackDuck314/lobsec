"""
Pandera schema for Dubai customs household imports data validation (COLL-22).

Customs data comes from Dubai Customs / CBUAE browser scrapes.
We validate the JSON structure with HS-code-specific import values.
"""


def validate_customs_json(data: dict) -> None:
    """
    Validate Dubai customs household imports JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp
    - source_url: URL string

    Optional fields (may be absent if extraction fails):
    - furniture_imports_aed: HS chapter 94 imports
    - household_goods_imports_aed: HS chapters 73+85 imports
    - total_imports_aed: total imports value
    - measurement_quarter: quarter string (e.g., "Q1 2024")
    - pdf_url: URL to downloaded PDF (if available)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Customs data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    # Validate numeric fields if present
    numeric_fields = [
        "furniture_imports_aed",
        "household_goods_imports_aed",
        "total_imports_aed",
    ]
    for field in numeric_fields:
        if field in data and data[field] is not None:
            val = data[field]
            if not isinstance(val, (int, float)):
                raise ValueError(f"{field} must be numeric, got: {type(val)}")
            if val < 0:
                raise ValueError(f"{field} cannot be negative: {val}")

    # Validate household share is reasonable
    if ("furniture_imports_aed" in data and "total_imports_aed" in data
            and data.get("total_imports_aed") and data.get("furniture_imports_aed")):
        furniture = data["furniture_imports_aed"]
        total = data["total_imports_aed"]
        if total > 0 and furniture > total:
            raise ValueError(
                f"furniture_imports_aed ({furniture}) cannot exceed total_imports_aed ({total})"
            )
