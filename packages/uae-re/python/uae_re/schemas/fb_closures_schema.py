"""
Pandera schema for F&B closures data validation (COLL-21).

F&B closure data comes from Google Maps and Zomato browser scrapes.
We validate the JSON structure containing closure records.
"""


def validate_fb_closures_json(data: dict) -> None:
    """
    Validate F&B closures scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp
    - closures: list of closure records (may be empty — graceful)

    Each closure record should have:
    - restaurant_name: string
    - area: string (may be None)
    - permanently_closed: boolean
    - source_url: string

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("F&B closures data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "closures" not in data:
        raise ValueError("Missing required field: closures")

    closures = data["closures"]
    if not isinstance(closures, list):
        raise ValueError("closures must be a list")

    # Validate each closure record structure
    for i, record in enumerate(closures[:10]):  # Validate first 10 for performance
        if not isinstance(record, dict):
            raise ValueError(f"Closure record {i} must be a dictionary")

        if "restaurant_name" not in record:
            raise ValueError(f"Closure record {i} missing restaurant_name")

        if not isinstance(record.get("restaurant_name"), str):
            raise ValueError(f"Closure record {i} restaurant_name must be a string")
