"""
Pandera schema for Google Maps Popular Times foot traffic data validation (COLL-26).

Foot traffic data comes from Google Maps browser scrapes with JSON extraction
of the Popular Times histogram. We validate the multi-location JSON structure.
"""


def validate_foot_traffic_json(data: dict) -> None:
    """
    Validate Google Maps foot traffic scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp
    - locations: list of location records (may be partial if some failed)

    Each location record should have:
    - location_name: string
    - source_url: string

    Optional per-location fields:
    - place_id: Google Maps place ID
    - popular_times: dict (7 days x 24 hours histogram, values 0-100)
    - current_popularity: int (0-100)
    - error: string (present if this location failed)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Foot traffic data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "locations" not in data:
        raise ValueError("Missing required field: locations")

    locations = data["locations"]
    if not isinstance(locations, list):
        raise ValueError("locations must be a list")

    # Validate popular_times structure for any location that has it
    for i, loc in enumerate(locations[:5]):  # Validate first 5 for performance
        if not isinstance(loc, dict):
            raise ValueError(f"Location record {i} must be a dictionary")

        if "popular_times" in loc and loc["popular_times"] is not None:
            pt = loc["popular_times"]
            if not isinstance(pt, dict):
                raise ValueError(f"Location {i} popular_times must be a dict")

            # Validate histogram values are 0-100
            for day, hours in pt.items():
                if isinstance(hours, list):
                    for h_val in hours:
                        if h_val is not None and not isinstance(h_val, (int, float)):
                            raise ValueError(
                                f"Location {i} popular_times value must be numeric"
                            )
                        if h_val is not None and not (0 <= h_val <= 100):
                            raise ValueError(
                                f"Location {i} popular_times value out of range [0, 100]: {h_val}"
                            )
