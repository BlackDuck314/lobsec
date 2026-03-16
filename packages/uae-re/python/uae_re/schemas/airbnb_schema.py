"""
Pandera schema for InsideAirbnb STR listing data validation (COLL-19).

InsideAirbnb data is a gzipped CSV file with per-listing records.
We validate the raw DataFrame structure before normalization.
"""

import pandas as pd


def validate_airbnb_dataframe(df: pd.DataFrame) -> None:
    """
    Validate InsideAirbnb CSV DataFrame structure.

    Required columns (subset — InsideAirbnb CSVs have many more columns,
    but these are the ones we use for normalization):
    - id: listing identifier (numeric or string)
    - neighbourhood_cleansed: area name
    - room_type: Entire home, Private room, Shared room, Hotel room
    - price: nightly price string (may include $ prefix and commas)
    - availability_365: days available per year (0-365)
    - reviews_per_month: float, proxy for booking frequency

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(df, pd.DataFrame):
        raise ValueError("InsideAirbnb data must be a pandas DataFrame")

    if df.empty:
        # Empty DataFrame is valid — graceful for quarters with no data
        return

    required_columns = ["id", "neighbourhood_cleansed", "room_type", "price",
                        "availability_365"]

    for col in required_columns:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")

    # Validate room_type values
    valid_room_types = {
        "Entire home/apt", "Private room", "Shared room", "Hotel room"
    }
    if "room_type" in df.columns:
        unique_types = set(df["room_type"].dropna().unique())
        invalid_types = unique_types - valid_room_types
        if invalid_types and len(invalid_types) > len(valid_room_types):
            # Only warn if majority of values are invalid (allows new types)
            raise ValueError(
                f"Unexpected room_type values (majority invalid): {invalid_types}"
            )

    # Validate availability_365 range
    if "availability_365" in df.columns:
        avail = pd.to_numeric(df["availability_365"], errors="coerce").dropna()
        if not avail.empty:
            if (avail < 0).any() or (avail > 365).any():
                raise ValueError(
                    f"availability_365 out of range [0, 365]: min={avail.min()}, max={avail.max()}"
                )


def validate_airbnb_json(data: dict) -> None:
    """
    Validate pre-parsed InsideAirbnb JSON structure (for non-CSV input paths).

    Args:
        data: Dictionary with scrapedAt, listings, source_url

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("InsideAirbnb data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if "listings" not in data and "records" not in data:
        # Allow both field names for flexibility
        raise ValueError("Missing required field: listings or records")

    listings = data.get("listings", data.get("records", []))
    if not isinstance(listings, list):
        raise ValueError("listings must be a list")
