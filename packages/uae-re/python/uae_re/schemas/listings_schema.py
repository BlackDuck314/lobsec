"""
Shared schema for Bayut and PropertyFinder listing data.

Validates JSON structure from listing collectors before normalization.

JSON format:
{
  "scrapedAt": "ISO timestamp",
  "areas": [
    {
      "area": "area name",
      "listingCount": 123,
      "listings": [
        {
          "price": 1500000.0,
          "bedrooms": 2,
          "sqft": 1200.0,
          "type": "Apartment",
          "reducedPrice": false
        }
      ]
    }
  ]
}
"""

import pandera as pa
from pandera.typing import Series
import pandas as pd


class ListingItemSchema(pa.DataFrameModel):
    """
    Schema for individual listing items within an area.

    All fields are optional as scraping may not always capture all data.
    """

    price: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        coerce=True
    )
    bedrooms: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        coerce=True
    )
    sqft: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        coerce=True
    )
    type: Series[str] = pa.Field(
        nullable=True,
        coerce=True
    )
    reducedPrice: Series[bool] = pa.Field(
        nullable=False,  # Always present (default False)
        coerce=True
    )

    class Config:
        strict = False  # Allow extra fields
        coerce = True


def validate_listings_json(data: dict) -> bool:
    """
    Validate the top-level JSON structure.

    Expects adapted format (dict with scrapedAt and areas).
    Call adapt_scraper_format() before this function if data is in scraper format.

    Returns True if valid, raises ValueError if invalid.
    """
    if not isinstance(data, dict):
        raise ValueError("Listing data must be a dict (use adapt_scraper_format first)")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt (should be injected from collectedAt)")

    if "areas" not in data or not isinstance(data["areas"], list):
        raise ValueError("Missing or invalid field: areas (must be list)")

    for area_data in data["areas"]:
        if "area" not in area_data or not isinstance(area_data["area"], str):
            raise ValueError("Area data missing 'area' field (str)")

        # listingCount may be None for blocked sources — default to 0
        if "listingCount" not in area_data:
            area_data["listingCount"] = 0
        if area_data["listingCount"] is None:
            area_data["listingCount"] = 0

        if "listings" not in area_data or not isinstance(
            area_data["listings"], list
        ):
            raise ValueError("Area data missing 'listings' field (list)")

        # Validate listings array with pandera (skip if empty — blocked areas)
        if len(area_data["listings"]) > 0:
            df = pd.DataFrame(area_data["listings"])
            try:
                ListingItemSchema.validate(df, lazy=True)
            except pa.errors.SchemaError as e:
                raise ValueError(f"Listing schema validation failed: {e}")

    return True
