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
    bedrooms: Series[int] = pa.Field(
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

    Returns True if valid, raises ValueError if invalid.
    """
    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if "areas" not in data or not isinstance(data["areas"], list):
        raise ValueError("Missing or invalid field: areas (must be list)")

    for area_data in data["areas"]:
        if "area" not in area_data or not isinstance(area_data["area"], str):
            raise ValueError("Area data missing 'area' field (str)")

        if "listingCount" not in area_data or not isinstance(
            area_data["listingCount"], int
        ):
            raise ValueError("Area data missing 'listingCount' field (int)")

        if "listings" not in area_data or not isinstance(
            area_data["listings"], list
        ):
            raise ValueError("Area data missing 'listings' field (list)")

        # Validate listings array with pandera
        if len(area_data["listings"]) > 0:
            df = pd.DataFrame(area_data["listings"])
            try:
                ListingItemSchema.validate(df, lazy=True)
            except pa.errors.SchemaError as e:
                raise ValueError(f"Listing schema validation failed: {e}")

    return True
