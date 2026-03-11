"""
ADREC Abu Dhabi transaction data schema.

Validates CSV downloads from ADREC dashboard before normalization.

Fields (based on CONTEXT.md and ADREC documentation):
- Asset Type: Residential, Commercial, Industrial, etc.
- Property Type: Apartment, Villa, Office, Warehouse, etc.
- Sale Type: Off-plan, Ready
- District: Administrative district in Abu Dhabi
- Community: Sub-area within district
- Project: Development project name
- Layout: Bedroom count (Studio, 1BR, 2BR, etc.)
- Registration Date: Transaction registration date
- Sold Area: Built-up area in sqm
- Plot Area: Land area in sqm (for villas/land)
- Rate: Price per sqm in AED
- Price: Total transaction price in AED
- Share: Ownership share percentage
- Sequence: Primary (first sale) or Secondary (resale)

Lease-specific fields:
- Contract Date: Lease contract date
- Rent: Annual rent in AED

Index-specific fields:
- Period: Time period for index
- Index Value: Price index value
"""

import pandera as pa
from pandera.typing import Series


class ADRECTransactionSchema(pa.DataFrameModel):
    """
    Schema for ADREC transaction data (sales).

    Flexible column names to handle variations in CSV exports.
    All columns are optional except core identifiers to handle
    different CSV formats from dashboard sections.
    """

    # Core transaction fields
    registration_date: Series[str] = pa.Field(
        nullable=True,
        alias="Registration Date",
        coerce=True
    )
    price: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        alias="Price",
        coerce=True
    )

    # Property identification
    asset_type: Series[str] = pa.Field(
        nullable=True,
        alias="Asset Type",
        coerce=True
    )
    property_type: Series[str] = pa.Field(
        nullable=True,
        alias="Property Type",
        coerce=True
    )
    district: Series[str] = pa.Field(
        nullable=True,
        alias="District",
        coerce=True
    )

    # Sale characteristics
    sale_type: Series[str] = pa.Field(
        nullable=True,
        alias="Sale Type",
        coerce=True
    )
    sequence: Series[str] = pa.Field(
        nullable=True,
        alias="Sequence",
        coerce=True
    )

    # Area measurements
    sold_area: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        alias="Sold Area",
        coerce=True
    )
    plot_area: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        alias="Plot Area",
        coerce=True
    )
    rate: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        alias="Rate",
        coerce=True
    )

    # Optional fields
    community: Series[str] = pa.Field(
        nullable=True,
        alias="Community",
        coerce=True
    )
    project: Series[str] = pa.Field(
        nullable=True,
        alias="Project",
        coerce=True
    )
    layout: Series[str] = pa.Field(
        nullable=True,
        alias="Layout",
        coerce=True
    )
    share: Series[float] = pa.Field(
        ge=0,
        le=100,
        nullable=True,
        alias="Share",
        coerce=True
    )

    class Config:
        strict = False  # Allow extra columns
        coerce = True   # Auto-convert types


class ADRECLeaseSchema(pa.DataFrameModel):
    """
    Schema for ADREC residential lease data.
    """

    contract_date: Series[str] = pa.Field(
        nullable=True,
        alias="Contract Date",
        coerce=True
    )
    rent: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        alias="Rent",
        coerce=True
    )
    district: Series[str] = pa.Field(
        nullable=True,
        alias="District",
        coerce=True
    )
    property_type: Series[str] = pa.Field(
        nullable=True,
        alias="Property Type",
        coerce=True
    )
    layout: Series[str] = pa.Field(
        nullable=True,
        alias="Layout",
        coerce=True
    )

    class Config:
        strict = False
        coerce = True


class ADRECIndexSchema(pa.DataFrameModel):
    """
    Schema for ADREC price index data.
    """

    period: Series[str] = pa.Field(
        nullable=True,
        alias="Period",
        coerce=True
    )
    index_value: Series[float] = pa.Field(
        ge=0,
        nullable=True,
        alias="Index Value",
        coerce=True
    )
    district: Series[str] = pa.Field(
        nullable=True,
        alias="District",
        coerce=True
    )
    property_type: Series[str] = pa.Field(
        nullable=True,
        alias="Property Type",
        coerce=True
    )

    class Config:
        strict = False
        coerce = True
