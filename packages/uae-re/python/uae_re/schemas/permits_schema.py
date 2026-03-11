"""
Building Permits Schema (pandera)

Validates raw building permits CSV data from Dubai Pulse before normalization.
The schema is generous with nullable=True for non-critical fields since exact column
names may vary in the Dubai Pulse dataset.

NORM-04: Hard error on schema validation failure.
"""

import pandera as pa
from pandera import Column, DataFrameSchema

# Building permits schema
# coerce=True handles CSV string/int type variations
# nullable=True for optional fields
permits_schema = DataFrameSchema(
    {
        # Critical fields (must exist)
        "permit_number": Column(str, nullable=True),
        "issue_date": Column(str),  # Date string, will be parsed later
        "status": Column(str, nullable=True),  # issued/withdrawn/expired/approved
        # Building classification fields (at least one should exist for type classification)
        "permit_type": Column(str, nullable=True),
        "building_type": Column(str, nullable=True),
        "usage": Column(str, nullable=True),
        "project_type": Column(str, nullable=True),
        # Location fields
        "area": Column(str, nullable=True),
        "zone": Column(str, nullable=True),
        "location": Column(str, nullable=True),
        # Metrics (optional)
        "floors": Column(float, pa.Check.ge(0), nullable=True),
        "units": Column(float, pa.Check.ge(0), nullable=True),
        "built_up_area": Column(float, pa.Check.ge(0), nullable=True),
    },
    coerce=True,  # Coerce types from CSV strings
    strict=False,  # Allow additional columns not in schema
)
