"""
DLD Transactions Schema (pandera)

Validates raw DLD transaction CSV data from Dubai Pulse before normalization.
Same schema used for both DLD sales and Ejari rentals (same source CSV).

NORM-04: Hard error on schema validation failure.
"""

import pandera as pa
from pandera import Column, DataFrameSchema

# DLD transactions schema
# coerce=True handles CSV string/int type variations
# nullable=True for optional fields
dld_schema = DataFrameSchema(
    {
        "trans_group_en": Column(
            str, pa.Check.isin(["Sales", "Mortgage", "Gift", "Rent"])
        ),
        "actual_worth": Column(float, pa.Check.ge(0), nullable=True),
        "meter_sale_price": Column(float, pa.Check.ge(0), nullable=True),
        "prop_type_en": Column(str, nullable=True),
        "area_name_en": Column(str, nullable=True),
        "rooms_en": Column(str, nullable=True),
        "procedure_name_en": Column(str, nullable=True),
        "trans_date": Column(str),  # Date string, will be parsed later
    },
    coerce=True,  # Coerce types from CSV strings
)
