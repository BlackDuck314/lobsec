"""
Google Trends Schema (pandera)

Validates the structure of a single keyword group's DataFrame as fetched
from pytrends.interest_over_time(). Each group DataFrame has:
  - index: date (DatetimeIndex, weekly periods)
  - columns: one per keyword (int, 0-100 Google Trends scale)

NORM-04: Hard error on schema validation failure.
"""

import pandera as pa
from pandera import Column, DataFrameSchema

# Trends data schema — validates a single group DataFrame.
# Keyword columns are validated as integers in 0-100 range with nullable=True
# (Google Trends returns null for some periods when data is insufficient).
# The 'date' column is added after reset_index() in normalization.
trends_schema = DataFrameSchema(
    {
        "date": Column(
            str,
            nullable=False,
            description="ISO date string from DatetimeIndex (weekly)",
        ),
    },
    # Allow any additional columns (the keyword columns — variable names per group)
    # by setting strict=False. Each keyword column is validated separately below.
    strict=False,
    coerce=True,
)


def validate_trends_group(df, group_name: str):
    """Validate a single keyword group DataFrame.

    Checks:
    - Has at least one row
    - Has at least one keyword column beyond 'date'
    - All keyword columns are numeric (0-100 scale)

    Args:
        df: DataFrame from pytrends.interest_over_time() with 'date' column added.
        group_name: Name of the keyword group (for error messages).

    Returns:
        Validated DataFrame.

    Raises:
        pa.errors.SchemaError: If validation fails.
        ValueError: If DataFrame is empty or has no keyword columns.
    """
    if df.empty:
        raise ValueError(f"Empty trends DataFrame for group '{group_name}'")

    keyword_cols = [c for c in df.columns if c != "date"]
    if not keyword_cols:
        raise ValueError(f"No keyword columns found in trends DataFrame for group '{group_name}'")

    # Validate keyword columns are numeric in 0-100 range
    col_schemas = {
        "date": Column(str, nullable=False),
    }
    for col in keyword_cols:
        col_schemas[col] = Column(
            pa.Float,
            pa.Check.in_range(0, 100),
            nullable=True,
            required=False,
        )

    schema = DataFrameSchema(col_schemas, strict=False, coerce=True)
    return schema.validate(df)
