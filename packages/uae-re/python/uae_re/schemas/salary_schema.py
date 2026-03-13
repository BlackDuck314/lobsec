"""
Pandera schema for salary survey PDF extraction validation.

Validates extracted salary data from Cooper Fitch, Hays, and Robert Half PDFs.
"""

import pandera as pa
from pandera.typing import Series


class SalaryExtractionSchema(pa.DataFrameModel):
    """
    Schema for validating extracted salary survey data.

    Must have at least 1 salary entry with role, seniority, and salary range.
    """

    role: Series[str] = pa.Field(nullable=False)
    seniority: Series[str] = pa.Field(nullable=True)
    salary_min: Series[int] = pa.Field(nullable=True, ge=0)
    salary_max: Series[int] = pa.Field(nullable=True, ge=0)
    median_salary: Series[int] = pa.Field(nullable=True, ge=0)

    class Config:
        strict = False  # Allow additional fields (e.g., sector, benefits)
        coerce = True


def validate_salary_extraction(data: dict) -> None:
    """
    Validate salary survey PDF extraction result.

    Args:
        data: Extracted salary data from pdfplumber

    Raises:
        ValueError: If no valid salary entries found
    """
    if not isinstance(data, dict):
        raise ValueError("Salary extraction data must be a dict")

    # Must have at least one of these keys with salary data
    salary_keys = ["salaries", "roles", "positions", "data"]
    has_data = any(key in data and data[key] for key in salary_keys)

    if not has_data:
        raise ValueError(
            "Salary extraction must have at least 1 salary entry "
            f"(expected one of: {salary_keys})"
        )

    # If data exists, validate it's a list with at least one entry
    for key in salary_keys:
        if key in data:
            if not isinstance(data[key], list):
                raise ValueError(f"Salary extraction {key} field must be a list")
            if len(data[key]) == 0:
                raise ValueError(
                    f"Salary extraction {key} field must have at least 1 entry"
                )
