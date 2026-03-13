"""
Pandera schema for job postings raw data validation.

Validates raw JSON structure from job platform scrapers (LinkedIn, Bayt, Indeed, GulfTalent).
"""

import pandera as pa
from pandera.typing import Series


class JobsRawSchema(pa.DataFrameModel):
    """
    Schema for validating raw job postings data.

    Must have either listings array or total_count field.
    Individual listings may have incomplete data (salary not always disclosed).
    """

    # Optional fields that may be present
    total_count: Series[int] = pa.Field(nullable=True, ge=0)
    job_title: Series[str] = pa.Field(nullable=True)
    company: Series[str] = pa.Field(nullable=True)
    salary_min: Series[int] = pa.Field(nullable=True, ge=0)
    salary_max: Series[int] = pa.Field(nullable=True, ge=0)
    location: Series[str] = pa.Field(nullable=True)
    seniority_level: Series[str] = pa.Field(nullable=True)

    class Config:
        strict = False  # Allow additional fields
        coerce = True  # Coerce types when possible


def validate_jobs_json(data: dict) -> None:
    """
    Validate raw job postings JSON structure.

    Args:
        data: Raw JSON data from job platform scraper

    Raises:
        ValueError: If required structure is missing
    """
    if not isinstance(data, dict):
        raise ValueError("Job postings data must be a dict")

    # Must have either listings array or total_count
    has_listings = "listings" in data or "jobs" in data or "results" in data
    has_count = "total_count" in data or "count" in data

    if not (has_listings or has_count):
        raise ValueError(
            "Job postings data must have either listings array or total_count field"
        )

    # If listings exist, should be a list
    for key in ["listings", "jobs", "results"]:
        if key in data and not isinstance(data[key], list):
            raise ValueError(f"Job postings {key} field must be a list")
