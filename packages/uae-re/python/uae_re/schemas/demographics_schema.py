"""
pandera schema for FCSA/DSC demographics data validation (NORM-04).

Demographics data comes from browser-extracted JSON (Dubai Statistics Centre).
Validates structure and population value ranges. Annual data — most quarterly
runs will return empty, which is valid.
"""


def validate_demographics_json(data: dict) -> None:
    """
    Validate DSC demographics scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp string
    - source_url: URL string

    Optional numeric fields:
    - total_population: total Dubai population estimate (positive)
    - population_growth_rate: YoY growth rate as percentage
    - expat_population: non-national population count (non-negative)
    - national_population: UAE national population count (non-negative)
    - working_age_pct: percentage in 25-54 age bracket (0-100)

    Note: Empty data dict (no population fields) is valid for most quarterly
    runs when no new annual bulletin has been published.

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Demographics data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "source_url" not in data:
        raise ValueError("Missing required field: source_url")

    if not isinstance(data.get("source_url"), str):
        raise ValueError("source_url must be a string")

    # Validate population fields if present
    if data.get("total_population") is not None:
        pop = data["total_population"]
        if not isinstance(pop, (int, float)):
            raise ValueError(f"total_population must be a number, got: {type(pop).__name__}")
        if pop <= 0:
            raise ValueError(f"total_population must be positive, got: {pop}")

    if data.get("population_growth_rate") is not None:
        rate = data["population_growth_rate"]
        if not isinstance(rate, (int, float)):
            raise ValueError(f"population_growth_rate must be a number, got: {type(rate).__name__}")
        # Dubai growth rate typically 0-10% but allow wider range for edge cases
        if rate < -10 or rate > 20:
            raise ValueError(
                f"population_growth_rate {rate}% outside expected range (-10% to 20%). "
                f"Check extraction logic."
            )

    if data.get("working_age_pct") is not None:
        pct = data["working_age_pct"]
        if not isinstance(pct, (int, float)):
            raise ValueError(f"working_age_pct must be a number, got: {type(pct).__name__}")
        if pct < 0 or pct > 100:
            raise ValueError(f"working_age_pct {pct} outside valid range (0-100)")
