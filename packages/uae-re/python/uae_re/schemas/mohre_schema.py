"""
pandera schema for MOHRE work permits data validation (NORM-04).

MOHRE data is semi-structured (from press releases/statistical reports),
so the schema is lenient. We validate basic structure and presence of
required fields.
"""


def validate_mohre_json(data: dict) -> None:
    """
    Validate MOHRE scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp
    - source_url: URL string
    - articles: list of article objects

    Each article should have at least:
    - title: string
    - date: string (may be empty if not found)
    - url: string

    Optional article fields:
    - total_permits: number
    - sector_breakdown: dict
    - nationality_breakdown: dict
    - full_text: string

    Raises:
        ValueError: If validation fails
    """
    # Top-level structure
    if not isinstance(data, dict):
        raise ValueError("MOHRE data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "source_url" not in data:
        raise ValueError("Missing required field: source_url")

    if not isinstance(data.get("source_url"), str):
        raise ValueError("source_url must be a string")

    if "articles" not in data:
        raise ValueError("Missing required field: articles")

    if not isinstance(data["articles"], list):
        raise ValueError("articles must be a list")

    # Validate each article
    for i, article in enumerate(data["articles"]):
        if not isinstance(article, dict):
            raise ValueError(f"Article {i} must be a dictionary")

        # Required fields
        if "title" not in article:
            raise ValueError(f"Article {i} missing required field: title")

        if "date" not in article:
            raise ValueError(f"Article {i} missing required field: date")

        if "url" not in article:
            raise ValueError(f"Article {i} missing required field: url")

        # Type checks
        if not isinstance(article["title"], str):
            raise ValueError(f"Article {i} title must be a string")

        if not isinstance(article["date"], str):
            raise ValueError(f"Article {i} date must be a string")

        if not isinstance(article["url"], str):
            raise ValueError(f"Article {i} url must be a string")

        # Optional numeric field
        if "total_permits" in article:
            if not isinstance(article["total_permits"], (int, float)):
                raise ValueError(f"Article {i} total_permits must be a number")

        # Optional dict fields
        if "sector_breakdown" in article:
            if not isinstance(article["sector_breakdown"], dict):
                raise ValueError(f"Article {i} sector_breakdown must be a dict")

        if "nationality_breakdown" in article:
            if not isinstance(article["nationality_breakdown"], dict):
                raise ValueError(f"Article {i} nationality_breakdown must be a dict")
