"""
pandera schema for DEWA connections data validation (NORM-04).

DEWA data is semi-structured (from press releases), so the schema is lenient.
We validate basic structure and presence of required fields.
"""

import pandera as pa
from pandera.typing import Series, DataFrame


def validate_dewa_json(data: dict) -> None:
    """
    Validate DEWA scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp
    - source_url: URL string
    - articles: list of article objects

    Each article should have at least:
    - title: string
    - date: string (may be empty if not found)
    - url: string

    Optional article fields:
    - connections_new: number
    - disconnections: number
    - areas_mentioned: list of strings
    - full_text: string

    Raises:
        ValueError: If validation fails
    """
    # Top-level structure
    if not isinstance(data, dict):
        raise ValueError("DEWA data must be a dictionary")

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

        # Optional numeric fields
        if "connections_new" in article:
            if not isinstance(article["connections_new"], (int, float)):
                raise ValueError(f"Article {i} connections_new must be a number")

        if "disconnections" in article:
            if not isinstance(article["disconnections"], (int, float)):
                raise ValueError(f"Article {i} disconnections must be a number")

        # Optional list field
        if "areas_mentioned" in article:
            if not isinstance(article["areas_mentioned"], list):
                raise ValueError(f"Article {i} areas_mentioned must be a list")
