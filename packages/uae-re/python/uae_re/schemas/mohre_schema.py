"""
Schema validation for MOHRE Observatory dashboard data (NORM-07).

MOHRE data comes from observatory.mohre.gov.ae dashboard scrape,
saved as JSON with stat_cards and chart_labels arrays.
"""

import json
import os


def validate_mohre_json(file_path: str) -> list[dict]:
    """
    Validate MOHRE JSON file exists, is readable, and has expected structure.

    Args:
        file_path: Path to JSON file

    Returns:
        Parsed JSON data (list of page objects)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(file_path, str):
        raise ValueError("file_path must be a string")

    if not os.path.exists(file_path):
        raise ValueError(f"JSON file does not exist: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"File is not valid JSON: {e}")
    except IOError as e:
        raise ValueError(f"Cannot read file: {e}")

    if not isinstance(data, list) or len(data) == 0:
        raise ValueError("MOHRE JSON must be a non-empty list")

    for i, page in enumerate(data):
        if not isinstance(page, dict):
            raise ValueError(f"Item {i} must be a dict")
        if "stat_cards" not in page:
            raise ValueError(f"Item {i} missing 'stat_cards' key")
        if not isinstance(page["stat_cards"], list):
            raise ValueError(f"Item {i} 'stat_cards' must be a list")
        if "chart_labels" not in page:
            raise ValueError(f"Item {i} missing 'chart_labels' key")
        if not isinstance(page["chart_labels"], list):
            raise ValueError(f"Item {i} 'chart_labels' must be a list")

    return data
