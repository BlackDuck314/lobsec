"""
World Bank API data validation schema.

Validates the structure of raw JSON collected from the World Bank Indicators API.
Expected format: {"collectedAt": str, "indicators": {label: [records...]}}
"""

import json
import os


def validate_worldbank_json(file_path: str) -> None:
    """
    Validate World Bank JSON file exists, loads, and has expected structure.

    Args:
        file_path: Path to JSON file

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(file_path, str):
        raise ValueError("file_path must be a string")

    if not os.path.exists(file_path):
        raise ValueError(f"JSON file does not exist: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    if not file_path.lower().endswith(".json"):
        raise ValueError(f"File is not JSON: {file_path}")

    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        raise ValueError(f"Cannot read/parse JSON file: {e}")

    if not isinstance(data, dict):
        raise ValueError("Root element must be a JSON object")

    if "indicators" not in data:
        raise ValueError("Missing 'indicators' key in JSON data")

    if not isinstance(data["indicators"], dict):
        raise ValueError("'indicators' must be a JSON object")
