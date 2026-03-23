"""
CBUAE Expanded (QER PDF) data validation schema.

Validates the structure of raw JSON collected from CBUAE QER PDF extraction.
Expected format: {"collectedAt": str, "quarters": {"2025-Q4": {...}, ...}}
"""

import json
import os


def validate_cbuae_expanded_json(file_path: str) -> None:
    """
    Validate CBUAE expanded JSON file exists, loads, and has expected structure.

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

    if "quarters" not in data:
        raise ValueError("Missing 'quarters' key in JSON data")

    if not isinstance(data["quarters"], dict):
        raise ValueError("'quarters' must be a JSON object")

    if len(data["quarters"]) < 1:
        raise ValueError("'quarters' must contain at least 1 entry")
