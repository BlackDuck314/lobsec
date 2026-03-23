"""
S&P Global PMI data validation schema.

Validates the structure of raw JSON collected from the PMI collector.
Expected format: {"collectedAt": str, "pmi_value": float|null, ...}

If pmi_value is present (not null), validates it falls within a
reasonable PMI range (30.0 to 70.0).
"""

import json
import os


def validate_pmi_json(file_path: str) -> None:
    """
    Validate PMI JSON file exists, loads, and has expected structure.

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

    if "collectedAt" not in data:
        raise ValueError("Missing 'collectedAt' key in JSON data")

    # pmi_value can be null (collection failed) or a float
    pmi_value = data.get("pmi_value")
    if pmi_value is not None:
        if not isinstance(pmi_value, (int, float)):
            raise ValueError(f"pmi_value must be a number or null, got {type(pmi_value).__name__}")
        if pmi_value < 30.0 or pmi_value > 70.0:
            raise ValueError(f"pmi_value {pmi_value} outside reasonable PMI range (30.0-70.0)")
