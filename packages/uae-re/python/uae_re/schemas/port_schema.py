"""
pandera schema for Jebel Ali port / DP World cargo data validation (NORM-04).

Port data comes from browser-extracted JSON (DP World press releases).
Validates structure and cargo volume ranges. Construction material subset
may not always be present in press releases.
"""


def validate_port_json(data: dict) -> None:
    """
    Validate DP World / Jebel Ali port scraped JSON structure.

    Required fields:
    - scrapedAt: ISO timestamp string
    - source_url: URL string

    Optional numeric fields (at least one must be present):
    - container_throughput_teu: container volume in Twenty-foot Equivalent Units (positive)
    - cargo_volume_tonnes: total cargo in metric tonnes (positive)
    - construction_material_tonnes: construction-related cargo subset (positive or None)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Port data must be a dictionary")

    if "scrapedAt" not in data:
        raise ValueError("Missing required field: scrapedAt")

    if not isinstance(data.get("scrapedAt"), str):
        raise ValueError("scrapedAt must be a string")

    if "source_url" not in data:
        raise ValueError("Missing required field: source_url")

    if not isinstance(data.get("source_url"), str):
        raise ValueError("source_url must be a string")

    # At least container throughput or cargo volume must be present
    core_fields = ["container_throughput_teu", "cargo_volume_tonnes"]
    present_fields = [f for f in core_fields if data.get(f) is not None]

    if not present_fields:
        raise ValueError(
            f"No cargo metrics found. Expected at least one of: {core_fields}"
        )

    # Validate positive cargo volumes
    for field in present_fields:
        value = data[field]
        if not isinstance(value, (int, float)):
            raise ValueError(f"{field} must be a number, got: {type(value).__name__}")
        if value <= 0:
            raise ValueError(f"{field} must be positive, got: {value}")

    # construction_material_tonnes is optional (may not be in press release)
    # If present, it must be positive; None is explicitly allowed
    if "construction_material_tonnes" in data and data["construction_material_tonnes"] is not None:
        cmt = data["construction_material_tonnes"]
        if not isinstance(cmt, (int, float)):
            raise ValueError(f"construction_material_tonnes must be a number, got: {type(cmt).__name__}")
        if cmt <= 0:
            raise ValueError(f"construction_material_tonnes must be positive, got: {cmt}")
