"""Output directory management and Crawlee storage configuration.

Ensures all scraper output goes to /opt/lobsec/data/raw/ (fscrypt encrypted)
instead of Crawlee's default ./storage/ directory.
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Default base directory for raw scraper output
DEFAULT_BASE_DIR = "/opt/lobsec/data/raw"

# Set CRAWLEE_STORAGE_DIR at module import to redirect Crawlee's default storage
_base_dir = os.environ.get("SCRAPER_OUTPUT_DIR", DEFAULT_BASE_DIR)
os.environ["CRAWLEE_STORAGE_DIR"] = os.path.join(_base_dir, "crawlee-storage")


def get_base_dir() -> Path:
    """Return the configured base output directory."""
    return Path(os.environ.get("SCRAPER_OUTPUT_DIR", DEFAULT_BASE_DIR))


def ensure_output_dir(mission_name: str) -> Path:
    """Create and return the output subdirectory for a mission.

    Args:
        mission_name: The mission name used as subdirectory name.

    Returns:
        Path to the mission output directory.
    """
    output_dir = get_base_dir() / mission_name
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.debug("Output directory ensured", path=str(output_dir), mission=mission_name)
    return output_dir


def get_output_path(mission_name: str, extension: str) -> Path:
    """Generate a timestamped output file path for a mission.

    Pattern: {base_dir}/{mission_name}/{YYYY-MM-DD}.{extension}

    Args:
        mission_name: The mission name used as subdirectory name.
        extension: File extension without dot (e.g., "csv", "json").

    Returns:
        Path to the output file (directory created if needed).
    """
    output_dir = ensure_output_dir(mission_name)
    today = date.today().isoformat()
    filename = f"{today}.{extension.lstrip('.')}"
    output_path = output_dir / filename
    logger.debug(
        "Output path generated",
        path=str(output_path),
        mission=mission_name,
        extension=extension,
    )
    return output_path
