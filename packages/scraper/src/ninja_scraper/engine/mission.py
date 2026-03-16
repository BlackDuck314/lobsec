"""Mission spec loader and Pydantic validation.

Missions are YAML files that declaratively define scraping targets,
extraction rules, output format, retry config, and timeout hierarchy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import structlog
import yaml
from pydantic import BaseModel, Field, model_validator

logger = structlog.get_logger()


class RetryConfig(BaseModel):
    """Retry configuration with exponential backoff and jitter."""

    max_attempts: int = Field(default=3, ge=1, le=10)
    initial_delay_ms: int = Field(default=2000, ge=100)
    max_delay_ms: int = Field(default=30000, ge=1000)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=5.0)
    jitter: bool = True
    skip_on_403: bool = False


class ConcurrencyConfig(BaseModel):
    """Concurrency and delay configuration for scraping missions."""

    max_concurrent: int = Field(default=2, ge=1, le=10)
    delay_between_requests_ms: list[int] = Field(default=[2000, 6000])
    """[min_delay, max_delay] in ms for random delay between requests."""


class Mission(BaseModel):
    """A scraping mission specification loaded from YAML.

    Defines what to scrape, how to extract data, where to save output,
    retry behavior, timeouts, and concurrency limits.
    """

    name: str
    description: str
    type: Literal["http_download", "browser_scrape", "api_call"]
    frequency: Literal["daily", "weekly", "monthly", "quarterly"]
    priority: int = Field(ge=1, le=5)
    source: dict[str, Any]
    extraction: dict[str, Any]
    output: dict[str, Any]
    retry: RetryConfig = Field(default_factory=RetryConfig)
    timeout_ms: int = Field(default=120000, ge=5000, le=3600000)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    areas: list[str] | None = None
    proxy: bool = False
    user_agent_rotation: bool = False
    schema_version: str = "1.0"

    @model_validator(mode="before")
    @classmethod
    def migrate_schema(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Validate and migrate mission schema versions."""
        version = values.get("schema_version", "1.0")
        if version == "1.0":
            return values
        else:
            logger.warning(
                "Unsupported mission schema version",
                version=version,
                mission=values.get("name", "unknown"),
            )
            raise ValueError(f"Unsupported mission schema version: {version}")


def load_mission(path: str) -> Mission:
    """Load and validate a single YAML mission file.

    Args:
        path: Path to the YAML mission file.

    Returns:
        Validated Mission instance.

    Raises:
        FileNotFoundError: If the mission file does not exist.
        yaml.YAMLError: If the YAML is malformed.
        pydantic.ValidationError: If the mission data is invalid.
    """
    mission_path = Path(path)
    if not mission_path.exists():
        raise FileNotFoundError(f"Mission file not found: {path}")

    with open(mission_path, "r") as f:
        data = yaml.safe_load(f)

    if data is None:
        raise ValueError(f"Empty mission file: {path}")

    mission = Mission(**data)
    logger.info("Mission loaded", mission=mission.name, type=mission.type, path=str(path))
    return mission


def load_all_missions(directory: str) -> dict[str, Mission]:
    """Load all YAML mission files from a directory.

    Args:
        directory: Path to directory containing *.yml mission files.

    Returns:
        Dictionary mapping mission name to validated Mission instance.
        Invalid missions are logged and skipped.
    """
    missions: dict[str, Mission] = {}
    dir_path = Path(directory)

    if not dir_path.exists():
        logger.warning("Missions directory does not exist", directory=directory)
        return missions

    for yml_file in sorted(dir_path.glob("*.yml")):
        try:
            mission = load_mission(str(yml_file))
            missions[mission.name] = mission
        except Exception as e:
            logger.error(
                "Failed to load mission",
                file=str(yml_file),
                error=str(e),
            )

    logger.info("Missions loaded", count=len(missions), directory=directory)
    return missions
