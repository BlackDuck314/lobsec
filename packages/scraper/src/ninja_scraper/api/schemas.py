"""Pydantic request/response models for the Ninja Scraper API.

Defines schemas for /scrape, /crawl, /missions, and /health endpoints.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl


class ScrapeRequest(BaseModel):
    """Request body for POST /scrape - single-page immediate scrape."""

    url: HttpUrl
    format: str = Field(default="json", description="Output format: json, csv, html")
    timeout_ms: int = Field(
        default=30000, ge=5000, le=600000, description="Timeout in milliseconds"
    )


class ScrapeResponse(BaseModel):
    """Response body for POST /scrape."""

    success: bool
    data: dict | None = None
    error: str | None = None
    duration_ms: int = 0


class CrawlRequest(BaseModel):
    """Request body for POST /crawl - queue a named mission."""

    mission_name: str = Field(description="Name of the mission to execute")
    params: dict = Field(default_factory=dict, description="Mission-specific parameters")
    force: bool = Field(default=False, description="Force re-run even if recent data exists")


class CrawlResponse(BaseModel):
    """Response body for POST /crawl."""

    job_id: str
    status: str = Field(description="Job status: queued, running, completed, failed")
    message: str


class MissionResultSchema(BaseModel):
    """Schema for mission execution result (embedded in JobStatus)."""

    success: bool
    file_path: str | None = None
    row_count: int = 0
    duration_ms: int = 0
    error: str | None = None
    mission_name: str = ""


class JobStatus(BaseModel):
    """Response body for GET /crawl/{job_id}."""

    job_id: str
    status: str = Field(description="Job status: queued, running, completed, failed")
    mission_name: str
    started_at: str | None = None
    completed_at: str | None = None
    result: MissionResultSchema | None = None
    error: str | None = None


class MissionInfo(BaseModel):
    """Mission summary for GET /missions listing."""

    name: str
    description: str
    type: str
    frequency: str
    priority: int
