"""FastAPI application for Ninja Scraper.

Provides HTTP endpoints for single-page scraping (/scrape),
mission-based crawling (/crawl), mission listing (/missions),
and health checking (/health).

Binds to 127.0.0.1:18791 (loopback only) with Bearer token
authentication on all endpoints except /health.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import structlog
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status

from ninja_scraper.api.auth import verify_token
from ninja_scraper.api.schemas import (
    CrawlRequest,
    CrawlResponse,
    JobStatus,
    MissionInfo,
    MissionResultSchema,
    ScrapeRequest,
    ScrapeResponse,
)
from ninja_scraper.engine.crawler import MissionResult, run_http_mission
from ninja_scraper.engine.handlers import execute_mission as handler_execute_mission
from ninja_scraper.engine.mission import Mission, load_all_missions
from ninja_scraper.utils.logging import setup_logging

logger = structlog.get_logger()

# In-memory state
_missions: dict[str, Mission] = {}
_jobs: dict[str, JobStatus] = {}

# Maximum concurrent background tasks
MAX_BACKGROUND_TASKS = 10
_active_task_count = 0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: load missions on startup."""
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    log = structlog.get_logger()

    missions_dir = os.environ.get(
        "MISSIONS_DIR",
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "missions"),
    )
    missions_dir = os.path.abspath(missions_dir)

    loaded = load_all_missions(missions_dir)
    _missions.update(loaded)
    log.info("Ninja Scraper starting", missions_loaded=len(_missions), missions_dir=missions_dir)

    yield

    log.info("Ninja Scraper shutting down")


app = FastAPI(
    title="Ninja Scraper",
    version="1.0.0",
    description="General-purpose web scraping engine for the lobsec ecosystem",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check() -> dict[str, Any]:
    """Unauthenticated health check endpoint.

    Returns service status, loaded mission count, and version.
    """
    return {
        "status": "ok",
        "missions_loaded": len(_missions),
        "version": "1.0.0",
    }


@app.post("/scrape", response_model=ScrapeResponse)
async def scrape_endpoint(
    request: ScrapeRequest,
    _token: str = Depends(verify_token),
) -> ScrapeResponse:
    """Execute a single-page scrape immediately.

    Uses HTTP download by default. Falls back to browser scrape
    if the URL matches known patterns requiring JavaScript rendering.
    """
    import time

    start = time.monotonic()
    log = logger.bind(url=str(request.url))

    try:
        # Create an ad-hoc mission for this scrape
        mission = Mission(
            name=f"adhoc-{uuid.uuid4().hex[:8]}",
            description=f"Ad-hoc scrape of {request.url}",
            type="http_download",
            frequency="daily",
            priority=1,
            source={"url": str(request.url), "method": "GET"},
            extraction={"format": request.format},
            output={"format": request.format},
            timeout_ms=request.timeout_ms,
        )

        result = await handler_execute_mission(mission)

        duration_ms = int((time.monotonic() - start) * 1000)

        if result.success and result.file_path:
            # Read the scraped data
            import json
            from pathlib import Path

            content = Path(result.file_path).read_text()
            try:
                data = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                data = {"content": content, "row_count": result.row_count}

            return ScrapeResponse(
                success=True,
                data=data if isinstance(data, dict) else {"items": data},
                duration_ms=duration_ms,
            )
        else:
            return ScrapeResponse(
                success=False,
                error=result.error,
                duration_ms=duration_ms,
            )

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        log.error("Scrape failed", error=str(e))
        return ScrapeResponse(
            success=False,
            error=str(e),
            duration_ms=duration_ms,
        )


@app.post("/crawl", response_model=CrawlResponse)
async def crawl_endpoint(
    request: CrawlRequest,
    background_tasks: BackgroundTasks,
    _token: str = Depends(verify_token),
) -> CrawlResponse:
    """Queue a named mission for background execution.

    Returns immediately with a job_id that can be polled via GET /crawl/{job_id}.
    """
    global _active_task_count

    # Validate mission exists
    if request.mission_name not in _missions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission not found: {request.mission_name}",
        )

    # Check concurrent task limit
    if _active_task_count >= MAX_BACKGROUND_TASKS:
        logger.warning(
            "Background task limit reached",
            active=_active_task_count,
            max=MAX_BACKGROUND_TASKS,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many background tasks ({_active_task_count}/{MAX_BACKGROUND_TASKS})",
        )

    # Create job
    job_id = str(uuid.uuid4())
    _jobs[job_id] = JobStatus(
        job_id=job_id,
        status="queued",
        mission_name=request.mission_name,
    )

    # Queue background execution
    background_tasks.add_task(
        _run_background_mission, job_id, request.mission_name, request.params
    )

    logger.info(
        "Mission queued",
        job_id=job_id,
        mission=request.mission_name,
    )

    return CrawlResponse(
        job_id=job_id,
        status="queued",
        message=f"Mission '{request.mission_name}' queued for execution",
    )


@app.get("/crawl/{job_id}", response_model=JobStatus)
async def get_crawl_status(
    job_id: str,
    _token: str = Depends(verify_token),
) -> JobStatus:
    """Return the status of a background crawl job."""
    if job_id not in _jobs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {job_id}",
        )
    return _jobs[job_id]


@app.get("/missions", response_model=list[MissionInfo])
async def list_missions(
    _token: str = Depends(verify_token),
) -> list[MissionInfo]:
    """List all loaded missions with their metadata."""
    return [
        MissionInfo(
            name=m.name,
            description=m.description,
            type=m.type,
            frequency=m.frequency,
            priority=m.priority,
        )
        for m in sorted(_missions.values(), key=lambda m: (m.priority, m.name))
    ]


async def _run_background_mission(job_id: str, mission_name: str, params: dict) -> None:
    """Background task: execute a mission via handler and update job status.

    Uses the handler module's execute_mission() for type-specific dispatch
    including area iteration, timeout enforcement, and error wrapping.

    Args:
        job_id: Unique job identifier.
        mission_name: Name of the mission to execute.
        params: Mission-specific parameters.
    """
    global _active_task_count
    _active_task_count += 1
    log = logger.bind(job_id=job_id, mission=mission_name)

    try:
        # Update status to running
        _jobs[job_id].status = "running"
        _jobs[job_id].started_at = datetime.now(timezone.utc).isoformat()
        log.info("Mission execution started")

        mission = _missions[mission_name]

        # Execute via handler (dispatches by type, handles areas, enforces timeout)
        result = await handler_execute_mission(mission)

        # Update job status
        _jobs[job_id].completed_at = datetime.now(timezone.utc).isoformat()
        _jobs[job_id].result = MissionResultSchema(
            success=result.success,
            file_path=result.file_path,
            row_count=result.row_count,
            duration_ms=result.duration_ms,
            error=result.error,
            mission_name=result.mission_name,
        )

        if result.success:
            _jobs[job_id].status = "completed"
            log.info(
                "Mission execution completed",
                row_count=result.row_count,
                duration_ms=result.duration_ms,
                file_path=result.file_path,
            )
        else:
            _jobs[job_id].status = "failed"
            _jobs[job_id].error = result.error
            log.error("Mission execution failed", error=result.error)

    except Exception as e:
        _jobs[job_id].status = "failed"
        _jobs[job_id].error = str(e)
        _jobs[job_id].completed_at = datetime.now(timezone.utc).isoformat()
        log.error("Mission execution error", error=str(e))

    finally:
        _active_task_count -= 1


def main() -> None:
    """Entry point for the ninja-scraper command."""
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))

    uvicorn.run(
        "ninja_scraper.api.main:app",
        host="127.0.0.1",
        port=int(os.environ.get("SCRAPER_PORT", "18791")),
        timeout_keep_alive=900,  # 15 min, above any mission timeout
        log_level="info",
    )


if __name__ == "__main__":
    main()
