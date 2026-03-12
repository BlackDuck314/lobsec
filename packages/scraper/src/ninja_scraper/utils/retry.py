"""Exponential backoff with jitter for mission retry logic.

Implements a custom retry loop using RetryConfig from mission specs.
Respects skip_on_403 for anti-bot detection and uses +/-25% jitter
to avoid thundering herd problems.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any, Callable, TypeVar

import httpx
import structlog

from ninja_scraper.engine.mission import RetryConfig

T = TypeVar("T")


async def retry_with_jitter(
    func: Callable[..., Any],
    retry_config: RetryConfig,
    log: structlog.BoundLogger | None = None,
) -> Any:
    """Execute an async function with exponential backoff and jitter.

    Args:
        func: Async callable to execute.
        retry_config: RetryConfig from mission spec.
        log: Optional bound logger for contextual logging.

    Returns:
        Result of the function call.

    Raises:
        Exception: The last exception after all retries are exhausted,
            or immediately on 403 if skip_on_403 is True.
    """
    if log is None:
        log = structlog.get_logger()

    last_exception: Exception | None = None

    for attempt in range(retry_config.max_attempts):
        try:
            return await func()
        except Exception as e:
            last_exception = e

            # Check for 403 skip condition
            if retry_config.skip_on_403 and _is_403(e):
                log.warning(
                    "403 detected, skipping retries per mission config",
                    attempt=attempt + 1,
                    error=str(e),
                )
                raise

            # Last attempt — re-raise
            if attempt == retry_config.max_attempts - 1:
                log.error(
                    "All retry attempts exhausted",
                    attempts=retry_config.max_attempts,
                    error=str(e),
                )
                raise

            # Calculate delay with exponential backoff
            base_delay_ms = retry_config.initial_delay_ms * (
                retry_config.backoff_multiplier ** attempt
            )
            delay_ms = min(base_delay_ms, retry_config.max_delay_ms)

            # Add +/-25% jitter
            if retry_config.jitter:
                jitter_range = delay_ms * 0.25
                delay_ms = delay_ms + random.uniform(-jitter_range, jitter_range)

            # Ensure delay is positive
            delay_ms = max(delay_ms, 100)

            log.info(
                "Retrying after delay",
                attempt=attempt + 1,
                max_attempts=retry_config.max_attempts,
                delay_ms=int(delay_ms),
                error=str(e),
            )

            await asyncio.sleep(delay_ms / 1000)

    # Should not reach here, but just in case
    if last_exception:
        raise last_exception
    raise RuntimeError("Retry loop completed without result or exception")


def _is_403(exc: Exception) -> bool:
    """Check if an exception represents an HTTP 403 response."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code == 403
    return False
