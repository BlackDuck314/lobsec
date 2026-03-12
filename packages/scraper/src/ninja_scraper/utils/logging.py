"""Structured logging setup for Ninja Scraper.

Configures structlog with JSON output, timestamps, and async-safe
processors. Adds context processors for mission and scraper metadata.
"""

from __future__ import annotations

import logging
import sys

import structlog


def setup_logging(level: str = "INFO") -> structlog.BoundLogger:
    """Configure structlog with JSON output and timestamp processors.

    Sets up structured logging that is async-safe and suitable for
    production use with systemd journal capture.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).

    Returns:
        Configured structlog BoundLogger instance.
    """
    # Configure stdlib logging for integration
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    log = structlog.get_logger("ninja_scraper")
    log.info("Logging configured", level=level)
    return log
