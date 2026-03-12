"""Bearer token authentication for the Ninja Scraper API.

Validates requests against the SCRAPER_AUTH_TOKEN environment variable.
Consistent with the gateway/proxy token authentication pattern.
"""

from __future__ import annotations

import os

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer()


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """Verify Bearer token from SCRAPER_AUTH_TOKEN environment variable.

    Args:
        credentials: HTTP Bearer credentials extracted by FastAPI.

    Returns:
        The validated token string.

    Raises:
        HTTPException: 500 if SCRAPER_AUTH_TOKEN not configured.
        HTTPException: 401 if token is invalid.
    """
    expected_token = os.environ.get("SCRAPER_AUTH_TOKEN")

    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: SCRAPER_AUTH_TOKEN not set",
        )

    if credentials.credentials != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
