"""Shared FastAPI dependencies."""

import hmac
from typing import TYPE_CHECKING, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_settings

if TYPE_CHECKING:
    from agent import SOCAgentPlanner

security = HTTPBearer(auto_error=False)

soc_agent: Optional["SOCAgentPlanner"] = None


def get_soc_agent() -> "SOCAgentPlanner":
    """Dependency to get the SOC agent instance"""
    if soc_agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOC Agent not initialized"
        )
    return soc_agent


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Bearer token authentication using the configured secret key."""
    settings = get_settings()

    if credentials is None:
        if settings.debug:
            return {"user_id": "debug_user", "role": "admin"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expected = settings.secret_key
    if not hmac.compare_digest(credentials.credentials, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"user_id": "api_user", "role": "admin"}
