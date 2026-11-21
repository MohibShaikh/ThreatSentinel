"""Shared FastAPI dependencies and process-wide singletons (set up in the lifespan)."""

import asyncio
import hmac
from typing import TYPE_CHECKING, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_settings

if TYPE_CHECKING:
    from agent import SOCAgentPlanner, TaskQueue

    from .store import InvestigationStore

security = HTTPBearer(auto_error=False)

soc_agent: Optional["SOCAgentPlanner"] = None
investigation_store: Optional["InvestigationStore"] = None
task_queue: Optional["TaskQueue"] = None
# investigation_id -> running asyncio.Task, so DELETE can actually cancel work
running_investigations: Dict[str, asyncio.Task] = {}


def get_soc_agent() -> "SOCAgentPlanner":
    if soc_agent is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SOC Agent not initialized")
    return soc_agent


def get_store() -> "InvestigationStore":
    if investigation_store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Investigation store not initialized")
    return investigation_store


def get_task_queue() -> "TaskQueue":
    if task_queue is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Task queue not initialized")
    return task_queue


def verify_token(token: Optional[str]) -> bool:
    """Constant-time comparison against the configured API secret."""
    expected = get_settings().secret_key
    if not token or not expected:
        return False
    return hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Bearer token authentication using the configured secret key.

    With DEBUG=true and no token, requests run as a debug user so local
    development works without a token. A token that is sent is always checked.
    """
    settings = get_settings()
    if credentials is None:
        if settings.debug:
            return {"user_id": "debug_user", "role": "admin"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_token(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"user_id": "api_user", "role": "admin"}
