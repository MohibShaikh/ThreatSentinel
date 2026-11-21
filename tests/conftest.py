"""
Shared test fixtures.

Every test runs offline: real aiohttp requests are refused unless a test
patches the session method it uses.
"""

import aiohttp
import pytest


@pytest.fixture(autouse=True)
def _block_real_network(monkeypatch):
    async def _refuse(self, method, url, *args, **kwargs):
        raise aiohttp.ClientConnectionError(f"Network disabled in tests: {method} {url}")

    monkeypatch.setattr(aiohttp.ClientSession, "_request", _refuse)


@pytest.fixture
def agent_config(tmp_path):
    """Planner config that writes only inside tmp_path."""
    return {
        "api_keys": {},
        "memory": {"memory_dir": str(tmp_path / "memory")},
        "reporting": {"reports_dir": str(tmp_path / "reports"), "auto_save": False},
        "audit": {"db_path": str(tmp_path / "action_logs.db")},
        "confidence_threshold": 0.7,
        "emergency_threshold": 0.8,
    }
