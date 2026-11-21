#!/usr/bin/env python3
"""
ThreatSentinel SOC Agent - API Server Entry Point

Host, port, reload and log level come from backend.config (env / .env):
HOST, PORT, DEBUG (enables auto-reload), LOG_LEVEL.
"""

if __name__ == "__main__":
    import uvicorn

    from backend.config import get_settings

    settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
