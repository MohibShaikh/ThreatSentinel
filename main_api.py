#!/usr/bin/env python3
"""
AITIA SOC Agent - API Server Entry Point
"""

if __name__ == "__main__":
    import uvicorn
    from backend.main import app
    
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 