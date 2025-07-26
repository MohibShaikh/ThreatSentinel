"""
AITIA SOC Agent Backend - FastAPI Main Application

REST API server providing web-based access to SOC Agent functionality
including incident investigation, report retrieval, and real-time monitoring.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

from .config import Settings, get_settings
from .models import (
    InvestigationRequest, 
    InvestigationResponse, 
    InvestigationStatus,
    HealthResponse,
    AgentStatsResponse
)
from .routes import investigations, reports, monitoring
from ..agent import SOCAgentPlanner


# Global agent instance
soc_agent: Optional[SOCAgentPlanner] = None
active_investigations: Dict[str, Any] = {}

# Security
security = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager for startup/shutdown"""
    global soc_agent
    
    # Startup
    settings = get_settings()
    
    try:
        # Initialize SOC Agent
        agent_config = {
            'api_keys': {
                'virustotal': settings.virustotal_api_key,
                'abuseipdb': settings.abuseipdb_api_key,
                'urlvoid': settings.urlvoid_api_key,
                'shodan': settings.shodan_api_key
            },
            'memory': {
                'memory_dir': settings.memory_dir
            },
            'reporting': {
                'reports_dir': settings.reports_dir,
                'auto_save': True
            },
            'confidence_threshold': settings.confidence_threshold,
            'emergency_threshold': settings.emergency_threshold,
            'max_investigation_time': settings.max_investigation_time
        }
        
        soc_agent = SOCAgentPlanner(agent_config)
        logging.info("SOC Agent initialized successfully")
        
    except Exception as e:
        logging.error(f"Failed to initialize SOC Agent: {e}")
        raise
    
    yield
    
    # Shutdown
    logging.info("Shutting down SOC Agent backend")


# Create FastAPI app
app = FastAPI(
    title="AITIA SOC Agent API",
    description="Autonomous Security Operations Center Agent API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency to get SOC agent
def get_soc_agent() -> SOCAgentPlanner:
    """Dependency to get the SOC agent instance"""
    if soc_agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOC Agent not initialized"
        )
    return soc_agent


# Authentication dependency (optional)
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Simple token-based authentication (implement as needed)"""
    if credentials is None:
        return None  # Allow unauthenticated access for demo
    
    # Implement token validation here
    # For demo purposes, accept any token
    return {"user_id": "demo_user"}


# Include routers
app.include_router(investigations.router, prefix="/api/v1/investigations", tags=["Investigations"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["Monitoring"])

# Import and include integrations router
from backend.routes import integrations
app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["Integrations"])


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint"""
    return {
        "message": "AITIA SOC Agent API",
        "version": "2.0.0",
        "documentation": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """Health check endpoint"""
    try:
        # Check agent status
        agent_status = "healthy"
        
        # Get basic stats
        tool_count = len(agent.tools.get_available_tools())
        memory_stats = await agent.memory.get_memory_stats()
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow(),
            version="2.0.0",
            agent_status=agent_status,
            available_tools=tool_count,
            memory_investigations=memory_stats.get('total_investigations', 0),
            active_investigations=len(active_investigations)
        )
        
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        return HealthResponse(
            status="unhealthy",
            timestamp=datetime.utcnow(),
            version="2.0.0",
            agent_status="error",
            error=str(e)
        )


@app.get("/api/v1/stats", response_model=AgentStatsResponse)
async def get_agent_stats(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """Get detailed agent statistics"""
    try:
        memory_stats = await agent.memory.get_memory_stats()
        tool_capabilities = agent.tools.get_tool_capabilities()
        
        return AgentStatsResponse(
            memory_stats=memory_stats,
            tool_capabilities=tool_capabilities,
            active_investigations=len(active_investigations),
            investigation_history=memory_stats.get('by_event_type', {}),
            risk_distribution=memory_stats.get('by_risk_level', {}),
            avg_investigation_time=memory_stats.get('avg_investigation_duration_seconds', 0.0)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get agent stats: {str(e)}"
        )


@app.post("/api/v1/investigate", response_model=InvestigationResponse)
async def investigate_event(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
    agent: SOCAgentPlanner = Depends(get_soc_agent),
    current_user = Depends(get_current_user)
):
    """
    Submit a security event for investigation
    
    This endpoint accepts security event data and triggers an autonomous
    investigation using the SOC Agent's analysis pipeline.
    """
    try:
        # Generate investigation ID
        investigation_id = f"inv_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{hash(str(request.event_data)) % 10000}"
        
        # Store investigation request
        active_investigations[investigation_id] = {
            'id': investigation_id,
            'status': 'in_progress',
            'start_time': datetime.utcnow(),
            'request': request,
            'user': current_user
        }
        
        # Start investigation in background
        background_tasks.add_task(
            run_investigation,
            investigation_id,
            request.event_data,
            request.emergency_mode
        )
        
        return InvestigationResponse(
            investigation_id=investigation_id,
            status="started",
            message="Investigation started successfully",
            estimated_completion_time=datetime.utcnow(),
            priority="emergency" if request.emergency_mode else "normal"
        )
        
    except Exception as e:
        logging.error(f"Investigation request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start investigation: {str(e)}"
        )


@app.get("/api/v1/investigate/{investigation_id}/status", response_model=InvestigationStatus)
async def get_investigation_status(investigation_id: str):
    """Get the status of an ongoing investigation"""
    if investigation_id not in active_investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    investigation = active_investigations[investigation_id]
    
    return InvestigationStatus(
        investigation_id=investigation_id,
        status=investigation['status'],
        start_time=investigation['start_time'],
        current_phase=investigation.get('current_phase', 'unknown'),
        progress_percentage=investigation.get('progress', 0),
        estimated_time_remaining=investigation.get('eta', 0),
        preliminary_risk_level=investigation.get('preliminary_risk', 'unknown')
    )


@app.get("/api/v1/investigate/{investigation_id}/result")
async def get_investigation_result(investigation_id: str):
    """Get the complete result of a finished investigation"""
    if investigation_id not in active_investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    investigation = active_investigations[investigation_id]
    
    if investigation['status'] != 'completed':
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation not completed. Current status: {investigation['status']}"
        )
    
    return investigation.get('result', {})


async def run_investigation(investigation_id: str, event_data: Dict[str, Any], emergency_mode: bool = False):
    """Background task to run the investigation"""
    global soc_agent, active_investigations
    
    try:
        # Update status
        active_investigations[investigation_id]['status'] = 'running'
        active_investigations[investigation_id]['current_phase'] = 'initial_assessment'
        
        # Run investigation
        result = await soc_agent.investigate_incident(event_data, emergency_mode)
        
        # Update with results
        active_investigations[investigation_id].update({
            'status': 'completed',
            'end_time': datetime.utcnow(),
            'result': result,
            'current_phase': 'completed',
            'progress': 100
        })
        
        logging.info(f"Investigation {investigation_id} completed successfully")
        
    except Exception as e:
        logging.error(f"Investigation {investigation_id} failed: {e}")
        active_investigations[investigation_id].update({
            'status': 'failed',
            'end_time': datetime.utcnow(),
            'error': str(e),
            'current_phase': 'failed'
        })


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler"""
    logging.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Run the server
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 