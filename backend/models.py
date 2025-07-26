"""
AITIA SOC Agent Backend Models

Pydantic models for API request and response validation.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, validator
from enum import Enum


class EventType(str, Enum):
    """Security event types"""
    SUSPICIOUS_IP = "suspicious_ip"
    LOGIN_ANOMALY = "login_anomaly"
    SUSPICIOUS_URL = "suspicious_url"
    DDOS_SIGNS = "ddos_signs"
    MALWARE_DETECTION = "malware_detection"
    PHISHING_ATTEMPT = "phishing_attempt"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvestigationRequest(BaseModel):
    """Request model for security event investigation"""
    event_data: Dict[str, Any] = Field(..., description="Security event data to investigate")
    emergency_mode: bool = Field(default=False, description="Enable emergency investigation mode")
    priority: Optional[str] = Field(default="normal", description="Investigation priority")
    user_context: Optional[Dict[str, Any]] = Field(default=None, description="Additional user context")
    
    @validator('event_data')
    def validate_event_data(cls, v):
        """Validate that event_data contains required fields"""
        if not isinstance(v, dict):
            raise ValueError("event_data must be a dictionary")
        
        # Require at least an event_type
        if 'event_type' not in v:
            raise ValueError("event_data must contain 'event_type' field")
        
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "event_data": {
                    "event_type": "suspicious_ip",
                    "source_ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0...",
                    "payload": {
                        "failed_login_attempts": 25,
                        "accessed_endpoints": ["/admin", "/login"],
                        "time_window": "10 minutes"
                    },
                    "timestamp": "2024-01-15T10:30:00Z"
                },
                "emergency_mode": False,
                "priority": "normal"
            }
        }


class InvestigationResponse(BaseModel):
    """Response model for investigation submission"""
    investigation_id: str = Field(..., description="Unique investigation identifier")
    status: str = Field(..., description="Current investigation status")
    message: str = Field(..., description="Human-readable status message")
    estimated_completion_time: datetime = Field(..., description="Estimated completion time")
    priority: str = Field(..., description="Investigation priority level")
    
    class Config:
        schema_extra = {
            "example": {
                "investigation_id": "inv_20240115_103000_1234",
                "status": "started",
                "message": "Investigation started successfully",
                "estimated_completion_time": "2024-01-15T10:35:00Z",
                "priority": "normal"
            }
        }


class InvestigationStatus(BaseModel):
    """Model for investigation status updates"""
    investigation_id: str = Field(..., description="Investigation identifier")
    status: str = Field(..., description="Current status (pending, running, completed, failed)")
    start_time: datetime = Field(..., description="Investigation start time")
    current_phase: str = Field(..., description="Current investigation phase")
    progress_percentage: int = Field(default=0, ge=0, le=100, description="Progress percentage")
    estimated_time_remaining: int = Field(default=0, description="Estimated seconds remaining")
    preliminary_risk_level: Optional[str] = Field(default=None, description="Preliminary risk assessment")
    
    class Config:
        schema_extra = {
            "example": {
                "investigation_id": "inv_20240115_103000_1234",
                "status": "running",
                "start_time": "2024-01-15T10:30:00Z",
                "current_phase": "intelligence_gathering",
                "progress_percentage": 60,
                "estimated_time_remaining": 45,
                "preliminary_risk_level": "medium"
            }
        }


class ActionRecommendation(BaseModel):
    """Model for recommended security actions"""
    action_type: str = Field(..., description="Type of action (BLOCK, ESCALATE, INVESTIGATE, etc.)")
    priority: int = Field(..., ge=1, le=5, description="Action priority (1=highest, 5=lowest)")
    description: str = Field(..., description="Human-readable action description")
    estimated_effort: str = Field(..., description="Estimated time/effort required")
    technical_details: Optional[str] = Field(default="", description="Technical implementation details")
    urgency: Optional[str] = Field(default="medium", description="Urgency level")


class ThreatIntelligence(BaseModel):
    """Model for threat intelligence data"""
    sources_consulted: List[str] = Field(..., description="List of intelligence sources consulted")
    overall_reputation_score: float = Field(..., ge=0.0, le=1.0, description="Overall reputation score")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the intelligence")
    threat_indicators: List[str] = Field(default=[], description="List of threat indicators found")
    source_details: List[Dict[str, Any]] = Field(default=[], description="Detailed results from each source")


class RiskAssessment(BaseModel):
    """Model for risk assessment results"""
    overall_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk score")
    risk_level: RiskLevel = Field(..., description="Categorical risk level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in assessment")
    component_scores: Dict[str, float] = Field(..., description="Individual component risk scores")
    risk_factors: List[str] = Field(default=[], description="Factors contributing to risk")
    mitigating_factors: List[str] = Field(default=[], description="Factors reducing risk")


class InvestigationReport(BaseModel):
    """Complete investigation report model"""
    metadata: Dict[str, Any] = Field(..., description="Report metadata")
    executive_summary: str = Field(..., description="Executive summary of findings")
    event_analysis: Dict[str, Any] = Field(..., description="Detailed event analysis")
    threat_intelligence: ThreatIntelligence = Field(..., description="Threat intelligence findings")
    risk_assessment: RiskAssessment = Field(..., description="Risk assessment results")
    recommended_actions: List[ActionRecommendation] = Field(..., description="Recommended actions")
    investigation_timeline: List[str] = Field(..., description="Investigation reasoning log")
    technical_details: Dict[str, Any] = Field(..., description="Technical analysis details")
    indicators: List[Dict[str, Any]] = Field(default=[], description="Indicators of compromise")


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str = Field(..., description="Overall health status")
    timestamp: datetime = Field(..., description="Health check timestamp")
    version: str = Field(..., description="API version")
    agent_status: str = Field(..., description="SOC Agent status")
    available_tools: Optional[int] = Field(default=0, description="Number of available tools")
    memory_investigations: Optional[int] = Field(default=0, description="Total investigations in memory")
    active_investigations: Optional[int] = Field(default=0, description="Currently active investigations")
    error: Optional[str] = Field(default=None, description="Error message if unhealthy")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-15T10:30:00Z",
                "version": "2.0.0",
                "agent_status": "healthy",
                "available_tools": 4,
                "memory_investigations": 150,
                "active_investigations": 2
            }
        }


class AgentStatsResponse(BaseModel):
    """Detailed agent statistics response"""
    memory_stats: Dict[str, Any] = Field(..., description="Memory system statistics")
    tool_capabilities: Dict[str, List[str]] = Field(..., description="Available tool capabilities")
    active_investigations: int = Field(..., description="Number of active investigations")
    investigation_history: Dict[str, int] = Field(..., description="Investigation count by event type")
    risk_distribution: Dict[str, int] = Field(..., description="Investigation count by risk level")
    avg_investigation_time: float = Field(..., description="Average investigation duration in seconds")


class ReportRequest(BaseModel):
    """Request model for generating reports"""
    investigation_id: str = Field(..., description="Investigation ID to generate report for")
    format: str = Field(default="json", description="Report format (json, markdown, html)")
    include_raw_data: bool = Field(default=False, description="Include raw intelligence data")
    
    @validator('format')
    def validate_format(cls, v):
        """Validate report format"""
        allowed_formats = ['json', 'markdown', 'html']
        if v.lower() not in allowed_formats:
            raise ValueError(f"Format must be one of: {allowed_formats}")
        return v.lower()


class ReportResponse(BaseModel):
    """Response model for report generation"""
    report_id: str = Field(..., description="Generated report identifier")
    investigation_id: str = Field(..., description="Source investigation ID")
    format: str = Field(..., description="Report format")
    generated_at: datetime = Field(..., description="Report generation timestamp")
    file_path: Optional[str] = Field(default=None, description="File path if saved to disk")
    content: Optional[str] = Field(default=None, description="Report content for inline display")


class MonitoringMetrics(BaseModel):
    """Real-time monitoring metrics"""
    timestamp: datetime = Field(..., description="Metrics timestamp")
    active_investigations: int = Field(..., description="Currently active investigations")
    completed_investigations_today: int = Field(..., description="Investigations completed today")
    average_investigation_time: float = Field(..., description="Average investigation time today")
    high_risk_events_today: int = Field(..., description="High/critical risk events today")
    api_response_time: float = Field(..., description="Average API response time")
    memory_usage_mb: float = Field(..., description="Current memory usage in MB")
    threat_intel_api_calls: Dict[str, int] = Field(..., description="API calls by source")
    error_rate: float = Field(..., description="Current error rate percentage")


class AlertConfiguration(BaseModel):
    """Configuration for automated alerts"""
    enabled: bool = Field(default=True, description="Enable/disable alerts")
    risk_threshold: RiskLevel = Field(default=RiskLevel.HIGH, description="Minimum risk level for alerts")
    notification_channels: List[str] = Field(default=["email"], description="Alert notification channels")
    escalation_delay_minutes: int = Field(default=30, description="Minutes before escalation")
    emergency_contacts: List[str] = Field(default=[], description="Emergency contact list")


class EventSubscription(BaseModel):
    """Model for real-time event subscriptions"""
    subscription_id: str = Field(..., description="Unique subscription identifier")
    event_types: List[EventType] = Field(..., description="Event types to subscribe to")
    risk_levels: List[RiskLevel] = Field(default=[], description="Risk levels to filter by")
    webhook_url: Optional[str] = Field(default=None, description="Webhook URL for notifications")
    active: bool = Field(default=True, description="Subscription status")


class BulkInvestigationRequest(BaseModel):
    """Request model for bulk investigation submission"""
    events: List[Dict[str, Any]] = Field(..., min_items=1, max_items=100, description="List of events to investigate")
    emergency_mode: bool = Field(default=False, description="Process all events in emergency mode")
    batch_id: Optional[str] = Field(default=None, description="Optional batch identifier")
    
    @validator('events')
    def validate_events(cls, v):
        """Validate that each event has required fields"""
        for event in v:
            if not isinstance(event, dict) or 'event_type' not in event:
                raise ValueError("Each event must be a dictionary with 'event_type' field")
        return v


class BulkInvestigationResponse(BaseModel):
    """Response model for bulk investigation submission"""
    batch_id: str = Field(..., description="Batch identifier")
    total_events: int = Field(..., description="Total number of events submitted")
    investigation_ids: List[str] = Field(..., description="List of investigation IDs created")
    estimated_completion_time: datetime = Field(..., description="Estimated completion time for all")
    status: str = Field(..., description="Batch processing status")


class SearchRequest(BaseModel):
    """Request model for searching investigations"""
    query: Optional[str] = Field(default=None, description="Free text search query")
    event_types: Optional[List[EventType]] = Field(default=None, description="Filter by event types")
    risk_levels: Optional[List[RiskLevel]] = Field(default=None, description="Filter by risk levels")
    date_from: Optional[datetime] = Field(default=None, description="Start date for search")
    date_to: Optional[datetime] = Field(default=None, description="End date for search")
    source_ip: Optional[str] = Field(default=None, description="Filter by source IP")
    limit: int = Field(default=50, le=500, description="Maximum results to return")
    offset: int = Field(default=0, description="Results offset for pagination")


class SearchResponse(BaseModel):
    """Response model for investigation search"""
    total_results: int = Field(..., description="Total number of matching investigations")
    results: List[Dict[str, Any]] = Field(..., description="Search results")
    query_time_ms: float = Field(..., description="Query execution time in milliseconds")
    has_more: bool = Field(..., description="Whether more results are available")


# Error response models
class ErrorResponse(BaseModel):
    """Standard error response model"""
    error: str = Field(..., description="Error message")
    status_code: int = Field(..., description="HTTP status code")
    timestamp: datetime = Field(..., description="Error timestamp")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")


class ValidationErrorResponse(BaseModel):
    """Validation error response model"""
    error: str = Field(..., description="Error message")
    status_code: int = Field(..., description="HTTP status code")
    timestamp: datetime = Field(..., description="Error timestamp")
    validation_errors: List[Dict[str, Any]] = Field(..., description="Detailed validation errors") 

class ReviewStatus(str, Enum):
    """Review status for human oversight"""
    PENDING_REVIEW = "pending_review"
    UNDER_REVIEW = "under_review" 
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_ESCALATION = "needs_escalation"

class ReviewPriority(str, Enum):
    """Priority levels for human review"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class HumanReviewRequest(BaseModel):
    """Request for human analyst review"""
    investigation_id: str
    reason: str
    priority: ReviewPriority
    risk_score: float
    confidence_score: float
    escalation_triggers: List[str]
    auto_escalated: bool = False
    assigned_analyst: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AnalystFeedback(BaseModel):
    """Analyst feedback on investigation"""
    investigation_id: str
    analyst_id: str
    review_status: ReviewStatus
    feedback_text: str
    accuracy_rating: int = Field(ge=1, le=5, description="1-5 rating of AI analysis accuracy")
    false_positive: bool = False
    missed_indicators: List[str] = []
    suggested_actions: List[str] = []
    learning_notes: str = ""
    reviewed_at: datetime = Field(default_factory=datetime.utcnow)

class AuditEntry(BaseModel):
    """Audit trail entry for compliance"""
    investigation_id: str
    event_type: str  # "investigation_started", "review_requested", "feedback_received", etc.
    actor: str  # "system" or analyst ID
    action: str
    details: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None
    session_id: Optional[str] = None

class ReviewQueue(BaseModel):
    """Human review queue item"""
    review_id: str
    investigation_id: str
    priority: ReviewPriority
    status: ReviewStatus
    reason: str
    risk_score: float
    confidence_score: float
    assigned_analyst: Optional[str] = None
    created_at: datetime
    sla_deadline: datetime
    escalation_count: int = 0

class EscalationRule(BaseModel):
    """Rules for automatic escalation to human review"""
    name: str
    description: str
    enabled: bool = True
    conditions: Dict[str, Any]  # risk_threshold, confidence_threshold, event_types, etc.
    priority: ReviewPriority
    notify_channels: List[str] = []  # email, slack, teams, etc. 