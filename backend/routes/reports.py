"""
AITIA SOC Agent - Reports Routes

API routes for generating and retrieving investigation reports.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import APIRouter, HTTPException, Depends, Query, status
from fastapi.responses import FileResponse, Response

from ..models import (
    ReportRequest,
    ReportResponse,
    InvestigationReport,
    ErrorResponse
)
from ..config import get_settings
from ...agent import SOCAgentPlanner


# Create router
router = APIRouter()

logger = logging.getLogger(__name__)


def get_soc_agent() -> SOCAgentPlanner:
    """Dependency to get SOC agent instance"""
    from ..main import soc_agent
    if soc_agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOC Agent not initialized"
        )
    return soc_agent


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    request: ReportRequest,
    agent: SOCAgentPlanner = Depends(get_soc_agent)
):
    """
    Generate a report for a completed investigation
    
    Creates a formatted report (JSON, Markdown, or HTML) from
    investigation results with optional raw data inclusion.
    """
    try:
        # Check if investigation exists and is completed
        from ..routes.investigations import active_investigations, investigation_history
        
        investigation = None
        if request.investigation_id in active_investigations:
            investigation = active_investigations[request.investigation_id]
        else:
            # Check historical investigations
            investigation = next(
                (inv for inv in investigation_history if inv['id'] == request.investigation_id),
                None
            )
        
        if not investigation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {request.investigation_id} not found"
            )
        
        if investigation.get('status') != 'completed':
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Investigation not completed. Status: {investigation.get('status')}"
            )
        
        # Get investigation result
        result = investigation.get('result', {})
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Investigation result not found"
            )
        
        # Generate report using the reporter
        settings = get_settings()
        
        # Create a mock context object for the reporter
        class MockContext:
            def __init__(self, investigation_data):
                self.event_id = investigation_data['id']
                self.event_data = investigation_data.get('request', {}).get('event_data', {})
                self.risk_assessment = result.get('risk_assessment', {})
                self.intelligence_data = result.get('intelligence_data', {})
                self.recommended_actions = result.get('recommended_actions', [])
                self.reasoning_log = result.get('reasoning_log', [])
                self.start_time = investigation_data.get('created_at', datetime.utcnow())
        
        mock_context = MockContext(investigation)
        
        # Generate report
        report_data = await agent.reporter.generate_report(mock_context)
        
        # Generate report ID
        report_id = f"rpt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{request.investigation_id}"
        
        # Get content based on format
        content = None
        file_path = None
        
        if request.format == 'json':
            content = report_data['formats']['json']
        elif request.format == 'markdown':
            content = report_data['formats']['markdown']
        else:  # html - would need to implement HTML generation
            content = report_data['formats']['markdown']  # Fallback to markdown
        
        # Save to file if requested (check settings)
        if settings.get('auto_save_reports', True):
            reports_dir = Path(settings.reports_dir)
            file_name = f"{report_id}.{request.format}"
            file_path = reports_dir / file_name
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            file_path = str(file_path)
        
        logger.info(f"Generated report {report_id} for investigation {request.investigation_id}")
        
        return ReportResponse(
            report_id=report_id,
            investigation_id=request.investigation_id,
            format=request.format,
            generated_at=datetime.utcnow(),
            file_path=file_path,
            content=content if len(content) < 50000 else None  # Don't return huge content inline
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )


@router.get("/{report_id}")
async def get_report(report_id: str):
    """
    Retrieve a previously generated report
    
    Returns the full content of a report by its ID.
    """
    try:
        settings = get_settings()
        reports_dir = Path(settings.reports_dir)
        
        # Look for report files with this ID
        report_files = list(reports_dir.glob(f"{report_id}.*"))
        
        if not report_files:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report {report_id} not found"
            )
        
        # Return the first matching file
        report_file = report_files[0]
        
        with open(report_file, 'r') as f:
            content = f.read()
        
        # Determine content type based on file extension
        file_extension = report_file.suffix.lower()
        if file_extension == '.json':
            media_type = "application/json"
        elif file_extension == '.md':
            media_type = "text/markdown"
        elif file_extension == '.html':
            media_type = "text/html"
        else:
            media_type = "text/plain"
        
        return Response(content=content, media_type=media_type)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve report {report_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve report: {str(e)}"
        )


@router.get("/{report_id}/download")
async def download_report(report_id: str):
    """
    Download a report file
    
    Returns the report as a downloadable file attachment.
    """
    try:
        settings = get_settings()
        reports_dir = Path(settings.reports_dir)
        
        # Look for report files with this ID
        report_files = list(reports_dir.glob(f"{report_id}.*"))
        
        if not report_files:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report {report_id} not found"
            )
        
        # Return the first matching file as download
        report_file = report_files[0]
        
        return FileResponse(
            path=str(report_file),
            filename=report_file.name,
            media_type='application/octet-stream'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download report {report_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download report: {str(e)}"
        )


@router.get("/investigation/{investigation_id}")
async def get_investigation_reports(investigation_id: str):
    """
    Get all reports for a specific investigation
    
    Returns a list of all reports generated for the given investigation.
    """
    try:
        settings = get_settings()
        reports_dir = Path(settings.reports_dir)
        
        # Look for report files for this investigation
        pattern = f"rpt_*_{investigation_id}.*"
        report_files = list(reports_dir.glob(pattern))
        
        reports = []
        for report_file in report_files:
            # Parse report ID from filename
            file_stem = report_file.stem
            report_id = file_stem.split('_')[0] + '_' + file_stem.split('_')[1] + '_' + investigation_id
            
            reports.append({
                'report_id': report_id,
                'investigation_id': investigation_id,
                'format': report_file.suffix[1:],  # Remove the dot
                'file_name': report_file.name,
                'file_size': report_file.stat().st_size,
                'created_at': datetime.fromtimestamp(report_file.stat().st_ctime),
                'modified_at': datetime.fromtimestamp(report_file.stat().st_mtime)
            })
        
        # Sort by creation time (newest first)
        reports.sort(key=lambda x: x['created_at'], reverse=True)
        
        return {
            'investigation_id': investigation_id,
            'total_reports': len(reports),
            'reports': reports
        }
        
    except Exception as e:
        logger.error(f"Failed to get reports for investigation {investigation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get investigation reports: {str(e)}"
        )


@router.get("/")
async def list_reports(
    limit: int = Query(50, le=200, description="Maximum results to return"),
    offset: int = Query(0, description="Results offset"),
    format: Optional[str] = Query(None, description="Filter by format")
):
    """
    List all available reports
    
    Returns a paginated list of all reports with metadata.
    """
    try:
        settings = get_settings()
        reports_dir = Path(settings.reports_dir)
        
        # Get all report files
        all_reports = []
        for report_file in reports_dir.glob("rpt_*.*"):
            file_stem = report_file.stem
            file_format = report_file.suffix[1:]  # Remove the dot
            
            # Skip if format filter is specified and doesn't match
            if format and file_format.lower() != format.lower():
                continue
            
            # Parse investigation ID from filename
            parts = file_stem.split('_')
            if len(parts) >= 3:
                investigation_id = '_'.join(parts[2:])
            else:
                investigation_id = 'unknown'
            
            all_reports.append({
                'report_id': file_stem,
                'investigation_id': investigation_id,
                'format': file_format,
                'file_name': report_file.name,
                'file_size': report_file.stat().st_size,
                'created_at': datetime.fromtimestamp(report_file.stat().st_ctime),
                'modified_at': datetime.fromtimestamp(report_file.stat().st_mtime)
            })
        
        # Sort by creation time (newest first)
        all_reports.sort(key=lambda x: x['created_at'], reverse=True)
        
        # Apply pagination
        total_count = len(all_reports)
        paginated_reports = all_reports[offset:offset + limit]
        
        return {
            'reports': paginated_reports,
            'total_count': total_count,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total_count
        }
        
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list reports: {str(e)}"
        )


@router.delete("/{report_id}")
async def delete_report(report_id: str):
    """
    Delete a report
    
    Removes a report file from the system.
    """
    try:
        settings = get_settings()
        reports_dir = Path(settings.reports_dir)
        
        # Look for report files with this ID
        report_files = list(reports_dir.glob(f"{report_id}.*"))
        
        if not report_files:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report {report_id} not found"
            )
        
        # Delete all matching files
        deleted_files = []
        for report_file in report_files:
            report_file.unlink()
            deleted_files.append(report_file.name)
        
        logger.info(f"Deleted report {report_id}: {deleted_files}")
        
        return {
            'message': f"Report {report_id} deleted successfully",
            'deleted_files': deleted_files
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete report {report_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete report: {str(e)}"
        )


@router.post("/cleanup")
async def cleanup_reports(
    days_old: int = Query(30, ge=1, description="Delete reports older than this many days"),
    dry_run: bool = Query(True, description="If true, only show what would be deleted")
):
    """
    Clean up old reports
    
    Removes reports older than the specified number of days.
    Use dry_run=true to see what would be deleted without actually deleting.
    """
    try:
        settings = get_settings()
        reports_dir = Path(settings.reports_dir)
        
        cutoff_date = datetime.now().timestamp() - (days_old * 24 * 60 * 60)
        
        old_reports = []
        total_size = 0
        
        for report_file in reports_dir.glob("rpt_*.*"):
            if report_file.stat().st_ctime < cutoff_date:
                file_info = {
                    'file_name': report_file.name,
                    'file_size': report_file.stat().st_size,
                    'created_at': datetime.fromtimestamp(report_file.stat().st_ctime)
                }
                old_reports.append(file_info)
                total_size += file_info['file_size']
                
                if not dry_run:
                    report_file.unlink()
        
        message = f"Found {len(old_reports)} reports older than {days_old} days"
        if not dry_run:
            message = f"Deleted {len(old_reports)} reports older than {days_old} days"
            logger.info(f"Cleaned up {len(old_reports)} old reports, freed {total_size} bytes")
        
        return {
            'message': message,
            'dry_run': dry_run,
            'reports_found': len(old_reports),
            'total_size_bytes': total_size,
            'reports': old_reports[:10] if dry_run else []  # Show first 10 in dry run
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup reports: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cleanup reports: {str(e)}"
        ) 