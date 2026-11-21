"""
ThreatSentinel SOC Agent - Reports Routes

Generate (json, markdown, html, stix) and retrieve investigation reports.
Every filesystem access validates the ID and confirms the resolved path stays
inside the reports directory.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, Response

from agent import IncidentReporter
from agent.planner import InvestigationContext

from ..config import get_settings
from ..deps import get_current_user, get_store
from ..models import ReportRequest, ReportResponse

router = APIRouter(dependencies=[Depends(get_current_user)])
logger = logging.getLogger(__name__)

SAFE_ID_PATTERN = re.compile(r"[\w\-]{1,160}")
REPORT_GLOBS = ("rpt_*.*", "evt_*.*")
FORMAT_EXTENSIONS = {"json": "json", "markdown": "md", "html": "html", "stix": "stix"}
MEDIA_TYPES = {
    ".json": "application/json",
    ".md": "text/markdown; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".stix": "application/stix+json;version=2.1",
}
HTML_REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'"
_LEGACY_SUFFIX = re.compile(r"_\d{8}_\d{6}$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _validate_id(value: str, what: str) -> str:
    """Reject IDs with glob metacharacters, dots or path separators before any filesystem use"""
    if not isinstance(value, str) or not SAFE_ID_PATTERN.fullmatch(value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid {what}")
    return value


def _reports_dir() -> Path:
    path = Path(get_settings().reports_dir).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _contained(path: Path, base: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(base):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report path")
    return resolved


def _investigation_id_from_stem(stem: str) -> str:
    if stem.startswith("rpt_"):
        parts = stem.split("_")
        return "_".join(parts[3:]) if len(parts) > 3 else "unknown"
    return _LEGACY_SUFFIX.sub("", stem)


def _file_info(path: Path) -> Dict[str, Any]:
    stat = path.stat()
    return {
        "report_id": path.stem,
        "investigation_id": _investigation_id_from_stem(path.stem),
        "format": path.suffix[1:],
        "file_name": path.name,
        "file_size": stat.st_size,
        "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc),
        "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
    }


def _all_report_files(base: Path) -> List[Path]:
    seen = {}
    for pattern in REPORT_GLOBS:
        for path in base.glob(pattern):
            if path.is_file() and path.suffix in MEDIA_TYPES:
                seen[path.name] = _contained(path, base)
    return list(seen.values())


def _find_report_files(report_id: str) -> List[Path]:
    _validate_id(report_id, "report ID")
    base = _reports_dir()
    files = [_contained(p, base) for p in base.glob(f"{report_id}.*") if p.is_file() and p.suffix in MEDIA_TYPES]
    if not files:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report {report_id} not found")
    return sorted(files, key=lambda p: list(MEDIA_TYPES).index(p.suffix))


def _context_from_record(record: Dict[str, Any]) -> InvestigationContext:
    result = dict(record.get("result") or {})
    result.setdefault("event_id", record["id"])
    result.setdefault("investigation_id", record["id"])
    result.setdefault("event_data", (record.get("request") or {}).get("event_data", {}))
    result.setdefault("start_time", record.get("created_at") or _utcnow())
    result["status"] = record.get("status", "completed")
    return InvestigationContext.from_dict(result)


@router.post("/generate", response_model=ReportResponse)
async def generate_report(request: ReportRequest):
    """Render a report for a completed (or pending-review) investigation."""
    investigation_id = _validate_id(request.investigation_id, "investigation ID")
    record = get_store().get(investigation_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation {investigation_id} not found")
    if record["status"] not in ("completed", "pending_human_review"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Investigation not completed. Status: {record['status']}")
    if not record.get("result"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation result not found")

    settings = get_settings()
    reporter = IncidentReporter({"reports_dir": settings.reports_dir, "auto_save": False,
                                 "include_raw_data": request.include_raw_data})
    report = await reporter.generate_report(_context_from_record(record))
    formats = report.get("formats") or {}
    if request.format not in formats:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Report rendering failed")
    content = formats[request.format]

    report_id = f"rpt_{_utcnow().strftime('%Y%m%d_%H%M%S')}_{investigation_id}"
    file_path = None
    if settings.auto_save_reports:
        base = _reports_dir()
        target = _contained(base / f"{report_id}.{FORMAT_EXTENSIONS[request.format]}", base)
        target.write_text(content, encoding="utf-8")
        file_path = target.name
    return ReportResponse(
        report_id=report_id,
        investigation_id=investigation_id,
        format=request.format,
        generated_at=_utcnow(),
        file_path=file_path,
        content=content if len(content) < 500_000 else None,
    )


@router.get("/investigation/{investigation_id}")
async def get_investigation_reports(investigation_id: str):
    _validate_id(investigation_id, "investigation ID")
    try:
        base = _reports_dir()
        files = {}
        for pattern in (f"rpt_*_{investigation_id}.*", f"{investigation_id}_*.*"):
            for path in base.glob(pattern):
                if path.is_file() and path.suffix in MEDIA_TYPES \
                        and _investigation_id_from_stem(path.stem) == investigation_id:
                    files[path.name] = _contained(path, base)
        reports = sorted((_file_info(p) for p in files.values()), key=lambda r: r["created_at"], reverse=True)
        return {"investigation_id": investigation_id, "total_reports": len(reports), "reports": reports}
    except HTTPException:
        raise
    except Exception:
        logger.exception(f"Failed to list reports for {investigation_id}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to get investigation reports") from None


@router.get("/")
async def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    format: Optional[str] = Query(None, pattern="^(json|md|html|stix)$"),
):
    reports = [_file_info(p) for p in _all_report_files(_reports_dir())]
    if format:
        reports = [r for r in reports if r["format"] == format]
    reports.sort(key=lambda r: r["created_at"], reverse=True)
    total = len(reports)
    return {"reports": reports[offset:offset + limit], "total_count": total, "limit": limit,
            "offset": offset, "has_more": offset + limit < total}


@router.post("/cleanup")
async def cleanup_reports(days_old: int = Query(30, ge=1), dry_run: bool = Query(True)):
    cutoff = _utcnow().timestamp() - days_old * 86400
    old = []
    total_size = 0
    for path in _all_report_files(_reports_dir()):
        stat = path.stat()
        if stat.st_mtime < cutoff:
            old.append({"file_name": path.name, "file_size": stat.st_size,
                        "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)})
            total_size += stat.st_size
            if not dry_run:
                path.unlink()
    verb = "Found" if dry_run else "Deleted"
    return {"message": f"{verb} {len(old)} reports older than {days_old} days", "dry_run": dry_run,
            "reports_found": len(old), "total_size_bytes": total_size, "reports": old[:10] if dry_run else []}


@router.get("/{report_id}")
async def get_report(report_id: str, format: Optional[str] = Query(None, pattern="^(json|md|html|stix)$")):
    files = _find_report_files(report_id)
    if format:
        files = [p for p in files if p.suffix == f".{format}"]
        if not files:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report {report_id} has no {format}")
    report_file = files[0]
    content = report_file.read_text(encoding="utf-8")
    headers = {"Content-Security-Policy": HTML_REPORT_CSP} if report_file.suffix == ".html" else None
    if report_file.suffix in (".json", ".stix"):
        try:
            json.loads(content)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Corrupt report file") from None
    return Response(content=content, media_type=MEDIA_TYPES[report_file.suffix], headers=headers)


@router.get("/{report_id}/download")
async def download_report(report_id: str, format: Optional[str] = Query(None, pattern="^(json|md|html|stix)$")):
    files = _find_report_files(report_id)
    if format:
        files = [p for p in files if p.suffix == f".{format}"] or files
    report_file = files[0]
    return FileResponse(path=str(report_file), filename=report_file.name, media_type="application/octet-stream")


@router.delete("/{report_id}")
async def delete_report(report_id: str):
    files = _find_report_files(report_id)
    deleted = []
    for path in files:
        path.unlink()
        deleted.append(path.name)
    logger.info(f"Deleted report {report_id}: {deleted}")
    return {"message": f"Report {report_id} deleted successfully", "deleted_files": deleted}
