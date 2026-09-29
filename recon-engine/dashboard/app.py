"""
dashboard/app.py — FastAPI application with dashboard routes.

Serves the visual asset browser on http://127.0.0.1:8080.
Access via SSH tunnel: ssh -L 8080:127.0.0.1:8080 user@your-vps
"""

import asyncio
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from core.config import settings
from core.database import DiffEvent, Domain, Endpoint, HttpService, Program, SessionLocal, get_db

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent

app = FastAPI(title="ReconEngine Dashboard", docs_url=None, redoc_url=None)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

security = HTTPBasic()

# Custom Jinja2 filters
def from_json(value):
    try:
        result = json.loads(value or "[]")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result
        return []
    except Exception:
        return []

def json_items(value):
    """Return key-value pairs from a JSON string or dict for use in templates."""
    try:
        if isinstance(value, str):
            d = json.loads(value or "{}")
        elif isinstance(value, dict):
            d = value
        else:
            return []
        return list(d.items())
    except Exception:
        return []

def format_dt(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    return value or "—"

templates.env.filters["from_json"]   = from_json
templates.env.filters["json_items"]  = json_items
templates.env.filters["format_dt"]   = format_dt


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def require_auth(request: Request, credentials: Optional[HTTPBasicCredentials] = Depends(HTTPBasic(auto_error=False))):
    """Skip auth entirely when disabled — no browser popup, no WWW-Authenticate header."""
    if not settings.dashboard.auth.enabled:
        return None
    # Auth is enabled — validate credentials
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    correct_user = secrets.compare_digest(
        credentials.username.encode(), settings.dashboard.auth.username.encode()
    )
    correct_pass = secrets.compare_digest(
        credentials.password.encode(), settings.dashboard.auth.password.encode()
    )
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db), _=Depends(require_auth)):
    total_programs  = db.query(func.count(Program.id)).scalar()
    total_domains   = db.query(func.count(Domain.id)).scalar()
    active_domains  = db.query(func.count(Domain.id)).filter(Domain.is_active == True).scalar()
    total_endpoints = db.query(func.count(Endpoint.id)).scalar()
    total_diffs     = db.query(func.count(DiffEvent.id)).scalar()
    unread_diffs    = db.query(func.count(DiffEvent.id)).filter(DiffEvent.notified == False).scalar()

    # Severity breakdown for recent diffs
    critical_count = db.query(func.count(DiffEvent.id)).filter(DiffEvent.severity == "critical").scalar()
    high_count     = db.query(func.count(DiffEvent.id)).filter(DiffEvent.severity == "high").scalar()
    medium_count   = db.query(func.count(DiffEvent.id)).filter(DiffEvent.severity == "medium").scalar()
    low_count      = db.query(func.count(DiffEvent.id)).filter(DiffEvent.severity == "low").scalar()

    # Recent 5 diff events
    recent_diffs   = db.query(DiffEvent).order_by(DiffEvent.created_at.desc()).limit(5).all()
    programs       = db.query(Program).all()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "total_programs": total_programs,
            "total_domains":  total_domains,
            "active_domains": active_domains,
            "total_endpoints":total_endpoints,
            "total_diffs":    total_diffs,
            "unread_diffs":   unread_diffs,
            "critical_count": critical_count,
            "high_count":     high_count,
            "medium_count":   medium_count,
            "low_count":      low_count,
            "recent_diffs":   recent_diffs,
            "programs":       programs,
        }
    )


@app.get("/domains", response_class=HTMLResponse)
async def domains(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_auth),
    program_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
):
    PAGE_SIZE = 50
    query = db.query(Domain).join(HttpService, isouter=True)

    if program_id:
        query = query.filter(Domain.program_id == program_id)
    if status == "active":
        query = query.filter(Domain.is_active == True)
    elif status == "inactive":
        query = query.filter(Domain.is_active == False)
    if search:
        query = query.filter(Domain.subdomain.contains(search))

    total   = query.count()
    domains = query.order_by(Domain.last_seen.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE).all()
    programs = db.query(Program).all()

    return templates.TemplateResponse(
        request=request,
        name="domains.html",
        context={
            "domains":    domains,
            "programs":   programs,
            "total":      total,
            "page":       page,
            "page_size":  PAGE_SIZE,
            "pages":      max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
            "program_id": program_id,
            "status":     status,
            "search":     search or "",
        }
    )


@app.get("/endpoints", response_class=HTMLResponse)
async def endpoints(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_auth),
    search: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
):
    PAGE_SIZE = 100
    query = db.query(Endpoint)

    if search:
        query = query.filter(Endpoint.endpoint_url.contains(search))
    if source:
        query = query.filter(Endpoint.source == source)

    total     = query.count()
    endpoints = query.order_by(Endpoint.first_seen.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE).all()

    return templates.TemplateResponse(
        request=request,
        name="endpoints.html",
        context={
            "endpoints": endpoints,
            "total":     total,
            "page":      page,
            "page_size": PAGE_SIZE,
            "pages":     max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
            "search":    search or "",
            "source":    source or "",
        }
    )


@app.get("/diffs", response_class=HTMLResponse)
async def diffs(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_auth),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
):
    PAGE_SIZE = 50
    query = db.query(DiffEvent)

    if severity:
        query = query.filter(DiffEvent.severity == severity)
    if event_type:
        query = query.filter(DiffEvent.event_type == event_type)

    total      = query.count()
    diff_events = query.order_by(DiffEvent.created_at.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE).all()

    event_types = [r[0] for r in db.query(DiffEvent.event_type).distinct().all()]

    return templates.TemplateResponse(
        request=request,
        name="diffs.html",
        context={
            "diff_events": diff_events,
            "event_types": event_types,
            "total":       total,
            "page":        page,
            "page_size":   PAGE_SIZE,
            "pages":       max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
            "severity":    severity or "",
            "event_type":  event_type or "",
        }
    )


# ---------------------------------------------------------------------------
# API endpoints (used by HTMX partial refreshes)
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def api_stats(db: Session = Depends(get_db), _=Depends(require_auth)):
    return {
        "total_domains":   db.query(func.count(Domain.id)).scalar(),
        "active_domains":  db.query(func.count(Domain.id)).filter(Domain.is_active == True).scalar(),
        "total_endpoints": db.query(func.count(Endpoint.id)).scalar(),
        "unread_diffs":    db.query(func.count(DiffEvent.id)).filter(DiffEvent.notified == False).scalar(),
    }


@app.post("/api/scan/{program_id}")
async def trigger_scan(program_id: int, db: Session = Depends(get_db), _=Depends(require_auth)):
    """Manually trigger a scan for a specific program from the dashboard."""
    import yaml
    from core.ingester import Ingester
    from core.runner import PipelineRunner
    from core.diff_engine import DiffEngine
    from alerts.notifier import dispatch_pending

    prog = db.query(Program).filter_by(id=program_id).first()
    if not prog:
        raise HTTPException(status_code=404, detail="Program not found")

    _targets_path = Path(__file__).parent.parent / "config" / "targets.yaml"
    with open(_targets_path) as f:
        targets = yaml.safe_load(f)

    prog_config = next(
        (p for p in targets.get("programs", []) if p["name"] == prog.name), None
    )
    if not prog_config:
        raise HTTPException(status_code=404, detail="Program not found in targets.yaml")

    domains = prog_config.get("domains", [])
    ingester = Ingester(prog.name)
    runner = PipelineRunner(prog.name, domains, ingester)

    asyncio.create_task(run_scan_and_notify(runner, prog.id))
    return {"status": "Scan started", "program": prog.name}


async def run_scan_and_notify(runner, program_id: int):
    from core.diff_engine import DiffEngine
    from alerts.notifier import dispatch_pending
    await runner.run()
    DiffEngine(program_id).run()
    await dispatch_pending()
