import hashlib
import logging
import secrets
import smtplib
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from email.message import EmailMessage
from pathlib import PurePosixPath
from uuid import UUID

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response as RawResponse
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.ai.explanations import explain
from app.api.deps import authenticated_user
from app.api.features import router as security_center_router
from app.core.config import settings
from app.core.database import get_db
from app.intelligence.kev import load_kev
from app.models.entities import AuditLog, Component, Finding, PasswordResetToken, Project, ProjectMember, Scan, ScanJob, SessionRecord, User, Vulnerability, utcnow
from app.parsers import parse_upload
from app.parsers.dependencies import ManifestError
from app.reports.pdf import scan_pdf
from app.scan_jobs import enqueue_scan_job
from app.schemas.api import AccountDelete, AuditorGrant, LoginIn, PasswordChange, PasswordReset, PasswordResetRequest, ProjectIn, ProjectPatch, RegisterIn, RoleUpdate, StatusUpdate
from app.security.auth import CSRF_COOKIE, SESSION_COOKIE, clear_session_cookies, create_session, digest, hash_password, password_hash, require_csrf, require_role, verify_password
from app.services.audit import audit
from app.services.projects import get_project, project_accessible_query

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("depshield.api")
app = FastAPI(title="DepShield API", version="1.0.0", description="Defensive software dependency and vulnerability intelligence API")
app.include_router(security_center_router)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"], allow_headers=["Content-Type", "X-CSRF-Token"])

_limits: dict[str, deque[float]] = defaultdict(deque)
_limits_lock = threading.Lock()


def rate_limit(request: Request, action: str, count: int, seconds: int = 900):
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    key = f"{action}:{ip}"
    with _limits_lock:
        entries = _limits[key]
        while entries and entries[0] <= now - seconds:
            entries.popleft()
        if len(entries) >= count:
            raise HTTPException(status_code=429, detail="Too many requests. Try again later.", headers={"Retry-After": str(seconds)})
        entries.append(now)


def user_dict(user: User):
    return {"id": str(user.id), "email": user.email, "display_name": user.display_name, "role": user.role, "created_at": user.created_at.isoformat()}


def project_dict(db: Session, project: Project):
    latest = db.scalar(select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc()).limit(1))
    return {
        "id": str(project.id), "name": project.name, "description": project.description, "ecosystem": project.ecosystem,
        "owner_id": str(project.owner_id), "archived": project.archived, "created_at": project.created_at.isoformat(),
        "updated_at": project.updated_at.isoformat(), "latest_scan": scan_dict(latest) if latest else None,
    }


def scan_dict(scan: Scan):
    return {
        "id": str(scan.id), "project_id": str(scan.project_id), "status": scan.status, "stage": scan.stage,
        "source_filename": scan.source_filename, "source_bytes": scan.source_bytes,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "created_at": scan.created_at.isoformat(), "intelligence_status": scan.intelligence_status or {}, "error_message": scan.error_message,
    }


def component_dict(component: Component):
    return {"id": str(component.id), "name": component.name, "version": component.version, "version_constraint": component.version_constraint,
            "ecosystem": component.ecosystem, "purl": component.purl, "directness": component.directness,
            "resolution": component.resolution, "manifest": component.manifest, "license": component.license,
            "dependencies": component.dependencies or []}


def finding_dict(finding: Finding):
    vuln = finding.vulnerability
    comp = finding.component
    return {
        "id": str(finding.id), "scan_id": str(finding.scan_id), "component": component_dict(comp),
        "vulnerability": {"id": str(vuln.id), "osv_id": vuln.osv_id, "aliases": vuln.aliases or [], "summary": vuln.summary,
                          "details": vuln.details, "published": vuln.published, "modified": vuln.modified, "references": vuln.references or [],
                          "nvd_description": vuln.nvd_description, "cwes": vuln.cwes or [], "nvd_published": vuln.nvd_published, "nvd_modified": vuln.nvd_modified},
        "cvss": finding.cvss, "official_severity": finding.official_severity, "kev_status": finding.kev_status,
        "fixed_versions": finding.fixed_versions or [], "affected_ranges": finding.affected_ranges or [], "risk_score": finding.risk_score, "priority": finding.priority,
        "risk_factors": finding.risk_factors or {},
    }


def get_scan(db: Session, user: User, scan_id: UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    get_project(db, user, scan.project_id)
    return scan


def project_scan_ids(db: Session, user: User):
    accessible = project_accessible_query(db, user).with_only_columns(Project.id)
    return select(Scan.id).where(Scan.project_id.in_(accessible))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > settings.max_upload_bytes + 1024 * 1024:
        return JSONResponse(status_code=413, content={"detail": "Request body exceeds the configured size limit"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    logger.error("Unhandled application error (%s)", type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "An internal error occurred"})


@app.get("/health/live", tags=["health"])
def health_live():
    return {"status": "alive", "service": "api"}


@app.get("/health/ready", tags=["health"])
def health_ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "available"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")


@app.get("/api/v1/auth/csrf", tags=["authentication"])
def csrf_token(response: Response, request: Request):
    existing = request.cookies.get(CSRF_COOKIE)
    token = existing if existing and len(existing) <= 200 else secrets.token_urlsafe(32)
    response.set_cookie(CSRF_COOKIE, token, max_age=settings.session_ttl_hours * 3600, httponly=False, secure=settings.cookie_secure, samesite="strict", path="/api/v1")
    return {"csrf_token": token}


@app.post("/api/v1/auth/register", status_code=202, tags=["authentication"], dependencies=[Depends(require_csrf)])
def register(payload: RegisterIn, request: Request, db: Session = Depends(get_db)):
    rate_limit(request, "register", 5)
    if not payload.accept_terms:
        raise HTTPException(status_code=422, detail="Terms and Privacy acknowledgement is required")
    email = payload.email.lower().strip()
    if db.scalar(select(User.id).where(User.email == email)) is None:
        user = User(email=email, display_name=payload.display_name, password_hash=hash_password(payload.password), role="developer")
        db.add(user)
        db.flush()
        audit(db, user.id, "account.registered", "user", user.id, metadata={"terms_acknowledged": True})
        db.commit()
    # Same response for an existing account to avoid disclosing account existence.
    return {"message": "If registration is available, you can sign in with the account details."}


@app.post("/api/v1/auth/login", tags=["authentication"], dependencies=[Depends(require_csrf)])
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    rate_limit(request, "login", 10)
    user = db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    valid = verify_password(payload.password, user.password_hash) if user else verify_password(payload.password, password_hash.hash("not-a-real-user-password"))
    if not user or not valid or not user.is_active:
        audit(db, user.id if user else None, "auth.login", "user", user.id if user else None, outcome="failure")
        db.commit()
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    csrf = create_session(db, user, response)
    audit(db, user.id, "auth.login", "user", user.id)
    db.commit()
    return {"user": user_dict(user), "csrf_token": csrf}


@app.post("/api/v1/auth/logout", tags=["authentication"], dependencies=[Depends(require_csrf)])
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        record = db.scalar(select(SessionRecord).where(SessionRecord.token_hash == digest(raw), SessionRecord.revoked_at.is_(None)))
        if record:
            record.revoked_at = utcnow()
            audit(db, record.user_id, "auth.logout", "session", record.id)
            db.commit()
    clear_session_cookies(response)
    return {"message": "Signed out"}


@app.get("/api/v1/auth/me", tags=["authentication"])
def me(user: User = Depends(authenticated_user)):
    return {"user": user_dict(user)}


@app.post("/api/v1/auth/password", tags=["authentication"], dependencies=[Depends(require_csrf)])
def change_password(payload: PasswordChange, response: Response, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    db.query(SessionRecord).filter(SessionRecord.user_id == user.id, SessionRecord.revoked_at.is_(None)).update({"revoked_at": utcnow()})
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)).update({"used_at": utcnow()})
    audit(db, user.id, "auth.password_changed", "user", user.id)
    db.commit()
    clear_session_cookies(response)
    return {"message": "Password changed. Sign in again."}


@app.post("/api/v1/auth/sessions/revoke-others", tags=["authentication"], dependencies=[Depends(require_csrf)])
def revoke_other_sessions(request: Request, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    current = request.cookies.get(SESSION_COOKIE)
    rows = db.scalars(select(SessionRecord).where(SessionRecord.user_id == user.id, SessionRecord.revoked_at.is_(None))).all()
    count = 0
    for row in rows:
        if not current or row.token_hash != digest(current):
            row.revoked_at = utcnow()
            count += 1
    audit(db, user.id, "auth.sessions_revoked", "user", user.id, metadata={"count": count})
    db.commit()
    return {"revoked": count}


def _send_reset_email(to_email: str, raw_token: str):
    if not settings.smtp_host:
        return
    msg = EmailMessage()
    msg["Subject"] = "DepShield password reset"
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg.set_content(f"Use this one-time link within {settings.reset_token_ttl_minutes} minutes: {settings.frontend_url.rstrip('/')}/reset-password?token={raw_token}\nIf you did not request this, ignore this message.")
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=5) as smtp:
            if settings.smtp_username and settings.smtp_password:
                smtp.starttls()
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning("password reset email delivery failed (%s)", type(exc).__name__)


@app.post("/api/v1/auth/password-reset", status_code=202, tags=["authentication"], dependencies=[Depends(require_csrf)])
def request_password_reset(payload: PasswordResetRequest, request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    rate_limit(request, "password-reset", 5)
    user = db.scalar(select(User).where(User.email == payload.email.lower().strip(), User.is_active.is_(True)))
    if user and settings.smtp_host:
        raw = secrets.token_urlsafe(40)
        db.add(PasswordResetToken(user_id=user.id, token_hash=digest(raw), expires_at=utcnow() + timedelta(minutes=settings.reset_token_ttl_minutes)))
        audit(db, user.id, "auth.password_reset_requested", "user", user.id)
        db.commit()
        background.add_task(_send_reset_email, user.email, raw)
    return {"message": "If an active account matches that address, password reset instructions will be sent."}


@app.post("/api/v1/auth/password-reset/complete", tags=["authentication"], dependencies=[Depends(require_csrf)])
def complete_password_reset(payload: PasswordReset, request: Request, response: Response, db: Session = Depends(get_db)):
    rate_limit(request, "password-reset-complete", 10)
    token = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == digest(payload.token), PasswordResetToken.used_at.is_(None), PasswordResetToken.expires_at > utcnow()))
    if not token:
        raise HTTPException(status_code=400, detail="Reset link is invalid or expired")
    user = db.get(User, token.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Reset link is invalid or expired")
    user.password_hash = hash_password(payload.new_password)
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)).update({"used_at": utcnow()})
    db.query(SessionRecord).filter(SessionRecord.user_id == user.id, SessionRecord.revoked_at.is_(None)).update({"revoked_at": utcnow()})
    audit(db, user.id, "auth.password_reset_completed", "user", user.id)
    db.commit()
    clear_session_cookies(response)
    return {"message": "Password updated. Sign in with the new password."}


@app.delete("/api/v1/auth/account", tags=["authentication"], dependencies=[Depends(require_csrf)])
def delete_account(payload: AccountDelete, response: Response, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    if not payload.confirm or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Recent password verification and confirmation are required")
    user_id = user.id
    audit(db, user_id, "account.deleted", "user", user_id)
    db.delete(user)
    db.commit()
    clear_session_cookies(response)
    return {"message": "Account and owned project data have been deleted"}


@app.get("/api/v1/projects", tags=["projects"])
def list_projects(user: User = Depends(authenticated_user), db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    rows = db.scalars(project_accessible_query(db, user).order_by(Project.updated_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [project_dict(db, p) for p in rows], "limit": limit, "offset": offset}


@app.post("/api/v1/projects", status_code=201, tags=["projects"], dependencies=[Depends(require_csrf)])
def create_project(payload: ProjectIn, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    require_role(user, "developer", "administrator")
    project = Project(owner_id=user.id, name=payload.name, description=payload.description.strip(), ecosystem=payload.ecosystem)
    db.add(project)
    db.flush()
    audit(db, user.id, "project.created", "project", project.id)
    db.commit()
    db.refresh(project)
    return project_dict(db, project)


@app.get("/api/v1/projects/{project_id}", tags=["projects"])
def project_details(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    return project_dict(db, get_project(db, user, project_id))


@app.patch("/api/v1/projects/{project_id}", tags=["projects"], dependencies=[Depends(require_csrf)])
def update_project(project_id: UUID, payload: ProjectPatch, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = get_project(db, user, project_id, write=True)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in changes.items():
        if isinstance(value, str):
            value = value.strip()
        setattr(project, key, value)
    audit(db, user.id, "project.updated", "project", project.id, metadata={"fields": sorted(changes)})
    db.commit()
    db.refresh(project)
    return project_dict(db, project)


@app.delete("/api/v1/projects/{project_id}", tags=["projects"], dependencies=[Depends(require_csrf)])
def delete_project(project_id: UUID, confirm_name: str = Query(...), user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = get_project(db, user, project_id, write=True)
    if confirm_name != project.name:
        raise HTTPException(status_code=400, detail="Project name confirmation did not match")
    audit(db, user.id, "project.deleted", "project", project.id)
    db.delete(project)
    db.commit()
    return {"message": "Project and associated scan data deleted"}


@app.get("/api/v1/projects/{project_id}/members", tags=["projects"])
def list_members(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = get_project(db, user, project_id)
    if user.role != "administrator" and project.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Project owner permission required")
    members = db.execute(select(ProjectMember, User).join(User, User.id == ProjectMember.user_id).where(ProjectMember.project_id == project.id)).all()
    return {"items": [{"id": str(m.id), "user_id": str(u.id), "email": u.email, "display_name": u.display_name, "access": m.access} for m, u in members]}


@app.post("/api/v1/projects/{project_id}/members", status_code=201, tags=["projects"], dependencies=[Depends(require_csrf)])
def add_member(project_id: UUID, payload: AuditorGrant, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = get_project(db, user, project_id, write=True)
    member = db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if not member or member.id == project.owner_id:
        raise HTTPException(status_code=404, detail="Eligible user not found")
    existing = db.scalar(select(ProjectMember).where(ProjectMember.project_id == project.id, ProjectMember.user_id == member.id))
    if not existing:
        db.add(ProjectMember(project_id=project.id, user_id=member.id, access="auditor"))
        audit(db, user.id, "project.auditor_added", "project", project.id, metadata={"member_id": str(member.id)})
        db.commit()
    return {"user_id": str(member.id), "email": member.email, "access": "auditor"}


@app.delete("/api/v1/projects/{project_id}/members/{member_id}", tags=["projects"], dependencies=[Depends(require_csrf)])
def remove_member(project_id: UUID, member_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = get_project(db, user, project_id, write=True)
    membership = db.scalar(select(ProjectMember).where(ProjectMember.project_id == project.id, ProjectMember.user_id == member_id))
    if membership:
        db.delete(membership)
        audit(db, user.id, "project.auditor_removed", "project", project.id, metadata={"member_id": str(member_id)})
        db.commit()
    return {"message": "Project access revoked"}


@app.post("/api/v1/projects/{project_id}/scans", status_code=202, tags=["scans"], dependencies=[Depends(require_csrf)])
async def create_scan(project_id: UUID, file: UploadFile = File(...), user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    require_role(user, "developer", "administrator")
    project = get_project(db, user, project_id, write=True)
    if project.archived:
        raise HTTPException(status_code=409, detail="Archived projects cannot start scans")
    raw = await file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"Upload exceeds {settings.max_upload_bytes} byte limit")
    filename = (file.filename or "upload").replace("\\", "/")
    filename = PurePosixPath(filename).name
    filename = "".join(ch for ch in filename if ch.isprintable() and ch not in "<>:\"|?*")[:255] or "upload"
    try:
        extracted = await run_in_threadpool(parse_upload, filename, raw, settings.max_archive_entries, settings.max_extracted_bytes)
    except ManifestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = Scan(project_id=project.id, requested_by=user.id, status="queued", stage="Queued", source_filename=filename,
                source_sha256=hashlib.sha256(raw).hexdigest(), source_bytes=len(raw))
    db.add(scan)
    db.flush()
    for row in extracted:
        allowed = {k: row.get(k) for k in ("name", "version", "version_constraint", "ecosystem", "purl", "directness", "resolution", "manifest", "license", "dependencies")}
        db.add(Component(scan_id=scan.id, **allowed))
    enqueue_scan_job(db, scan)
    audit(db, user.id, "scan.queued", "scan", scan.id, metadata={"component_count": len(extracted), "upload_bytes": len(raw)})
    db.commit()
    db.refresh(scan)
    return {**scan_dict(scan), "component_count": len(extracted), "message": "Scan queued. A running worker will process this job."}


@app.get("/api/v1/projects/{project_id}/scans", tags=["scans"])
def list_scans(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    project = get_project(db, user, project_id)
    rows = db.scalars(select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [scan_dict(s) for s in rows], "limit": limit, "offset": offset}


@app.get("/api/v1/scans/{scan_id}", tags=["scans"])
def scan_details(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = get_scan(db, user, scan_id)
    counts = db.execute(select(Finding.priority, func.count(Finding.id)).where(Finding.scan_id == scan.id).group_by(Finding.priority)).all()
    return {**scan_dict(scan), "component_count": db.scalar(select(func.count(Component.id)).where(Component.scan_id == scan.id)),
            "finding_count": db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id)), "priority_counts": dict(counts)}


@app.post("/api/v1/scans/{scan_id}/cancel", tags=["scans"], dependencies=[Depends(require_csrf)])
def cancel_scan(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = get_scan(db, user, scan_id)
    project = db.get(Project, scan.project_id)
    if user.role != "administrator" and project.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Project owner permission required")

    # Lock the job before the scan, matching worker claim/finalization order.
    job = db.scalar(
        select(ScanJob).where(ScanJob.scan_id == scan.id).with_for_update()
        .execution_options(populate_existing=True)
    )
    scan = db.scalar(
        select(Scan).where(Scan.id == scan.id).with_for_update()
        .execution_options(populate_existing=True)
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"queued", "processing"}:
        enqueue_scan_job(db, scan)
        db.commit()
        raise HTTPException(status_code=409, detail="Only queued or processing scans can be cancelled")
    if job and job.status not in {"queued", "processing"}:
        enqueue_scan_job(db, scan)
        db.commit()
        raise HTTPException(status_code=409, detail="Scan has already finished")

    scan.status = "cancelled"
    scan.stage = "Cancelled"
    scan.completed_at = scan.completed_at or utcnow()
    if job:
        job.status = "cancelled"
        job.locked_at = None
    else:
        # Legacy scans without a job still receive one terminal queue record.
        enqueue_scan_job(db, scan)
    audit(db, user.id, "scan.cancelled", "scan", scan.id)
    db.commit()
    return scan_dict(scan)


@app.get("/api/v1/scans/{scan_id}/components", tags=["scans"])
def scan_components(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db), q: str = "", ecosystem: str | None = None, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)):
    scan = get_scan(db, user, scan_id)
    stmt = select(Component).where(Component.scan_id == scan.id)
    if q:
        stmt = stmt.where(Component.name.ilike(f"%{q[:100]}%"))
    if ecosystem:
        stmt = stmt.where(Component.ecosystem == ecosystem)
    rows = db.scalars(stmt.order_by(Component.ecosystem, Component.name).offset(offset).limit(limit)).all()
    return {"items": [component_dict(c) for c in rows], "limit": limit, "offset": offset}


@app.get("/api/v1/scans/{scan_id}/findings", tags=["vulnerabilities"])
def scan_findings(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db), priority: str | None = None, severity: str | None = None, kev: str | None = None, q: str = "", limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    scan = get_scan(db, user, scan_id)
    stmt = select(Finding).where(Finding.scan_id == scan.id).join(Finding.component).join(Finding.vulnerability)
    if priority:
        stmt = stmt.where(Finding.priority == priority.title())
    if severity:
        stmt = stmt.where(Finding.official_severity == severity.title())
    if kev:
        stmt = stmt.where(Finding.kev_status == kev.lower())
    if q:
        needle = f"%{q[:100]}%"
        stmt = stmt.where(or_(Component.name.ilike(needle), Vulnerability.osv_id.ilike(needle), Vulnerability.summary.ilike(needle)))
    rows = db.scalars(stmt.order_by(Finding.risk_score.desc().nullslast(), Finding.created_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [finding_dict(f) for f in rows], "limit": limit, "offset": offset}


@app.get("/api/v1/scans/{scan_id}/sbom", tags=["reports"])
def scan_sbom(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = get_scan(db, user, scan_id)
    if not scan.sbom_json:
        raise HTTPException(status_code=409, detail="SBOM is generated when the scan worker processes this job")
    project = db.get(Project, scan.project_id)
    sbom = scan.sbom_json
    audit(db, user.id, "report.sbom_downloaded", "scan", scan.id)
    db.commit()
    safe_name = "".join(c for c in project.name if c.isalnum() or c in "-_")[:60] or "project"
    return JSONResponse(sbom, headers={"Content-Disposition": f'attachment; filename="{safe_name}-{scan.id}.cdx.json"'})


def report_data(db: Session, scan: Scan):
    project = db.get(Project, scan.project_id)
    components = db.scalars(select(Component).where(Component.scan_id == scan.id).order_by(Component.name)).all()
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id).join(Finding.component).join(Finding.vulnerability).options()).all()
    return project, components, findings


@app.get("/api/v1/scans/{scan_id}/report.json", tags=["reports"])
def scan_report_json(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = get_scan(db, user, scan_id)
    project, components, findings = report_data(db, scan)
    audit(db, user.id, "report.json_downloaded", "scan", scan.id)
    db.commit()
    return {"project": {"id": str(project.id), "name": project.name}, "scan": scan_dict(scan),
            "components": [component_dict(c) for c in components], "findings": [finding_dict(f) for f in findings],
            "limitations": ["Package-level matching does not establish reachability.", "A missing finding is not proof of absence if intelligence sources were unavailable."]}


@app.get("/api/v1/scans/{scan_id}/report.pdf", tags=["reports"])
def scan_report_pdf(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = get_scan(db, user, scan_id)
    project, components, findings = report_data(db, scan)
    payload = scan_pdf({"name": project.name}, scan_dict(scan), [component_dict(c) for c in components], [finding_dict(f) for f in findings])
    audit(db, user.id, "report.pdf_downloaded", "scan", scan.id)
    db.commit()
    return RawResponse(payload, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="depshield-{scan.id}.pdf"'})


@app.get("/api/v1/vulnerabilities", tags=["vulnerabilities"])
def vulnerability_search(user: User = Depends(authenticated_user), db: Session = Depends(get_db), q: str = "", priority: str | None = None, ecosystem: str | None = None, kev: str | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    stmt = select(Finding).where(Finding.scan_id.in_(project_scan_ids(db, user))).join(Finding.component).join(Finding.vulnerability)
    if q:
        needle = f"%{q[:100]}%"
        stmt = stmt.where(or_(Component.name.ilike(needle), Vulnerability.osv_id.ilike(needle), Vulnerability.summary.ilike(needle)))
    if priority:
        stmt = stmt.where(Finding.priority == priority.title())
    if ecosystem:
        stmt = stmt.where(Component.ecosystem == ecosystem)
    if kev:
        stmt = stmt.where(Finding.kev_status == kev.lower())
    rows = db.scalars(stmt.order_by(Finding.created_at.desc(), Finding.risk_score.desc().nullslast()).offset(offset).limit(limit)).all()
    return {"items": [finding_dict(f) for f in rows], "limit": limit, "offset": offset}


@app.post("/api/v1/findings/{finding_id}/explanation", tags=["ai"], dependencies=[Depends(require_csrf)])
def finding_explanation(finding_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    get_scan(db, user, finding.scan_id)
    output = explain(
        {"osv_id": finding.vulnerability.osv_id, "aliases": finding.vulnerability.aliases or [], "summary": finding.vulnerability.summary,
         "details": finding.vulnerability.details, "references": finding.vulnerability.references or [],
         "nvd_description": finding.vulnerability.nvd_description, "cwes": finding.vulnerability.cwes or []},
        component_dict(finding.component),
        {"cvss": finding.cvss, "official_severity": finding.official_severity, "kev_status": finding.kev_status,
         "fixed_versions": finding.fixed_versions or [], "risk_score": finding.risk_score, "priority": finding.priority, "risk_factors": finding.risk_factors},
    )
    audit(db, user.id, "ai.explanation_requested", "finding", finding.id, metadata={"provider": output.generated_by})
    db.commit()
    return output.model_dump()


@app.get("/api/v1/scans/{scan_id}/compare/{other_scan_id}", tags=["scans"])
def compare_scans(scan_id: UUID, other_scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    newer = get_scan(db, user, scan_id)
    older = get_scan(db, user, other_scan_id)
    if newer.project_id != older.project_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    def keys(scan):
        rows = db.execute(select(Vulnerability.osv_id, Component.purl, Component.name, Component.version).join(Finding, Finding.vulnerability_id == Vulnerability.id).join(Component, Component.id == Finding.component_id).where(Finding.scan_id == scan.id)).all()
        return {f"{r[0]}|{r[1] or r[2]}" for r in rows}
    new_findings, old_findings = keys(newer), keys(older)
    reliable = newer.status == "completed" and older.status == "completed"
    return {"older_scan_id": str(older.id), "newer_scan_id": str(newer.id), "comparison_reliable": reliable,
            "new_findings": sorted(new_findings - old_findings), "findings_in_both": sorted(new_findings & old_findings),
            "no_longer_detected": sorted(old_findings - new_findings) if reliable else None,
            "note": None if reliable else "At least one scan was partial or incomplete; missing findings are not labelled as fixed."}


@app.get("/api/v1/dashboard", tags=["dashboard"])
def dashboard(user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project_ids = project_accessible_query(db, user).with_only_columns(Project.id)
    scan_ids = select(Scan.id).where(Scan.project_id.in_(project_ids))
    total_projects = db.scalar(select(func.count()).select_from(Project).where(Project.id.in_(project_ids))) or 0
    total_scans = db.scalar(select(func.count()).select_from(Scan).where(Scan.id.in_(scan_ids))) or 0
    component_count = db.scalar(select(func.count()).select_from(Component).where(Component.scan_id.in_(scan_ids))) or 0
    rows = db.execute(select(Finding.priority, func.count(Finding.id)).where(Finding.scan_id.in_(scan_ids)).group_by(Finding.priority)).all()
    kev_count = db.scalar(select(func.count(Finding.id)).where(Finding.scan_id.in_(scan_ids), Finding.kev_status == "known")) or 0
    recent = db.scalars(select(Scan).where(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.desc()).limit(8)).all()
    return {"projects": total_projects, "scans": total_scans, "components": component_count,
            "priority_counts": dict(rows), "known_exploited_findings": kev_count, "recent_scans": [scan_dict(s) for s in recent]}


@app.get("/api/v1/profile", tags=["profile"])
def get_profile(user: User = Depends(authenticated_user)):
    return {"user": user_dict(user)}


@app.patch("/api/v1/profile", tags=["profile"], dependencies=[Depends(require_csrf)])
def update_profile(payload: dict, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    display_name = payload.get("display_name")
    if not isinstance(display_name, str) or not display_name.strip() or len(display_name.strip()) > 100:
        raise HTTPException(status_code=422, detail="Display name must be between 1 and 100 characters")
    user.display_name = display_name.strip()
    audit(db, user.id, "profile.updated", "user", user.id)
    db.commit()
    return {"user": user_dict(user)}


@app.get("/api/v1/admin/overview", tags=["administration"])
def admin_overview(user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    require_role(user, "administrator")
    job_counts = dict(db.execute(select(ScanJob.status, func.count(ScanJob.id)).group_by(ScanJob.status)).all())
    return {"users": db.scalar(select(func.count(User.id))) or 0, "active_users": db.scalar(select(func.count(User.id)).where(User.is_active.is_(True))) or 0,
            "projects": db.scalar(select(func.count(Project.id))) or 0, "scans": db.scalar(select(func.count(Scan.id))) or 0,
            "jobs": job_counts, "intelligence": {"osv": "checked during scans", "cisa_kev": "cached by worker", "nvd": "best effort", "ollama_enabled": settings.ollama_enabled}}


@app.get("/api/v1/admin/users", tags=["administration"])
def admin_users(user: User = Depends(authenticated_user), db: Session = Depends(get_db), q: str = "", limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
    require_role(user, "administrator")
    stmt = select(User)
    if q:
        stmt = stmt.where(User.email.ilike(f"%{q[:100]}%"))
    rows = db.scalars(stmt.order_by(User.created_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [{**user_dict(row), "is_active": row.is_active} for row in rows]}


@app.patch("/api/v1/admin/users/{target_id}/role", tags=["administration"], dependencies=[Depends(require_csrf)])
def admin_user_role(target_id: UUID, payload: RoleUpdate, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    require_role(user, "administrator")
    if payload.role not in {"developer", "auditor"}:
        raise HTTPException(status_code=422, detail="Administrators may assign developer or auditor roles; administrator grants require out-of-band review")
    target = db.get(User, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = payload.role
    audit(db, user.id, "admin.role_changed", "user", target.id, metadata={"role": payload.role})
    db.commit()
    return {"user": user_dict(target)}


@app.patch("/api/v1/admin/users/{target_id}/status", tags=["administration"], dependencies=[Depends(require_csrf)])
def admin_user_status(target_id: UUID, payload: StatusUpdate, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    require_role(user, "administrator")
    target = db.get(User, target_id)
    if not target or target.id == user.id and not payload.is_active:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_active = payload.is_active
    if not target.is_active:
        db.query(SessionRecord).filter(SessionRecord.user_id == target.id, SessionRecord.revoked_at.is_(None)).update({"revoked_at": utcnow()})
    audit(db, user.id, "admin.account_status_changed", "user", target.id, metadata={"is_active": target.is_active})
    db.commit()
    return {"user": {**user_dict(target), "is_active": target.is_active}}


@app.get("/api/v1/admin/audit", tags=["administration"])
def admin_audit(user: User = Depends(authenticated_user), db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    require_role(user, "administrator")
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [{"id": str(r.id), "actor_id": str(r.actor_id) if r.actor_id else None, "action": r.action,
                       "target_type": r.target_type, "target_id": r.target_id, "outcome": r.outcome,
                       "metadata": r.metadata_json, "created_at": r.created_at.isoformat()} for r in rows]}


@app.get("/api/v1/admin/jobs", tags=["administration"])
def admin_jobs(user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    require_role(user, "administrator")
    rows = db.scalars(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(200)).all()
    return {"items": [{"id": str(r.id), "scan_id": str(r.scan_id), "status": r.status, "attempts": r.attempts,
                       "max_attempts": r.max_attempts, "last_error": r.last_error, "created_at": r.created_at.isoformat()} for r in rows]}


@app.get("/api/v1/admin/health", tags=["administration"])
def admin_health(user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    require_role(user, "administrator")
    db.execute(text("SELECT 1"))
    kev, kev_status = load_kev()
    return {"database": "available", "kev_status": kev_status, "kev_entries": len(kev) if kev_status == "available" else None,
            "ollama": "configured" if settings.ollama_enabled else "disabled", "worker": "separate process; see scan job states"}


