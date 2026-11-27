"""Authorization-scoped SBOM, policy, license, remediation and monitoring APIs."""

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.ai.explanations import explain
from app.api.deps import authenticated_user
from app.core.config import settings
from app.core.database import get_db
from app.features.licenses import evaluate_license_policy, fetch_registry_license, license_pdf, recognized_licenses
from app.features.policy import DEFAULT_POLICY, evaluate_scan_policy
from app.features.remediation import build_remediation_plan, remediation_pdf
from app.features.sbom import SBOMValidationError, compare_components, sbom_query_component, validate_cyclonedx
from app.intelligence.osv import query_components_cached
from app.models.entities import (Component, Finding, ImportedSBOM, LicenseEvidence, MonitoringSchedule,
                                 Notification, NotificationPreference, Project, ProjectSecurityPolicy,
                                 Scan, User, utcnow)
from app.schemas.api import MonitoringScheduleIn, NotificationPreferenceIn, SBOMCompareIn, SecurityPolicyIn
from app.security.auth import require_csrf, require_role
from app.services.audit import audit
from app.services.projects import get_project

router = APIRouter(prefix="/api/v1")
MAX_SBOM_BYTES = 5 * 1024 * 1024
SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._ -]")


def _project(db: Session, user: User, project_id: UUID, *, write: bool = False) -> Project:
    return get_project(db, user, project_id, write=write)


def _owner(db: Session, user: User, project_id: UUID) -> Project:
    require_role(user, "developer", "administrator")
    return _project(db, user, project_id, write=True)


def _scan(db: Session, user: User, scan_id: UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _project(db, user, scan.project_id)
    return scan


def _policy_dict(db: Session, project_id: UUID) -> dict:
    row = db.get(ProjectSecurityPolicy, project_id)
    if not row:
        return {"project_id": str(project_id), **DEFAULT_POLICY}
    return {"project_id": str(project_id), "max_allowed_priority": row.max_allowed_priority,
            "fail_on_kev": row.fail_on_kev, "partial_behavior": row.partial_behavior,
            "unavailable_behavior": row.unavailable_behavior,
            "fail_on_unknown_license": row.fail_on_unknown_license,
            "allowed_licenses": row.allowed_licenses or [], "restricted_licenses": row.restricted_licenses or [],
            "updated_at": row.updated_at.isoformat() if row.updated_at else None}


def _latest_result_scan(db: Session, project_id: UUID) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.project_id == project_id, Scan.status.in_(("completed", "partial")))
                     .order_by(Scan.created_at.desc()).limit(1))
    if not scan:
        raise HTTPException(status_code=409, detail="Run a scan before reviewing component evidence")
    return scan


def _license_rows(db: Session, scan: Scan) -> list[dict]:
    components = db.scalars(select(Component).where(Component.scan_id == scan.id).order_by(Component.ecosystem, Component.name)).all()
    keys = list({(component.ecosystem, component.name, component.version) for component in components if component.version})
    evidence_map = {}
    for offset in range(0, len(keys), 400):
        batch = keys[offset:offset + 400]
        evidence_rows = db.scalars(select(LicenseEvidence).where(tuple_(LicenseEvidence.ecosystem, LicenseEvidence.package_name,
                                                                        LicenseEvidence.package_version).in_(batch))).all()
        evidence_map.update({(row.ecosystem, row.package_name, row.package_version): row for row in evidence_rows})
    rows = []
    for component in components:
        evidence = evidence_map.get((component.ecosystem, component.name, component.version))
        verified = bool(evidence and evidence.status == "available" and evidence.license_expression)
        expression = evidence.license_expression if verified else None
        declared = component.license if isinstance(component.license, str) and component.license.strip() else None
        rows.append({"component_id": str(component.id), "name": component.name, "version": component.version,
                     "ecosystem": component.ecosystem, "purl": component.purl,
                     "license": expression or declared, "verified_metadata": verified,
                     "evidence_source": evidence.source_url if verified else ("manifest declaration (unverified)" if declared else None),
                     "evidence_status": evidence.status if evidence else ("declared_unverified" if declared else "unknown"),
                     "checked_at": evidence.checked_at.isoformat() if evidence else None,
                     "recognized_licenses": recognized_licenses(expression) if verified else []})
    return rows


def _license_evaluation(rows: list[dict], policy: dict) -> dict:
    result = evaluate_license_policy(rows, policy)
    if policy.get("fail_on_unknown_license"):
        result["status"] = "fail" if result["violations"] or result["unknown"] else "clear"
    return result


def _finding_data(db: Session, scan: Scan) -> list[dict]:
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)
                          .options(joinedload(Finding.component), joinedload(Finding.vulnerability))
                          .order_by(Finding.risk_score.desc().nullslast())).all()
    return [{"id": str(item.id),
             "component": {"name": item.component.name, "version": item.component.version,
                           "ecosystem": item.component.ecosystem, "resolution": item.component.resolution,
                           "purl": item.component.purl},
             "vulnerability": {"osv_id": item.vulnerability.osv_id, "summary": item.vulnerability.summary,
                               "details": item.vulnerability.details, "aliases": item.vulnerability.aliases or [],
                               "references": item.vulnerability.references or [], "nvd_description": item.vulnerability.nvd_description,
                               "cwes": item.vulnerability.cwes or []},
             "cvss": item.cvss, "official_severity": item.official_severity, "kev_status": item.kev_status,
             "fixed_versions": item.fixed_versions or [], "affected_ranges": item.affected_ranges or [],
             "risk_score": item.risk_score, "priority": item.priority,
             "risk_factors": item.risk_factors or {}} for item in findings]


def _resolve_sbom(db: Session, project_id: UUID, kind: str, item_id: UUID) -> tuple[dict, dict]:
    if kind == "imported":
        item = db.scalar(select(ImportedSBOM).where(ImportedSBOM.id == item_id, ImportedSBOM.project_id == project_id))
        if not item:
            raise HTTPException(status_code=404, detail="Imported SBOM not found")
        return item.document, {"kind": "imported", "id": str(item.id), "filename": item.filename,
                               "spec_version": item.spec_version, "version_evidence": "user-supplied SBOM; installation not verified"}
    scan = db.scalar(select(Scan).where(Scan.id == item_id, Scan.project_id == project_id))
    if not scan or not scan.sbom_json:
        raise HTTPException(status_code=404, detail="Generated SBOM not found for this project")
    return scan.sbom_json, {"kind": "generated", "id": str(scan.id), "filename": scan.source_filename,
                            "status": scan.status, "version_evidence": "generated from parsed manifest; installation not verified"}


def _reject_json_constant(value):
    raise ValueError(f"Non-standard JSON constant {value} is not allowed")


@router.get("/projects/{project_id}/sboms")
def list_sboms(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _project(db, user, project_id)
    imported = db.scalars(select(ImportedSBOM).where(ImportedSBOM.project_id == project.id)
                          .order_by(ImportedSBOM.created_at.desc()).limit(100)).all()
    generated = db.scalars(select(Scan).where(Scan.project_id == project.id, Scan.sbom_json.is_not(None))
                           .order_by(Scan.created_at.desc()).limit(100)).all()
    return {"imported": [{"id": str(item.id), "filename": item.filename, "spec_version": item.spec_version,
                           "sha256": item.sha256, "created_at": item.created_at.isoformat(),
                           "component_count": len(item.document.get("components", []))} for item in imported],
            "generated": [{"id": str(scan.id), "filename": scan.source_filename, "status": scan.status,
                           "created_at": scan.created_at.isoformat(), "component_count": len((scan.sbom_json or {}).get("components", []))} for scan in generated]}


@router.post("/projects/{project_id}/sboms/import", status_code=201, dependencies=[Depends(require_csrf)])
async def import_sbom(project_id: UUID, file: UploadFile = File(...), user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _owner(db, user, project_id)
    raw = await file.read(MAX_SBOM_BYTES + 1)
    if len(raw) > MAX_SBOM_BYTES:
        raise HTTPException(status_code=413, detail="SBOM exceeds the 5 MiB limit")
    try:
        document = json.loads(raw.decode("utf-8-sig"), parse_constant=_reject_json_constant)
        validate_cyclonedx(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        message = str(exc) if isinstance(exc, SBOMValidationError) else "SBOM must be valid UTF-8 CycloneDX JSON"
        raise HTTPException(status_code=422, detail=message) from exc
    filename = SAFE_FILENAME.sub("_", PurePosixPath((file.filename or "imported.cdx.json").replace("\\", "/")).name)[:255] or "imported.cdx.json"
    item = ImportedSBOM(project_id=project.id, uploaded_by=user.id, filename=filename,
                        spec_version=document["specVersion"], document=document,
                        sha256=hashlib.sha256(raw).hexdigest())
    db.add(item)
    audit(db, user.id, "sbom.imported", "project", project.id,
          metadata={"spec_version": item.spec_version, "component_count": len(document.get("components", []))})
    db.commit()
    db.refresh(item)
    return {"id": str(item.id), "project_id": str(project.id), "filename": filename,
            "spec_version": item.spec_version, "sha256": item.sha256,
            "component_count": len(document.get("components", [])), "created_at": item.created_at.isoformat()}


@router.post("/projects/{project_id}/sboms/compare")
def compare_sboms(project_id: UUID, payload: SBOMCompareIn, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _project(db, user, project_id)
    left_doc, left_info = _resolve_sbom(db, project.id, payload.left.kind, payload.left.id)
    right_doc, right_info = _resolve_sbom(db, project.id, payload.right.kind, payload.right.id)
    diff = compare_components(left_doc.get("components", []), right_doc.get("components", []))
    notes = []
    for info in (left_info, right_info):
        if info.get("status") in {"partial", "queued", "processing"}:
            notes.append(f"Generated SBOM {info['id']} came from a {info['status']} scan")
    return {"project_id": str(project.id), "left": left_info, "right": right_info, **diff,
            "download_name": f"depshield-sbom-diff-{payload.left.id}-{payload.right.id}.json",
            "notes": notes + ["Package versions are statements in the supplied/generated BOM and do not prove installation."]}


@router.post("/projects/{project_id}/sboms/{sbom_id}/vulnerabilities", dependencies=[Depends(require_csrf)])
def check_imported_sbom_vulnerabilities(project_id: UUID, sbom_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _project(db, user, project_id)
    imported = db.scalar(select(ImportedSBOM).where(ImportedSBOM.id == sbom_id, ImportedSBOM.project_id == project.id))
    if not imported:
        raise HTTPException(status_code=404, detail="Imported SBOM not found")
    source_components = imported.document.get("components", [])
    queries, source_indices = [], []
    for index, component in enumerate(source_components):
        row = sbom_query_component(component)
        if row:
            queries.append(row)
            source_indices.append(index)
        if len(queries) >= 1000:
            break
    if not queries:
        return {"status": "unresolved", "items": [], "note": "No supported package URLs with exact versions were available for OSV matching."}
    results, status = query_components_cached(db, queries)
    items = []
    for position, advisories in results.items():
        source = source_components[source_indices[position]]
        for advisory in advisories:
            items.append({"component": source, "osv_id": advisory.get("id"), "summary": advisory.get("summary"),
                          "aliases": advisory.get("aliases", []), "references": advisory.get("references", []),
                          "evidence": "OSV exact package/version query against the imported SBOM declaration",
                          "version_confirmed_installed": False})
    db.commit()
    return {"status": status, "items": items,
            "queried_components": len(queries), "unmatched_or_unsupported_components": max(0, len(source_components) - len(queries)),
            "note": "A package/version match describes the imported BOM declaration; it does not verify an installed artifact."}


@router.get("/projects/{project_id}/security-policy")
def get_security_policy(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _project(db, user, project_id)
    return _policy_dict(db, project.id)


@router.put("/projects/{project_id}/security-policy", dependencies=[Depends(require_csrf)])
def update_security_policy(project_id: UUID, payload: SecurityPolicyIn, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _owner(db, user, project_id)
    row = db.get(ProjectSecurityPolicy, project.id)
    values = payload.model_dump()
    if row is None:
        row = ProjectSecurityPolicy(project_id=project.id, **values)
        db.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
    audit(db, user.id, "project.security_policy_updated", "project", project.id,
          metadata={"max_allowed_priority": payload.max_allowed_priority})
    db.commit()
    return _policy_dict(db, project.id)


@router.post("/scans/{scan_id}/policy/evaluate", dependencies=[Depends(require_csrf)])
def evaluate_policy(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = _scan(db, user, scan_id)
    policy = _policy_dict(db, scan.project_id)
    findings = _finding_data(db, scan)
    license_result = _license_evaluation(_license_rows(db, scan), policy)
    result = evaluate_scan_policy(scan, findings, policy, license_result)
    scan.policy_result = result
    audit(db, user.id, "scan.security_policy_evaluated", "scan", scan.id, metadata={"status": result["status"]})
    db.commit()
    return result


@router.get("/scans/{scan_id}/policy-result")
def scan_policy_result(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = _scan(db, user, scan_id)
    if scan.policy_result:
        return scan.policy_result
    policy = _policy_dict(db, scan.project_id)
    return evaluate_scan_policy(scan, _finding_data(db, scan), policy, _license_evaluation(_license_rows(db, scan), policy))


def _remediation_data(db: Session, scan: Scan, ai: bool = False) -> dict:
    rows = _finding_data(db, scan)
    ai_rows = {}
    if ai:
        for item in rows[:20]:
            output = explain(item["vulnerability"], item["component"],
                             {key: item.get(key) for key in ("cvss", "official_severity", "kev_status", "fixed_versions", "risk_score", "priority", "risk_factors")})
            ai_rows[item["id"]] = {"text": output.remediation, "generated_by": output.generated_by,
                                    "uncertainty": output.uncertainty}
    return build_remediation_plan(scan, rows, ai_rows)


@router.get("/scans/{scan_id}/remediation")
def remediation_plan(scan_id: UUID, ai_explanations: bool = False, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = _scan(db, user, scan_id)
    return _remediation_data(db, scan, ai=ai_explanations)


@router.get("/scans/{scan_id}/remediation.pdf")
def remediation_plan_pdf(scan_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    scan = _scan(db, user, scan_id)
    project = db.get(Project, scan.project_id)
    content = remediation_pdf(project.name, _remediation_data(db, scan))
    return Response(content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="depshield-remediation-{scan.id}.pdf"'})


@router.get("/projects/{project_id}/licenses")
def license_inventory(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _project(db, user, project_id)
    scan = _latest_result_scan(db, project.id)
    rows = _license_rows(db, scan)
    policy = _policy_dict(db, project.id)
    return {"project_id": str(project.id), "scan_id": str(scan.id), "scan_status": scan.status,
            "items": rows, "evaluation": _license_evaluation(rows, policy),
            "policy": {"allowed_licenses": policy["allowed_licenses"], "restricted_licenses": policy["restricted_licenses"],
                       "fail_on_unknown_license": policy["fail_on_unknown_license"]}}


@router.post("/projects/{project_id}/licenses/refresh", dependencies=[Depends(require_csrf)])
def refresh_license_evidence(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _owner(db, user, project_id)
    scan = _latest_result_scan(db, project.id)
    components = db.scalars(select(Component).where(Component.scan_id == scan.id, Component.version.is_not(None))
                            .order_by(Component.ecosystem, Component.name).limit(100)).all()
    now = datetime.now(timezone.utc)
    due = []
    for component in components:
        evidence = db.scalar(select(LicenseEvidence).where(LicenseEvidence.ecosystem == component.ecosystem,
                                                           LicenseEvidence.package_name == component.name,
                                                           LicenseEvidence.package_version == component.version))
        checked = evidence.checked_at.replace(tzinfo=timezone.utc) if evidence and evidence.checked_at.tzinfo is None else (evidence.checked_at if evidence else None)
        if not evidence or not checked or checked < now - timedelta(hours=24):
            due.append(component)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda item: fetch_registry_license(item.ecosystem, item.name, item.version), due))
    for component, result in zip(due, results):
        evidence = db.scalar(select(LicenseEvidence).where(LicenseEvidence.ecosystem == component.ecosystem,
                                                           LicenseEvidence.package_name == component.name,
                                                           LicenseEvidence.package_version == component.version))
        if evidence is None:
            evidence = LicenseEvidence(ecosystem=component.ecosystem, package_name=component.name,
                                       package_version=component.version)
            db.add(evidence)
        evidence.license_expression = result["license"]
        evidence.source_url = result["source_url"]
        evidence.status = result["status"]
        evidence.checked_at = now
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="License evidence changed concurrently; refresh the inventory")
    audit(db, user.id, "project.license_evidence_refreshed", "project", project.id,
          metadata={"checked_count": len(due), "scan_id": str(scan.id)})
    db.commit()
    return {"checked": len(due), "deferred_or_cached": len(components) - len(due), "items": _license_rows(db, scan)}


@router.get("/projects/{project_id}/licenses/report.json")
def license_report_json(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    return license_inventory(project_id, user, db)


@router.get("/projects/{project_id}/licenses/report.pdf")
def license_report_pdf(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    data = license_inventory(project_id, user, db)
    project = db.get(Project, project_id)
    content = license_pdf(project.name, data["scan_id"], data["items"], data["evaluation"])
    return Response(content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="depshield-licenses-{project_id}.pdf"'})


def _schedule_dict(schedule: MonitoringSchedule | None, project_id: UUID) -> dict:
    if not schedule:
        return {"project_id": str(project_id), "configured": False, "active": False}
    return {"id": str(schedule.id), "project_id": str(project_id), "configured": True,
            "interval_hours": schedule.interval_hours, "active": schedule.active,
            "next_run_at": schedule.next_run_at.isoformat(), "last_scan_id": str(schedule.last_scan_id) if schedule.last_scan_id else None,
            "created_at": schedule.created_at.isoformat(), "updated_at": schedule.updated_at.isoformat()}


@router.get("/projects/{project_id}/monitoring/schedule")
def get_monitoring_schedule(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _project(db, user, project_id)
    schedule = db.scalar(select(MonitoringSchedule).where(MonitoringSchedule.project_id == project.id))
    return _schedule_dict(schedule, project.id)


@router.put("/projects/{project_id}/monitoring/schedule", dependencies=[Depends(require_csrf)])
def set_monitoring_schedule(project_id: UUID, payload: MonitoringScheduleIn, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _owner(db, user, project_id)
    if project.archived:
        raise HTTPException(status_code=409, detail="Archived projects cannot be monitored")
    schedule = db.scalar(select(MonitoringSchedule).where(MonitoringSchedule.project_id == project.id))
    now = utcnow()
    if schedule is None:
        schedule = MonitoringSchedule(project_id=project.id, interval_hours=payload.interval_hours,
                                      active=payload.active, next_run_at=now + timedelta(hours=payload.interval_hours))
        db.add(schedule)
    else:
        schedule.interval_hours = payload.interval_hours
        schedule.active = payload.active
        schedule.next_run_at = now + timedelta(hours=payload.interval_hours) if payload.active else schedule.next_run_at
    audit(db, user.id, "project.monitoring_schedule_updated", "project", project.id,
          metadata={"interval_hours": payload.interval_hours, "active": payload.active})
    db.commit()
    db.refresh(schedule)
    return _schedule_dict(schedule, project.id)


@router.delete("/projects/{project_id}/monitoring/schedule", dependencies=[Depends(require_csrf)])
def delete_monitoring_schedule(project_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    project = _owner(db, user, project_id)
    schedule = db.scalar(select(MonitoringSchedule).where(MonitoringSchedule.project_id == project.id))
    if schedule:
        db.delete(schedule)
        db.commit()
    return {"project_id": str(project.id), "configured": False}


@router.get("/notifications")
def list_notifications(unread_only: bool = False, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                       user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    stmt = select(Notification).where(Notification.user_id == user.id)
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    items = db.scalars(stmt.order_by(Notification.created_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [{"id": str(item.id), "project_id": str(item.project_id), "event_type": item.event_type,
                        "title": item.title, "message": item.message, "payload": item.payload or {},
                        "read_at": item.read_at.isoformat() if item.read_at else None,
                        "email_status": item.email_status, "created_at": item.created_at.isoformat()} for item in items],
            "limit": limit, "offset": offset}


@router.post("/notifications/{notification_id}/read", dependencies=[Depends(require_csrf)])
def mark_notification_read(notification_id: UUID, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    item = db.scalar(select(Notification).where(Notification.id == notification_id, Notification.user_id == user.id))
    if not item:
        raise HTTPException(status_code=404, detail="Notification not found")
    if item.read_at is None:
        item.read_at = utcnow()
        db.commit()
    return {"id": str(item.id), "read_at": item.read_at.isoformat()}


@router.post("/notifications/read-all", dependencies=[Depends(require_csrf)])
def mark_all_notifications_read(user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Notification).where(Notification.user_id == user.id, Notification.read_at.is_(None))).all()
    now = utcnow()
    for item in rows:
        item.read_at = now
    db.commit()
    return {"updated": len(rows)}


@router.get("/notification-preferences")
def get_notification_preferences(user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    row = db.get(NotificationPreference, user.id)
    return {"email_enabled": bool(row and row.email_enabled), "smtp_configured": bool(settings.smtp_host)}


@router.put("/notification-preferences", dependencies=[Depends(require_csrf)])
def set_notification_preferences(payload: NotificationPreferenceIn, user: User = Depends(authenticated_user), db: Session = Depends(get_db)):
    if payload.email_enabled and not settings.smtp_host:
        raise HTTPException(status_code=409, detail="Configure SMTP before enabling email alerts")
    row = db.get(NotificationPreference, user.id)
    if row is None:
        row = NotificationPreference(user_id=user.id, email_enabled=payload.email_enabled)
        db.add(row)
    else:
        row.email_enabled = payload.email_enabled
    db.commit()
    return {"email_enabled": row.email_enabled, "smtp_configured": bool(settings.smtp_host)}
