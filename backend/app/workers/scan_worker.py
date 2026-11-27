"""Durable PostgreSQL-backed scan worker. Uploaded source is never executed."""

import logging
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete, or_, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.features.monitoring import create_scan_notifications, deliver_pending_notification_emails, enqueue_due_schedule
from app.intelligence.kev import load_kev
from app.intelligence.osv import affected_ranges, cve_ids, fixed_versions, nvd_enrich, query_components_cached
from app.models.entities import Component, Finding, Project, Scan, ScanJob, Vulnerability
from app.risk.scoring import official_severity, score_finding
from app.sbom.cyclonedx import build_sbom

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("depshield.worker")


def claim_job():
    now = datetime.now(timezone.utc)
    stale_before = now - timedelta(minutes=10)
    with SessionLocal() as db:
        with db.begin():
            job = db.scalar(
                select(ScanJob)
                .where(
                    or_(
                        (ScanJob.status == "queued") & (ScanJob.available_at <= now),
                        (ScanJob.status == "processing") & (ScanJob.locked_at < stale_before),
                    )
                )
                .order_by(ScanJob.created_at)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if not job:
                return None
            scan = db.scalar(
                select(Scan).where(Scan.id == job.scan_id).with_for_update()
                .execution_options(populate_existing=True)
            )
            if not scan:
                job.status = "failed"
                job.last_error = "Associated scan no longer exists"
                job.locked_at = None
                return None
            if scan.status in {"completed", "partial", "failed", "cancelled"}:
                job.status = "completed" if scan.status == "partial" else scan.status
                job.locked_at = None
                return None
            if job.attempts >= job.max_attempts:
                job.status = "failed"
                job.last_error = "Worker lease expired after maximum attempts"
                job.locked_at = None
                scan.status = "failed"
                scan.stage = "Failed"
                scan.error_message = "Scan could not be completed. Check worker and intelligence service health."
                scan.completed_at = now
                return None
            job.status = "processing"
            job.locked_at = now
            job.attempts += 1
            scan_id = job.scan_id
            job_id = job.id
            scan.status = "processing"
            scan.stage = "Generating SBOM"
            scan.started_at = scan.started_at or now
            return job_id, scan_id, job.attempts, job.max_attempts


def set_stage(scan_id, stage):
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan and scan.status == "processing":
            scan.stage = stage
            db.commit()


def process_job(job_id: UUID, scan_id: UUID, attempts: int, max_attempts: int):
    scan_deadline = time.monotonic() + max(1, settings.scan_timeout_seconds)
    with SessionLocal() as db:
        job = db.scalar(
            select(ScanJob).where(ScanJob.id == job_id).with_for_update()
            .execution_options(populate_existing=True)
        )
        scan = db.scalar(
            select(Scan).where(Scan.id == scan_id).with_for_update()
            .execution_options(populate_existing=True)
        )
        if not job:
            return
        if not scan:
            job.status = "failed"
            job.last_error = "Associated scan no longer exists"
            job.locked_at = None
            db.commit()
            return
        if scan.status == "cancelled" or job.status == "cancelled":
            job.status = "cancelled"
            job.locked_at = None
            db.commit()
            return
        if job.status != "processing" or job.attempts != attempts:
            return
        if scan.status in {"completed", "partial", "failed"}:
            job.status = "completed" if scan.status == "partial" else scan.status
            job.locked_at = None
            db.commit()
            return
        scan.status = "processing"
        components = db.scalars(select(Component).where(Component.scan_id == scan.id).order_by(Component.id)).all()
        project = db.get(Project, scan.project_id)
        project_name = project.name if project else "Project"
        component_rows = [
            {"name": c.name, "version": c.version, "version_constraint": c.version_constraint, "ecosystem": c.ecosystem,
             "purl": c.purl, "directness": c.directness, "resolution": c.resolution, "manifest": c.manifest,
             "license": c.license, "dependencies": c.dependencies}
            for c in components
        ]

    bom = build_sbom(project_name, component_rows)
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan and scan.status != "cancelled":
            scan.sbom_json = bom
            db.commit()

    set_stage(scan_id, "Checking vulnerabilities")
    with SessionLocal() as cache_db:
        osv_results, osv_status = query_components_cached(cache_db, component_rows, deadline=scan_deadline)
    kev_ids, kev_status = load_kev(deadline=scan_deadline)
    set_stage(scan_id, "Calculating risk")
    source_status = {"osv": osv_status, "cisa_kev": kev_status, "nvd": "disabled" if not settings.nvd_enabled else "not_checked", "last_checked": datetime.now(timezone.utc).isoformat()}
    nvd_unavailable = False
    nvd_succeeded = False
    nvd_attempted = False
    nvd_had_data = False

    with SessionLocal() as db:
        job = db.scalar(
            select(ScanJob).where(ScanJob.id == job_id).with_for_update()
            .execution_options(populate_existing=True)
        )
        scan = db.scalar(
            select(Scan).where(Scan.id == scan_id).with_for_update()
            .execution_options(populate_existing=True)
        )
        if not job or job.status != "processing" or job.attempts != attempts:
            db.rollback()
            return
        if not scan:
            job.status = "failed"
            job.last_error = "Associated scan no longer exists"
            job.locked_at = None
            db.commit()
            return
        if scan.status == "cancelled" or job.status == "cancelled":
            job.status = "cancelled"
            job.locked_at = None
            db.commit()
            return
        if scan.status in {"completed", "partial", "failed"}:
            job.status = "completed" if scan.status == "partial" else scan.status
            job.locked_at = None
            db.commit()
            return
        current_components = db.scalars(select(Component).where(Component.scan_id == scan.id).order_by(Component.id)).all()
        for index, advisory_rows in osv_results.items():
            component = current_components[index]
            seen = set()
            for advisory in advisory_rows:
                advisory_id = advisory.get("id")
                if not advisory_id or advisory_id in seen:
                    continue
                seen.add(advisory_id)
                aliases = sorted({a for a in advisory.get("aliases", []) if isinstance(a, str) and len(a) <= 100})
                references = [r for r in advisory.get("references", []) if isinstance(r, dict) and isinstance(r.get("url"), str)][:50]
                vuln = db.scalar(select(Vulnerability).where(Vulnerability.osv_id == advisory_id))
                if not vuln:
                    vuln = Vulnerability(osv_id=advisory_id, aliases=aliases, summary=(advisory.get("summary") or "")[:1000], details=(advisory.get("details") or "")[:20000], published=advisory.get("published"), modified=advisory.get("modified"), references=references)
                    db.add(vuln)
                    db.flush()
                else:
                    vuln.aliases = sorted(set(vuln.aliases or []) | set(aliases))
                    vuln.summary = (advisory.get("summary") or vuln.summary or "")[:1000]
                    vuln.details = (advisory.get("details") or vuln.details or "")[:20000]
                    vuln.references = references or vuln.references
                    vuln.modified = advisory.get("modified") or vuln.modified
                    vuln.source_updated_at = datetime.now(timezone.utc)

                fixed = fixed_versions(advisory, component.ecosystem, component.name)
                cvss = None
                nvd_severity = None
                nvd_record = None
                advisory_cves = cve_ids(advisory)
                nvd_attempted = nvd_attempted or bool(advisory_cves)
                for cve_id in advisory_cves:
                    enrichment = nvd_enrich(cve_id, deadline=scan_deadline)
                    if enrichment.get("_unavailable"):
                        nvd_unavailable = True
                    else:
                        nvd_succeeded = True
                        if enrichment:
                            nvd_record = nvd_record or enrichment
                            nvd_had_data = True
                    if enrichment.get("cvss") is not None:
                        cvss = float(enrichment["cvss"])
                        nvd_severity = enrichment.get("severity")
                        break
                if cvss is not None:
                    nvd_had_data = True
                if nvd_record:
                    vuln.nvd_description = (nvd_record.get("description") or vuln.nvd_description or "")[:20000] or None
                    vuln.cwes = sorted(set(vuln.cwes or []) | set(nvd_record.get("cwes", [])))
                    vuln.nvd_published = nvd_record.get("published") or vuln.nvd_published
                    vuln.nvd_modified = nvd_record.get("modified") or vuln.nvd_modified
                cves = cve_ids(advisory)
                kev = (any(cve in kev_ids for cve in cves) if cves else None) if kev_status in {"available", "cached"} else None
                kev_state = "known" if kev is True else "not_listed" if kev is False else "unknown"
                score, priority, factors = score_finding(cvss, kev, component.directness, fixed)
                db.add(Finding(scan_id=scan.id, component_id=component.id, vulnerability_id=vuln.id, cvss=cvss,
                               official_severity=nvd_severity.title() if isinstance(nvd_severity, str) else official_severity(cvss),
                               kev_status=kev_state, fixed_versions=fixed,
                               affected_ranges=affected_ranges(advisory, component.ecosystem, component.name),
                               risk_score=score, priority=priority, risk_factors=factors))

        if not settings.nvd_enabled:
            source_status["nvd"] = "disabled"
        elif not nvd_attempted:
            source_status["nvd"] = "not_checked"
        elif nvd_unavailable and nvd_succeeded:
            source_status["nvd"] = "partial"
        elif nvd_unavailable:
            source_status["nvd"] = "unavailable"
        elif nvd_had_data:
            source_status["nvd"] = "available"
        else:
            source_status["nvd"] = "no_score_returned"
        scan.intelligence_status = source_status
        source_degraded = osv_status not in {"available", "cached"} or kev_status not in {"available", "cached"} or nvd_unavailable
        has_unresolved = any(not c.version or c.resolution != "resolved" for c in components)
        scan.status = "partial" if source_degraded or has_unresolved else "completed"
        scan.stage = "Partially completed" if scan.status == "partial" else "Completed"
        scan.completed_at = datetime.now(timezone.utc)
        job = db.get(ScanJob, job_id)
        if job:
            job.status = "completed"
            job.locked_at = None
        db.flush()
        create_scan_notifications(db, scan)
        db.commit()


def fail_job(job_id: UUID, scan_id: UUID, error: Exception, attempts: int, max_attempts: int):
    with SessionLocal() as db:
        job = db.scalar(
            select(ScanJob).where(ScanJob.id == job_id).with_for_update()
            .execution_options(populate_existing=True)
        )
        scan = db.scalar(
            select(Scan).where(Scan.id == scan_id).with_for_update()
            .execution_options(populate_existing=True)
        )
        if job:
            if scan and (scan.status == "cancelled" or job.status == "cancelled"):
                job.status = "cancelled"
                job.locked_at = None
                db.commit()
                return
            if job.status != "processing" or job.attempts != attempts:
                db.rollback()
                return
            if scan and scan.status in {"completed", "partial", "failed"}:
                job.status = "completed" if scan.status == "partial" else scan.status
                job.locked_at = None
                db.commit()
                return
            job.last_error = type(error).__name__
            job.locked_at = None
            if attempts < max_attempts:
                job.status = "queued"
                job.available_at = datetime.now(timezone.utc) + timedelta(seconds=2**attempts)
                if scan:
                    scan.status = "queued"
                    scan.stage = "Retry scheduled"
            else:
                job.status = "failed"
        if scan and (not job or job.status == "failed") and scan.status not in {"completed", "partial", "cancelled"}:
            scan.status = "failed"
            scan.stage = "Failed"
            scan.error_message = "Scan could not be completed. Check worker and intelligence service health."
            scan.completed_at = datetime.now(timezone.utc)
        db.commit()
    logger.warning("scan job %s failed on attempt %s", job_id, attempts)


def run_once() -> bool:
    claimed = claim_job()
    if not claimed:
        with SessionLocal() as db:
            return enqueue_due_schedule(db)
    job_id, scan_id, attempts, max_attempts = claimed
    try:
        process_job(job_id, scan_id, attempts, max_attempts)
        deliver_pending_notification_emails(session_factory=SessionLocal)
    except Exception as exc:
        fail_job(job_id, scan_id, exc, attempts, max_attempts)
    return True


def prune_expired_scans() -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, settings.data_retention_days))
    terminal = ("completed", "partial", "failed", "cancelled")
    with SessionLocal() as db:
        result = db.execute(delete(Scan).where(Scan.created_at < cutoff, Scan.status.in_(terminal)))
        deleted = result.rowcount or 0
        db.commit()
    if deleted:
        logger.info("retention cleanup removed %s expired scan snapshots", deleted)
    return deleted


def run_forever():
    logger.info("scan worker started")
    next_cleanup = 0.0
    while True:
        if time.monotonic() >= next_cleanup:
            try:
                prune_expired_scans()
            except Exception:
                logger.exception("retention cleanup failed")
            next_cleanup = time.monotonic() + 24 * 60 * 60
        try:
            if not run_once():
                time.sleep(max(0.5, settings.worker_poll_seconds))
        except Exception:
            logger.exception("scan worker loop failed")
            time.sleep(max(0.5, settings.worker_poll_seconds))


if __name__ == "__main__":
    run_forever()
