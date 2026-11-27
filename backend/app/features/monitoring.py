import hashlib
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.scan_jobs import enqueue_scan_job
from app.models.entities import (Component, Finding, MonitoringSchedule, Notification,
                                 NotificationPreference, Project, Scan,
                                 User, Vulnerability)

logger = logging.getLogger("depshield.monitoring")


def enqueue_due_schedule(db: Session, now: datetime | None = None) -> bool:
    """Atomically turn one due project schedule into a durable scan job."""
    now = now or datetime.now(timezone.utc)
    schedule = db.scalar(
        select(MonitoringSchedule).where(MonitoringSchedule.active.is_(True), MonitoringSchedule.next_run_at <= now)
        .order_by(MonitoringSchedule.next_run_at).with_for_update(skip_locked=True).limit(1)
    )
    if not schedule:
        return False
    project = db.get(Project, schedule.project_id)
    latest = db.scalar(select(Scan).where(Scan.project_id == schedule.project_id, Scan.status.in_(("completed", "partial")))
                       .order_by(Scan.created_at.desc()).limit(1))
    interval = timedelta(hours=schedule.interval_hours)
    schedule.next_run_at = now + interval
    if not project or project.archived or not latest:
        db.commit()
        return True
    original = db.scalars(select(Component).where(Component.scan_id == latest.id).order_by(Component.id)).all()
    if not original:
        db.commit()
        return True
    scan = Scan(project_id=project.id, requested_by=None, status="queued", stage="Queued by monitoring",
                source_filename=f"scheduled-{latest.source_filename}"[:255], source_sha256=latest.source_sha256,
                source_bytes=latest.source_bytes)
    db.add(scan)
    db.flush()
    for component in original:
        db.add(Component(scan_id=scan.id, name=component.name, version=component.version,
                         version_constraint=component.version_constraint, ecosystem=component.ecosystem,
                         purl=component.purl, directness=component.directness, resolution=component.resolution,
                         manifest=component.manifest, license=component.license, dependencies=component.dependencies or []))
    enqueue_scan_job(db, scan)
    schedule.last_scan_id = scan.id
    db.commit()
    logger.info("monitoring enqueued scheduled scan %s for project %s", scan.id, project.id)
    return True


def _finding_rows(db: Session, scan_id) -> list[tuple]:
    return db.execute(select(Vulnerability.osv_id, Component.purl, Component.name, Component.version,
                             Component.ecosystem, Finding.kev_status)
                      .join(Finding, Finding.vulnerability_id == Vulnerability.id)
                      .join(Component, Finding.component_id == Component.id)
                      .where(Finding.scan_id == scan_id)).all()


def _finding_key(row) -> str:
    component = row.purl or f"{row.ecosystem}/{row.name}@{row.version or 'unverified'}"
    return f"{row.osv_id}|{component}"


def create_scan_notifications(db: Session, scan: Scan) -> int:
    """Insert idempotent project-owner alerts in the scan completion transaction."""
    if scan.status not in {"completed", "partial"}:
        return 0
    project = db.get(Project, scan.project_id)
    owner = db.get(User, project.owner_id) if project else None
    if not project or not owner:
        return 0
    previous = db.scalar(select(Scan).where(Scan.project_id == project.id, Scan.id != scan.id,
                                   Scan.status == "completed", Scan.completed_at.is_not(None),
                                   Scan.created_at < scan.created_at)
                         .order_by(Scan.completed_at.desc()).limit(1))
    current_rows = _finding_rows(db, scan.id)
    previous_rows = _finding_rows(db, previous.id) if previous else []
    current_by_key = {_finding_key(row): row for row in current_rows}
    previous_by_key = {_finding_key(row): row for row in previous_rows}
    pref = db.get(NotificationPreference, owner.id)
    email_status = "pending" if pref and pref.email_enabled else "not_requested"
    created = 0

    def add(event_type: str, row, message: str):
        nonlocal created
        key = _finding_key(row)
        digest = hashlib.sha256(f"{project.id}|{scan.id}|{event_type}|{key}".encode()).hexdigest()
        event_key = f"{scan.id}|{event_type}|{digest}"
        existing = db.scalar(select(Notification.id).where(Notification.user_id == owner.id, Notification.event_key == event_key))
        if existing:
            return
        db.add(Notification(user_id=owner.id, project_id=project.id, event_key=event_key, event_type=event_type,
                            title={"new_vulnerability": "New vulnerability detected", "new_kev": "Known exploited vulnerability detected",
                                   "resolved": "Vulnerability no longer detected"}[event_type],
                            message=message[:1000], payload={"scan_id": str(scan.id), "vulnerability_id": row.osv_id,
                                                             "package": row.name, "version": row.version,
                                                             "scan_status": scan.status}, email_status=email_status))
        created += 1

    for key, row in current_by_key.items():
        if key not in previous_by_key:
            add("new_vulnerability", row, f"{row.osv_id} was found in {row.name} ({row.version or 'version unverified'}).")
        prior = previous_by_key.get(key)
        if row.kev_status == "known" and (not prior or prior.kev_status != "known"):
            add("new_kev", row, f"{row.osv_id} in {row.name} is now listed as known exploited in this scan.")
    if previous and scan.status == "completed":
        for key in sorted(previous_by_key.keys() - current_by_key.keys()):
            row = previous_by_key[key]
            add("resolved", row, f"{row.osv_id} was not present in this complete scan of {row.name}; review before treating it as resolved.")
    db.flush()
    return created


def record_scan_alerts(scan_id, session_factory=SessionLocal) -> int:
    with session_factory() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return 0
        created = create_scan_notifications(db, scan)
        db.commit()
        return created


def _send_email(recipient: str, title: str, message_text: str) -> None:
    if not settings.smtp_host:
        raise RuntimeError("SMTP is not configured")
    message = EmailMessage()
    message["Subject"] = f"DepShield alert: {title}"
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message.set_content(f"{message_text}\n\nOpen DepShield to review the project and scan evidence.")
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password or "")
        smtp.send_message(message)


def deliver_pending_notification_emails(session_factory=SessionLocal, limit: int = 20) -> int:
    """Claim email outbox rows before sending to avoid duplicate delivery on retries."""
    delivered = 0
    for _ in range(limit):
        with session_factory() as db:
            row = db.execute(select(Notification, User).join(User, User.id == Notification.user_id)
                             .where(Notification.email_status == "pending")
                             .order_by(Notification.created_at).with_for_update(skip_locked=True).limit(1)).first()
            if not row:
                break
            notification, user = row
            notification.email_status = "sending"
            title, body, recipient, notification_id = notification.title, notification.message, user.email, notification.id
            db.commit()
        status = "sent"
        try:
            _send_email(recipient, title, body)
            delivered += 1
        except Exception as exc:  # Never log recipient, body or SMTP credentials.
            status = "failed"
            logger.warning("notification email delivery failed (%s)", type(exc).__name__)
        with session_factory() as db:
            notification = db.get(Notification, notification_id)
            if notification and notification.email_status == "sending":
                notification.email_status = status
                db.commit()
    return delivered
