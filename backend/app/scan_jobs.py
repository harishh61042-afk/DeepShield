"""Idempotent persistence helpers for the one-job-per-scan queue."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models.entities import Scan, ScanJob


_SCAN_TO_JOB = {
    "queued": "queued",
    "processing": "processing",
    "completed": "completed",
    "partial": "completed",
    "failed": "failed",
    "cancelled": "cancelled",
}
_JOB_TO_SCAN = {
    "queued": "queued",
    "processing": "processing",
    "completed": "completed",
    "failed": "failed",
    "cancelled": "cancelled",
}
_TERMINAL_SCAN_STATES = {"completed", "partial", "failed", "cancelled"}


def _reconcile_scan_and_job(scan: Scan, job: ScanJob, now: datetime) -> None:
    """Repair state drift without reviving terminal work or resetting attempts."""
    if scan.status in _TERMINAL_SCAN_STATES:
        job.status = _SCAN_TO_JOB[scan.status]
        job.locked_at = None
        return

    if job.status in _JOB_TO_SCAN and job.status in {"completed", "failed", "cancelled"}:
        scan.status = _JOB_TO_SCAN[job.status]
        scan.stage = {"completed": "Completed", "failed": "Failed", "cancelled": "Cancelled"}[job.status]
        scan.completed_at = scan.completed_at or now
        job.locked_at = None
        return

    if job.status == "processing":
        scan.status = "processing"
        scan.started_at = scan.started_at or job.locked_at or now
        if scan.stage in {"Queued", "Retry scheduled", "Queued by monitoring"}:
            scan.stage = "Generating SBOM"
        return

    job.status = "queued"
    job.locked_at = None
    scan.status = "queued"
    if scan.stage not in {"Queued by monitoring", "Retry scheduled"}:
        scan.stage = "Queued"


def enqueue_scan_job(db: Session, scan: Scan, max_attempts: int = 3) -> tuple[ScanJob, bool]:
    """Create exactly one job for a scan, returning the existing row on replay.

    PostgreSQL and SQLite use their native ON CONFLICT DO NOTHING operation,
    leaving the unique scan_id constraint as the final concurrency guard. The
    existing job and scan are then locked in the same order used by the worker
    and cancellation path before state is reconciled.
    """
    if scan.id is None:
        db.flush()
    scan_id = scan.id
    now = datetime.now(timezone.utc)
    initial_status = _SCAN_TO_JOB.get(scan.status, "queued")
    values = {
        "id": uuid4(),
        "scan_id": scan_id,
        "status": initial_status,
        "attempts": 1 if initial_status == "processing" else 0,
        "max_attempts": max_attempts,
        "available_at": now,
        "locked_at": (scan.started_at or now) if initial_status == "processing" else None,
        "last_error": None,
        "created_at": now,
    }

    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        statement = postgresql_insert(ScanJob.__table__).values(**values).on_conflict_do_nothing(
            index_elements=[ScanJob.scan_id]
        )
        inserted = db.execute(statement.returning(ScanJob.id)).scalar_one_or_none() is not None
    elif dialect == "sqlite":
        statement = sqlite_insert(ScanJob.__table__).values(**values).on_conflict_do_nothing(
            index_elements=[ScanJob.scan_id]
        )
        inserted = db.execute(statement.returning(ScanJob.id)).scalar_one_or_none() is not None
    else:
        # Keep a transactional fallback for other SQLAlchemy dialects. The
        # supported production and test databases take the atomic upsert path.
        existing = db.scalar(select(ScanJob).where(ScanJob.scan_id == scan_id).with_for_update())
        inserted = existing is None
        if inserted:
            db.add(ScanJob(**values))
            db.flush()

    job = db.scalar(
        select(ScanJob).where(ScanJob.scan_id == scan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if job is None:
        raise RuntimeError("Scan job could not be created or retrieved")

    locked_scan = db.scalar(
        select(Scan).where(Scan.id == scan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked_scan is None:
        raise RuntimeError("Cannot enqueue a scan job without its scan")

    _reconcile_scan_and_job(locked_scan, job, now)
    return job, inserted
