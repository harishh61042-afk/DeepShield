"""Real PostgreSQL checks. Requires a dedicated database named *_test."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import make_url

from app.core.config import settings
from app.models.entities import Component, MonitoringSchedule, Project, Scan, ScanJob, User
from app.scan_jobs import enqueue_scan_job


TEST_DATABASE_URL = os.getenv("DEPSHIELD_TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not TEST_DATABASE_URL, reason="DEPSHIELD_TEST_DATABASE_URL is not configured")


def _database_url():
    url = make_url(TEST_DATABASE_URL)
    if url.get_backend_name() != "postgresql" or not (url.database or "").lower().endswith("_test"):
        pytest.fail("PostgreSQL integration tests require a dedicated database whose name ends with _test")
    return url


def test_postgresql_idempotent_enqueue_concurrency_worker_lifecycle_and_restart(monkeypatch):
    url = _database_url()
    schema = f"qa_{uuid4().hex}"
    admin_engine = create_engine(url, pool_pre_ping=True)
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    admin_engine.dispose()
    isolated_url = url.update_query_dict({"options": f"-csearch_path={schema}"})
    monkeypatch.setattr(settings, "database_url", isolated_url.render_as_string(hide_password=False))
    command.upgrade(Config("alembic.ini"), "head")
    engine = create_engine(isolated_url, pool_pre_ping=True)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    from app.workers import scan_worker

    previous_factory = scan_worker.SessionLocal
    scan_worker.SessionLocal = factory
    try:
        tables = set(inspect(engine).get_table_names())
        assert {"imported_sboms", "project_security_policies", "monitoring_schedules", "notifications", "license_evidence"} <= tables
        columns = {column["name"] for column in inspect(engine).get_columns("scans")}
        assert "policy_result" in columns
        assert "affected_ranges" in {column["name"] for column in inspect(engine).get_columns("scan_findings")}
        unique_constraints = inspect(engine).get_unique_constraints("scan_jobs")
        assert any(
            item["name"] == "scan_jobs_scan_id_key" and item["column_names"] == ["scan_id"]
            for item in unique_constraints
        ), "The one-job-per-scan unique constraint must remain installed"

        suffix = uuid4().hex
        with factory() as db:
            user = User(email=f"pg-{suffix}@example.test", display_name="Postgres integration", password_hash="fixture", role="developer")
            db.add(user)
            db.flush()
            project = Project(owner_id=user.id, name=f"PG {suffix}", ecosystem="python")
            db.add(project)
            db.flush()
            scan = Scan(project_id=project.id, requested_by=user.id, status="queued", stage="Queued",
                        source_filename="requirements.txt", source_sha256="d" * 64, source_bytes=10)
            db.add(scan)
            db.flush()
            component = Component(scan_id=scan.id, name="demo", version="1.0", ecosystem="PyPI",
                                  directness="direct", resolution="resolved", manifest="requirements.txt", dependencies=[])
            db.add(component)
            schedule = MonitoringSchedule(project_id=project.id, interval_hours=24, active=True,
                                          next_run_at=scan.created_at)
            db.add(schedule)
            ids = user.id, project.id, scan.id
            db.commit()

        def enqueue_duplicate(_):
            with factory() as db:
                scan = db.get(Scan, ids[2])
                assert scan is not None
                job, inserted = enqueue_scan_job(db, scan)
                db.commit()
                return job.id, inserted

        with ThreadPoolExecutor(max_workers=8) as pool:
            submissions = list(pool.map(enqueue_duplicate, range(8)))
        job_ids = {job_id for job_id, _ in submissions}
        assert len(job_ids) == 1, "Concurrent submissions for one scan must all reuse one job ID"
        assert sum(inserted for _, inserted in submissions) == 1, "Exactly one concurrent enqueue may insert a job"
        job_id = next(iter(job_ids))

        with factory() as db:
            scan = db.get(Scan, ids[2])
            assert scan is not None
            repeated, inserted = enqueue_scan_job(db, scan)
            assert not inserted and repeated.id == job_id
            assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == ids[2])) == 1
            db.commit()

        def claim():
            return scan_worker.claim_job()

        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda _: claim(), range(2)))
        claimed = [item for item in claims if item]
        assert len(claimed) == 1, "Concurrent workers must claim only one active job for this scan"
        assert claimed[0][0] == job_id and claimed[0][2] == 1

        scan_worker.fail_job(job_id, ids[2], RuntimeError("integration retry"), attempts=1, max_attempts=3)
        with factory() as db:
            job = db.get(ScanJob, job_id)
            scan = db.get(Scan, ids[2])
            assert job and job.status == "queued" and job.attempts == 1
            assert scan and scan.status == "queued" and scan.stage == "Retry scheduled"
            assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == ids[2])) == 1
            job.available_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        retried = scan_worker.claim_job()
        assert retried and retried[0] == job_id and retried[2] == 2
        with factory() as db:
            job = db.get(ScanJob, job_id)
            assert job and job.status == "processing" and job.attempts == 2
            job.locked_at = datetime.now(timezone.utc) - timedelta(hours=1)
            db.commit()

        recovered = scan_worker.claim_job()
        assert recovered and recovered[0] == job_id and recovered[2] == 3, \
            "A stale processing lock must recover the same job after worker restart"
        scan_worker.fail_job(job_id, ids[2], RuntimeError("max attempts"), attempts=3, max_attempts=3)
        with factory() as db:
            job = db.get(ScanJob, job_id)
            scan = db.get(Scan, ids[2])
            assert job and job.status == "failed" and job.locked_at is None
            assert scan and scan.status == "failed" and scan.completed_at is not None
            assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == ids[2])) == 1

        with factory() as db:
            cancelled = Scan(project_id=ids[1], requested_by=ids[0], status="cancelled", stage="Cancelled",
                             source_filename="requirements.txt", source_sha256="e" * 64, source_bytes=10,
                             completed_at=datetime.now(timezone.utc))
            db.add(cancelled)
            db.flush()
            cancelled_id = cancelled.id
            cancelled_job, inserted = enqueue_scan_job(db, cancelled)
            assert inserted and cancelled_job.status == "cancelled"
            cancelled_job.status = "processing"
            cancelled_job.attempts = 1
            cancelled_job.locked_at = datetime.now(timezone.utc) - timedelta(hours=1)
            db.commit()
            cancelled_job_id = cancelled_job.id

        assert scan_worker.claim_job() is None, "Restart recovery must not revive a cancelled scan"
        scan_worker.fail_job(cancelled_job_id, cancelled_id, RuntimeError("late cancellation race"), attempts=1, max_attempts=3)
        with factory() as db:
            cancelled = db.get(Scan, cancelled_id)
            cancelled_job = db.get(ScanJob, cancelled_job_id)
            assert cancelled and cancelled.status == "cancelled"
            assert cancelled_job and cancelled_job.status == "cancelled" and cancelled_job.locked_at is None
            assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == cancelled_id)) == 1
    finally:
        scan_worker.SessionLocal = previous_factory
        engine.dispose()

