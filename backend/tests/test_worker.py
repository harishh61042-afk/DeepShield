from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.entities import Component, Finding, Project, Scan, ScanJob, User, Vulnerability
from app.parsers.dependencies import parse_package_lock
from app.workers import scan_worker


def make_database():
    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return engine, factory


def seed_job(factory):
    component_data = parse_package_lock(
        {"lockfileVersion": 3, "packages": {"node_modules/demo-package": {"version": "1.0.0"}}}
    )[0]
    with factory() as db:
        user = User(email="worker@example.com", display_name="Worker test", password_hash="test-only")
        db.add(user)
        db.flush()
        project = Project(owner_id=user.id, name="Worker test project", ecosystem="javascript")
        db.add(project)
        db.flush()
        scan = Scan(
            project_id=project.id,
            requested_by=user.id,
            status="queued",
            stage="Queued",
            source_filename="package-lock.json",
            source_sha256="a" * 64,
            source_bytes=100,
        )
        db.add(scan)
        db.flush()
        db.add(Component(scan_id=scan.id, **component_data))
        job = ScanJob(scan_id=scan.id, status="queued", attempts=0, max_attempts=3)
        db.add(job)
        db.commit()
        return scan.id, job.id


def test_worker_persists_sbom_findings_and_terminal_status(monkeypatch):
    engine, factory = make_database()
    monkeypatch.setattr(scan_worker, "SessionLocal", factory)
    advisory = {
        "id": "OSV-QA-ONLY-1",
        "aliases": [],
        "summary": "Worker test fixture only",
        "details": "This synthetic record is used only to exercise persistence.",
        "affected": [{
            "package": {"name": "demo-package", "ecosystem": "npm"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
        }],
        "references": [],
    }
    monkeypatch.setattr(scan_worker, "query_components_cached", lambda db, components, deadline=None: ({0: [advisory]}, "available"))
    monkeypatch.setattr(scan_worker, "load_kev", lambda deadline=None: (set(), "available"))
    scan_id, job_id = seed_job(factory)
    try:
        assert scan_worker.run_once() is True
        with factory() as db:
            scan = db.get(Scan, scan_id)
            job = db.get(ScanJob, job_id)
            finding = db.scalar(select(Finding).where(Finding.scan_id == scan_id))
            vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.osv_id == "OSV-QA-ONLY-1"))
            assert scan is not None and scan.status == "completed"
            assert scan.sbom_json["bomFormat"] == "CycloneDX"
            assert scan.sbom_json["specVersion"] == "1.6"
            assert job is not None and job.status == "completed" and job.locked_at is None
            assert finding is not None and finding.fixed_versions == ["1.0.1"]
            assert finding.priority == "Unknown" and finding.risk_score is None
            assert vulnerability is not None and vulnerability.summary == "Worker test fixture only"
    finally:
        engine.dispose()


def test_worker_retry_and_final_failure_update_scan_state(monkeypatch):
    engine, factory = make_database()
    scan_id, job_id = seed_job(factory)
    monkeypatch.setattr(scan_worker, "SessionLocal", factory)
    try:
        first = scan_worker.claim_job()
        assert first and first[0] == job_id and first[2] == 1
        scan_worker.fail_job(job_id, scan_id, RuntimeError("test-only failure"), attempts=1, max_attempts=3)
        with factory() as db:
            scan = db.get(Scan, scan_id)
            job = db.get(ScanJob, job_id)
            assert job is not None and job.status == "queued"
            assert scan is not None and scan.status == "queued" and scan.stage == "Retry scheduled"
            assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == scan_id)) == 1
            job.available_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        retry = scan_worker.claim_job()
        assert retry and retry[0] == job_id and retry[2] == 2
        with factory() as db:
            job = db.get(ScanJob, job_id)
            assert job is not None
            job.locked_at = datetime.now(timezone.utc) - timedelta(hours=1)
            db.commit()
        recovered = scan_worker.claim_job()
        assert recovered and recovered[0] == job_id and recovered[2] == 3
        scan_worker.fail_job(job_id, scan_id, RuntimeError("test-only failure"), attempts=3, max_attempts=3)
        with factory() as db:
            scan = db.get(Scan, scan_id)
            job = db.get(ScanJob, job_id)
            assert job is not None and job.status == "failed" and job.last_error == "RuntimeError"
            assert scan is not None and scan.status == "failed" and scan.completed_at is not None
            assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == scan_id)) == 1
    finally:
        engine.dispose()


def test_worker_restart_does_not_requeue_a_cancelled_scan(monkeypatch):
    engine, factory = make_database()
    scan_id, job_id = seed_job(factory)
    monkeypatch.setattr(scan_worker, "SessionLocal", factory)
    try:
        with factory() as db:
            scan = db.get(Scan, scan_id)
            job = db.get(ScanJob, job_id)
            assert scan is not None and job is not None
            scan.status = "cancelled"
            scan.stage = "Cancelled"
            job.status = "processing"
            job.attempts = 1
            job.locked_at = datetime.now(timezone.utc) - timedelta(hours=1)
            db.commit()

        assert scan_worker.claim_job() is None
        scan_worker.fail_job(job_id, scan_id, RuntimeError("late worker error"), attempts=1, max_attempts=3)
        with factory() as db:
            scan = db.get(Scan, scan_id)
            job = db.get(ScanJob, job_id)
            assert scan is not None and scan.status == "cancelled"
            assert job is not None and job.status == "cancelled" and job.locked_at is None
            assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == scan_id)) == 1
    finally:
        engine.dispose()
