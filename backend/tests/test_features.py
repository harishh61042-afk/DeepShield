from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.features.licenses import evaluate_license_policy, fetch_registry_license, recognized_licenses
from app.features.monitoring import create_scan_notifications, enqueue_due_schedule
from app.features.policy import DEFAULT_POLICY, evaluate_scan_policy
from app.features.remediation import build_remediation_plan
from app.features.sbom import SBOMValidationError, compare_components, validate_cyclonedx
from app.models.entities import (Component, Finding, MonitoringSchedule, Notification, Project,
                                 Scan, ScanJob, User, Vulnerability)


def test_sbom_validation_accepts_supported_cyclonedx_and_rejects_invalid_versions_and_duplicate_refs():
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [{"type": "library", "name": "requests", "version": "2.31.0", "bom-ref": "pkg:pypi/requests@2.31.0"}]}
    assert validate_cyclonedx(document) is document
    with pytest.raises(SBOMValidationError, match="Supported CycloneDX"):
        validate_cyclonedx({**document, "specVersion": "1.3"})
    with pytest.raises(SBOMValidationError, match="unique"):
        validate_cyclonedx({**document, "components": [document["components"][0], document["components"][0]]})


def test_sbom_comparison_classifies_added_removed_and_version_changes():
    before = [{"type": "library", "name": "a", "purl": "pkg:npm/a@1.0.0", "version": "1.0.0"},
              {"type": "library", "name": "b", "purl": "pkg:npm/b@2.0.0", "version": "2.0.0"}]
    after = [{"type": "library", "name": "a", "purl": "pkg:npm/a@1.1.0", "version": "1.1.0"},
             {"type": "library", "name": "c", "purl": "pkg:npm/c@3.0.0", "version": "3.0.0"}]
    result = compare_components(before, after)
    assert result["counts"] == {"added": 1, "removed": 1, "changed": 1}
    assert result["changed"][0]["before"]["version"] == "1.0.0"
    assert result["changed"][0]["after"]["version"] == "1.1.0"


def test_policy_gate_fails_for_over_limit_and_never_passes_partial_as_clean():
    scan = SimpleNamespace(id="scan-1", project_id="project-1", status="partial",
                           intelligence_status={"osv": "partial", "cisa_kev": "cached"})
    result = evaluate_scan_policy(scan, [{"priority": "Critical", "kev_status": "known"}], DEFAULT_POLICY)
    assert result["status"] == "FAIL"
    assert any("exceed" in message for message in result["failures"])
    warning = evaluate_scan_policy(scan, [], {**DEFAULT_POLICY, "partial_behavior": "warning"})
    assert warning["status"] == "WARNING"
    assert any("not conclusive" in message for message in warning["warnings"])


def test_license_policy_keeps_unrecognized_values_for_review():
    assert recognized_licenses("MIT OR Apache-2.0") == ["Apache-2.0", "MIT"]
    rows = [{"name": "known", "recognized_licenses": ["MIT"]},
            {"name": "unknown", "recognized_licenses": []}]
    result = evaluate_license_policy(rows, {"allowed_licenses": ["MIT"], "restricted_licenses": []})
    assert result["status"] == "review_required"
    assert [row["name"] for row in result["unknown"]] == ["unknown"]


def test_license_metadata_lookup_rejects_url_path_control_before_network(monkeypatch):
    calls = []
    monkeypatch.setattr("app.features.licenses.httpx.get", lambda *args, **kwargs: calls.append(args[0]))
    rejected = fetch_registry_license("npm", "../../malicious", "1.0.0")
    assert rejected == {"license": None, "status": "unavailable", "source_url": None}
    assert calls == []


def test_remediation_uses_only_single_fixed_version_as_target():
    scan = SimpleNamespace(id="scan-1", status="completed")
    finding = {"id": "finding-1", "component": {"name": "lib", "version": "1.0", "ecosystem": "npm", "resolution": "resolved"},
               "vulnerability": {"osv_id": "GHSA-test", "summary": "Test issue"}, "fixed_versions": ["1.2.0"],
               "affected_ranges": [{"type": "SEMVER", "events": [{"introduced": "0", "fixed": "1.2.0"}]}],
               "priority": "High", "official_severity": "High", "kev_status": "not_listed"}
    plan = build_remediation_plan(scan, [finding])
    item = plan["groups"]["high"][0]
    assert item["recommended_target"] == "1.2.0"
    assert item["affected_ranges"]
    finding["fixed_versions"] = ["1.2.0", "2.0.0"]
    plan = build_remediation_plan(scan, [finding])
    item = plan["groups"]["needs_evidence"][0]
    assert item["recommended_target"] is None


@pytest.fixture
def db_factory():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        yield factory
    finally:
        engine.dispose()


def seed_project(factory):
    with factory() as db:
        user = User(email="monitor@example.com", display_name="Monitor", password_hash="test", role="developer")
        db.add(user)
        db.flush()
        project = Project(owner_id=user.id, name="Monitored", ecosystem="npm")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, requested_by=user.id, status="completed", stage="Completed",
                    source_filename="package-lock.json", source_sha256="a" * 64, source_bytes=40,
                    intelligence_status={"osv": "available", "cisa_kev": "available"},
                    completed_at=datetime.now(timezone.utc) - timedelta(days=1),
                    created_at=datetime.now(timezone.utc) - timedelta(days=1))
        db.add(scan)
        db.flush()
        db.add(Component(scan_id=scan.id, name="safe-lib", version="1.0.0", ecosystem="npm", purl="pkg:npm/safe-lib@1.0.0",
                         directness="direct", resolution="resolved", manifest="package-lock.json", dependencies=[]))
        schedule = MonitoringSchedule(project_id=project.id, interval_hours=6, active=True,
                                      next_run_at=datetime.now(timezone.utc) - timedelta(hours=1))
        db.add(schedule)
        db.commit()
        return user.id, project.id, scan.id


def test_due_monitoring_schedule_enqueues_one_durable_scan_job(db_factory):
    _, project_id, _ = seed_project(db_factory)
    now = datetime.now(timezone.utc)
    with db_factory() as db:
        assert enqueue_due_schedule(db, now)
        assert not enqueue_due_schedule(db, now)
        scans = db.scalars(select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at)).all()
        assert len(scans) == 2
        scheduled = scans[-1]
        assert scheduled.source_filename.startswith("scheduled-")
        assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == scheduled.id)) == 1
        schedule = db.scalar(select(MonitoringSchedule).where(MonitoringSchedule.project_id == project_id))
        assert schedule.last_scan_id == scheduled.id


def test_partial_scan_does_not_emit_resolution_and_alerts_are_idempotent(db_factory):
    user_id, project_id, previous_id = seed_project(db_factory)
    with db_factory() as db:
        previous = db.get(Scan, previous_id)
        component = db.scalar(select(Component).where(Component.scan_id == previous.id))
        vuln = Vulnerability(osv_id="OSV-ALERT-1", aliases=[], summary="Alert test", details="", references=[], cwes=[])
        db.add(vuln)
        db.flush()
        db.add(Finding(scan_id=previous.id, component_id=component.id, vulnerability_id=vuln.id,
                       kev_status="not_listed", priority="High", fixed_versions=[], affected_ranges=[], risk_factors={}))
        current = Scan(project_id=project_id, status="partial", stage="Partial", source_filename="scheduled-lock.json",
                       source_sha256="a" * 64, source_bytes=40, intelligence_status={"osv": "partial"},
                       created_at=datetime.now(timezone.utc))
        db.add(current)
        db.commit()
        assert create_scan_notifications(db, current) == 0
        assert db.scalar(select(func.count(Notification.id))) == 0
        current.status = "completed"
        current.intelligence_status = {"osv": "available", "cisa_kev": "available"}
        db.commit()
        assert create_scan_notifications(db, current) == 1
        assert create_scan_notifications(db, current) == 0
        rows = db.scalars(select(Notification).where(Notification.user_id == user_id)).all()
        assert len(rows) == 1
        assert rows[0].event_type == "resolved"

