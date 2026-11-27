import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Uuid

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="developer", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    projects: Mapped[list["Project"]] = relationship(back_populates="owner", cascade="all, delete-orphan")

    __table_args__ = (CheckConstraint("role in ('developer','administrator','auditor')", name="ck_user_role"),)


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(1000), default="")
    ecosystem: Mapped[str] = mapped_column(String(40), default="mixed")
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    owner: Mapped[User] = relationship(back_populates="projects")
    members: Mapped[list["ProjectMember"]] = relationship(cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(cascade="all, delete-orphan")


class ProjectMember(Base):
    __tablename__ = "project_members"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    access: Mapped[str] = mapped_column(String(20), default="auditor")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("project_id", "user_id"), CheckConstraint("access = 'auditor'", name="ck_member_readonly"))


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(60), default="Queued")
    source_filename: Mapped[str] = mapped_column(String(255))
    source_sha256: Mapped[str] = mapped_column(String(64))
    source_bytes: Mapped[int] = mapped_column(Integer)
    sbom_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    intelligence_status: Mapped[dict] = mapped_column(JSON, default=dict)
    policy_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    components: Mapped[list["Component"]] = relationship(cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ImportedSBOM(Base):
    __tablename__ = "imported_sboms"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    filename: Mapped[str] = mapped_column(String(255))
    spec_version: Mapped[str] = mapped_column(String(10))
    document: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ProjectSecurityPolicy(Base):
    __tablename__ = "project_security_policies"
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    max_allowed_priority: Mapped[str] = mapped_column(String(20), default="High")
    fail_on_kev: Mapped[bool] = mapped_column(Boolean, default=True)
    partial_behavior: Mapped[str] = mapped_column(String(10), default="warning")
    unavailable_behavior: Mapped[str] = mapped_column(String(10), default="warning")
    fail_on_unknown_license: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_licenses: Mapped[list] = mapped_column(JSON, default=list)
    restricted_licenses: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class LicenseEvidence(Base):
    __tablename__ = "license_evidence"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ecosystem: Mapped[str] = mapped_column(String(40))
    package_name: Mapped[str] = mapped_column(String(255))
    package_version: Mapped[str] = mapped_column(String(255))
    license_expression: Mapped[str | None] = mapped_column(String(500))
    source_url: Mapped[str | None] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("ecosystem", "package_name", "package_version", name="uq_license_evidence_package"),)


class MonitoringSchedule(Base):
    __tablename__ = "monitoring_schedules"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), unique=True, index=True)
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    __table_args__ = (CheckConstraint("interval_hours >= 6 and interval_hours <= 720", name="ck_monitoring_interval_hours"),)


class NotificationPreference(Base):
    __tablename__ = "notification_preferences"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    email_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    event_key: Mapped[str] = mapped_column(String(200))
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(String(1000))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    email_status: Mapped[str] = mapped_column(String(20), default="not_requested")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    __table_args__ = (UniqueConstraint("user_id", "event_key", name="uq_notification_user_event"),)


class Component(Base):
    __tablename__ = "scan_components"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(255))
    version_constraint: Mapped[str | None] = mapped_column(String(255))
    ecosystem: Mapped[str] = mapped_column(String(40), index=True)
    purl: Mapped[str | None] = mapped_column(String(700))
    directness: Mapped[str] = mapped_column(String(20), default="unknown")
    resolution: Mapped[str] = mapped_column(String(30), default="resolved")
    manifest: Mapped[str] = mapped_column(String(255))
    license: Mapped[str | None] = mapped_column(String(255))
    dependencies: Mapped[list] = mapped_column(JSON, default=list)
    __table_args__ = (
        Index("ix_component_scan_purl", "scan_id", "purl"),
        CheckConstraint("directness in ('direct','transitive','unknown')", name="ck_component_directness"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    osv_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(String(1000), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    published: Mapped[str | None] = mapped_column(String(40))
    modified: Mapped[str | None] = mapped_column(String(40))
    references: Mapped[list] = mapped_column(JSON, default=list)
    nvd_description: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list] = mapped_column(JSON, default=list)
    nvd_published: Mapped[str | None] = mapped_column(String(40))
    nvd_modified: Mapped[str | None] = mapped_column(String(40))
    source_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntelligenceCache(Base):
    __tablename__ = "intelligence_cache"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(20), index=True)
    cache_key: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    __table_args__ = (UniqueConstraint("source", "cache_key"),)


class Finding(Base):
    __tablename__ = "scan_findings"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    component_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_components.id", ondelete="CASCADE"), index=True)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), index=True)
    cvss: Mapped[float | None] = mapped_column()
    official_severity: Mapped[str] = mapped_column(String(20), default="Unknown")
    kev_status: Mapped[str] = mapped_column(String(20), default="unknown")
    fixed_versions: Mapped[list] = mapped_column(JSON, default=list)
    affected_ranges: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    priority: Mapped[str] = mapped_column(String(20), default="Unknown")
    risk_factors: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    vulnerability: Mapped[Vulnerability] = relationship()
    component: Mapped[Component] = relationship()
    __table_args__ = (UniqueConstraint("scan_id", "component_id", "vulnerability_id"),)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str] = mapped_column(String(50), default="")
    target_id: Mapped[str | None] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(String(20), default="success")
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
