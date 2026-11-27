"""Additive storage for SBOM imports, policies, licenses and monitoring."""

from alembic import op
import sqlalchemy as sa


revision = "0002_security_center"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("policy_result", sa.JSON(), nullable=True))
    op.add_column("scan_findings", sa.Column("affected_ranges", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
    op.create_table(
        "imported_sboms",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("uploaded_by", sa.Uuid(), nullable=True),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("spec_version", sa.String(10), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_imported_sboms_project_id", "imported_sboms", ["project_id"])
    op.create_index("ix_imported_sboms_created_at", "imported_sboms", ["created_at"])

    op.create_table(
        "project_security_policies",
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("max_allowed_priority", sa.String(20), nullable=False),
        sa.Column("fail_on_kev", sa.Boolean(), nullable=False),
        sa.Column("partial_behavior", sa.String(10), nullable=False),
        sa.Column("unavailable_behavior", sa.String(10), nullable=False),
        sa.Column("fail_on_unknown_license", sa.Boolean(), nullable=False),
        sa.Column("allowed_licenses", sa.JSON(), nullable=False),
        sa.Column("restricted_licenses", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("project_id"),
    )

    op.create_table(
        "license_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ecosystem", sa.String(40), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("package_version", sa.String(255), nullable=False),
        sa.Column("license_expression", sa.String(500)),
        sa.Column("source_url", sa.String(1000)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ecosystem", "package_name", "package_version", name="uq_license_evidence_package"),
    )

    op.create_table(
        "monitoring_schedules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scan_id", sa.Uuid()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("interval_hours >= 6 and interval_hours <= 720", name="ck_monitoring_interval_hours"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id"),
    )
    op.create_index("ix_monitoring_schedules_project_id", "monitoring_schedules", ["project_id"])
    op.create_index("ix_monitoring_schedules_active", "monitoring_schedules", ["active"])
    op.create_index("ix_monitoring_schedules_next_run_at", "monitoring_schedules", ["next_run_at"])

    op.create_table(
        "notification_preferences",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("email_enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

    op.create_table(
        "notifications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("event_key", sa.String(200), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("message", sa.String(1000), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.Column("email_status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "event_key", name="uq_notification_user_event"),
    )
    for index, column in (("user_id", "user_id"), ("project_id", "project_id"), ("event_type", "event_type"), ("created_at", "created_at")):
        op.create_index(f"ix_notifications_{index}", "notifications", [column])


def downgrade():
    op.drop_table("notifications")
    op.drop_table("notification_preferences")
    op.drop_index("ix_monitoring_schedules_next_run_at", table_name="monitoring_schedules")
    op.drop_index("ix_monitoring_schedules_active", table_name="monitoring_schedules")
    op.drop_index("ix_monitoring_schedules_project_id", table_name="monitoring_schedules")
    op.drop_table("monitoring_schedules")
    op.drop_table("license_evidence")
    op.drop_table("project_security_policies")
    op.drop_index("ix_imported_sboms_created_at", table_name="imported_sboms")
    op.drop_index("ix_imported_sboms_project_id", table_name="imported_sboms")
    op.drop_table("imported_sboms")
    op.drop_column("scans", "policy_result")
    op.drop_column("scan_findings", "affected_ranges")
