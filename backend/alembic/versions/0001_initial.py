"""Initial DepShield relational schema.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("users",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False), sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False), sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.CheckConstraint("role in ('developer','administrator','auditor')", name="ck_user_role"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("email"))
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_role", "users", ["role"])

    op.create_table("sessions",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("token_hash"))
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.create_table("password_reset_tokens",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("token_hash"))
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])
    op.create_index("ix_password_reset_tokens_token_hash", "password_reset_tokens", ["token_hash"])

    op.create_table("projects",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("owner_id", sa.Uuid(), nullable=False), sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False), sa.Column("ecosystem", sa.String(40), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_projects_owner_id", "projects", ["owner_id"])

    op.create_table("project_members",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("project_id", sa.Uuid(), nullable=False), sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("access", sa.String(20), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("access = 'auditor'", name="ck_member_readonly"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("project_id", "user_id"))
    op.create_index("ix_project_members_project_id", "project_members", ["project_id"])
    op.create_index("ix_project_members_user_id", "project_members", ["user_id"])

    op.create_table("scans",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("project_id", sa.Uuid(), nullable=False), sa.Column("requested_by", sa.Uuid()),
        sa.Column("status", sa.String(30), nullable=False), sa.Column("stage", sa.String(60), nullable=False),
        sa.Column("source_filename", sa.String(255), nullable=False), sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("source_bytes", sa.Integer(), nullable=False), sa.Column("sbom_json", sa.JSON()), sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)), sa.Column("intelligence_status", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.String(500)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])

    op.create_table("scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("scan_id", sa.Uuid(), nullable=False), sa.Column("status", sa.String(20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False), sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False), sa.Column("locked_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(500)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("scan_id"))
    op.create_index("ix_scan_jobs_scan_id", "scan_jobs", ["scan_id"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_available_at", "scan_jobs", ["available_at"])

    op.create_table("scan_components",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("scan_id", sa.Uuid(), nullable=False), sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(255)), sa.Column("version_constraint", sa.String(255)), sa.Column("ecosystem", sa.String(40), nullable=False),
        sa.Column("purl", sa.String(700)), sa.Column("directness", sa.String(20), nullable=False), sa.Column("resolution", sa.String(30), nullable=False),
        sa.Column("manifest", sa.String(255), nullable=False), sa.Column("license", sa.String(255)), sa.Column("dependencies", sa.JSON(), nullable=False),
        sa.CheckConstraint("directness in ('direct','transitive','unknown')", name="ck_component_directness"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_scan_components_scan_id", "scan_components", ["scan_id"])
    op.create_index("ix_scan_components_ecosystem", "scan_components", ["ecosystem"])
    op.create_index("ix_component_scan_purl", "scan_components", ["scan_id", "purl"])

    op.create_table("vulnerabilities",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("osv_id", sa.String(100), nullable=False), sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=False), sa.Column("details", sa.Text(), nullable=False),
        sa.Column("published", sa.String(40)), sa.Column("modified", sa.String(40)), sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("nvd_description", sa.Text()), sa.Column("cwes", sa.JSON(), nullable=False),
        sa.Column("nvd_published", sa.String(40)), sa.Column("nvd_modified", sa.String(40)),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=False), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("osv_id"))
    op.create_index("ix_vulnerabilities_osv_id", "vulnerabilities", ["osv_id"])

    op.create_table("intelligence_cache",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("source", sa.String(20), nullable=False),
        sa.Column("cache_key", sa.String(64), nullable=False), sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("source", "cache_key"))
    op.create_index("ix_intelligence_cache_source", "intelligence_cache", ["source"])
    op.create_index("ix_intelligence_cache_expires_at", "intelligence_cache", ["expires_at"])

    op.create_table("scan_findings",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("scan_id", sa.Uuid(), nullable=False), sa.Column("component_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False), sa.Column("cvss", sa.Float()), sa.Column("official_severity", sa.String(20), nullable=False),
        sa.Column("kev_status", sa.String(20), nullable=False), sa.Column("fixed_versions", sa.JSON(), nullable=False), sa.Column("risk_score", sa.Integer()),
        sa.Column("priority", sa.String(20), nullable=False), sa.Column("risk_factors", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["component_id"], ["scan_components.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("scan_id", "component_id", "vulnerability_id"))
    op.create_index("ix_scan_findings_scan_id", "scan_findings", ["scan_id"])
    op.create_index("ix_scan_findings_component_id", "scan_findings", ["component_id"])
    op.create_index("ix_scan_findings_vulnerability_id", "scan_findings", ["vulnerability_id"])

    op.create_table("audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("actor_id", sa.Uuid()), sa.Column("action", sa.String(80), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=False), sa.Column("target_id", sa.String(80)), sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade():
    op.drop_table("audit_logs")
    op.drop_table("scan_findings")
    op.drop_table("intelligence_cache")
    op.drop_table("vulnerabilities")
    op.drop_table("scan_components")
    op.drop_table("scan_jobs")
    op.drop_table("scans")
    op.drop_table("project_members")
    op.drop_table("projects")
    op.drop_table("password_reset_tokens")
    op.drop_table("sessions")
    op.drop_table("users")
