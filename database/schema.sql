BEGIN;

CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 0001_initial

CREATE TABLE users (
    id UUID NOT NULL, 
    email VARCHAR(320) NOT NULL, 
    display_name VARCHAR(100) NOT NULL, 
    password_hash VARCHAR(255) NOT NULL, 
    role VARCHAR(20) NOT NULL, 
    is_active BOOLEAN NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT ck_user_role CHECK (role in ('developer','administrator','auditor')), 
    UNIQUE (email)
);

CREATE INDEX ix_users_email ON users (email);

CREATE INDEX ix_users_role ON users (role);

CREATE TABLE sessions (
    id UUID NOT NULL, 
    user_id UUID NOT NULL, 
    token_hash VARCHAR(64) NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    revoked_at TIMESTAMP WITH TIME ZONE, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
    UNIQUE (token_hash)
);

CREATE INDEX ix_sessions_user_id ON sessions (user_id);

CREATE INDEX ix_sessions_token_hash ON sessions (token_hash);

CREATE INDEX ix_sessions_expires_at ON sessions (expires_at);

CREATE TABLE password_reset_tokens (
    id UUID NOT NULL, 
    user_id UUID NOT NULL, 
    token_hash VARCHAR(64) NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    used_at TIMESTAMP WITH TIME ZONE, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
    UNIQUE (token_hash)
);

CREATE INDEX ix_password_reset_tokens_user_id ON password_reset_tokens (user_id);

CREATE INDEX ix_password_reset_tokens_token_hash ON password_reset_tokens (token_hash);

CREATE TABLE projects (
    id UUID NOT NULL, 
    owner_id UUID NOT NULL, 
    name VARCHAR(120) NOT NULL, 
    description VARCHAR(1000) NOT NULL, 
    ecosystem VARCHAR(40) NOT NULL, 
    archived BOOLEAN NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(owner_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX ix_projects_owner_id ON projects (owner_id);

CREATE TABLE project_members (
    id UUID NOT NULL, 
    project_id UUID NOT NULL, 
    user_id UUID NOT NULL, 
    access VARCHAR(20) NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT ck_member_readonly CHECK (access = 'auditor'), 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE, 
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
    UNIQUE (project_id, user_id)
);

CREATE INDEX ix_project_members_project_id ON project_members (project_id);

CREATE INDEX ix_project_members_user_id ON project_members (user_id);

CREATE TABLE scans (
    id UUID NOT NULL, 
    project_id UUID NOT NULL, 
    requested_by UUID, 
    status VARCHAR(30) NOT NULL, 
    stage VARCHAR(60) NOT NULL, 
    source_filename VARCHAR(255) NOT NULL, 
    source_sha256 VARCHAR(64) NOT NULL, 
    source_bytes INTEGER NOT NULL, 
    sbom_json JSON, 
    started_at TIMESTAMP WITH TIME ZONE, 
    completed_at TIMESTAMP WITH TIME ZONE, 
    intelligence_status JSON NOT NULL, 
    error_message VARCHAR(500), 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE, 
    FOREIGN KEY(requested_by) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_scans_project_id ON scans (project_id);

CREATE INDEX ix_scans_status ON scans (status);

CREATE INDEX ix_scans_created_at ON scans (created_at);

CREATE TABLE scan_jobs (
    id UUID NOT NULL, 
    scan_id UUID NOT NULL, 
    status VARCHAR(20) NOT NULL, 
    attempts INTEGER NOT NULL, 
    max_attempts INTEGER NOT NULL, 
    available_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    locked_at TIMESTAMP WITH TIME ZONE, 
    last_error VARCHAR(500), 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
    UNIQUE (scan_id)
);

CREATE INDEX ix_scan_jobs_scan_id ON scan_jobs (scan_id);

CREATE INDEX ix_scan_jobs_status ON scan_jobs (status);

CREATE INDEX ix_scan_jobs_available_at ON scan_jobs (available_at);

CREATE TABLE scan_components (
    id UUID NOT NULL, 
    scan_id UUID NOT NULL, 
    name VARCHAR(255) NOT NULL, 
    version VARCHAR(255), 
    version_constraint VARCHAR(255), 
    ecosystem VARCHAR(40) NOT NULL, 
    purl VARCHAR(700), 
    directness VARCHAR(20) NOT NULL, 
    resolution VARCHAR(30) NOT NULL, 
    manifest VARCHAR(255) NOT NULL, 
    license VARCHAR(255), 
    dependencies JSON NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT ck_component_directness CHECK (directness in ('direct','transitive','unknown')), 
    FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_scan_components_scan_id ON scan_components (scan_id);

CREATE INDEX ix_scan_components_ecosystem ON scan_components (ecosystem);

CREATE INDEX ix_component_scan_purl ON scan_components (scan_id, purl);

CREATE TABLE vulnerabilities (
    id UUID NOT NULL, 
    osv_id VARCHAR(100) NOT NULL, 
    aliases JSON NOT NULL, 
    summary VARCHAR(1000) NOT NULL, 
    details TEXT NOT NULL, 
    published VARCHAR(40), 
    modified VARCHAR(40), 
    "references" JSON NOT NULL, 
    nvd_description TEXT, 
    cwes JSON NOT NULL, 
    nvd_published VARCHAR(40), 
    nvd_modified VARCHAR(40), 
    source_updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (osv_id)
);

CREATE INDEX ix_vulnerabilities_osv_id ON vulnerabilities (osv_id);

CREATE TABLE intelligence_cache (
    id UUID NOT NULL, 
    source VARCHAR(20) NOT NULL, 
    cache_key VARCHAR(64) NOT NULL, 
    payload JSON NOT NULL, 
    fetched_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (source, cache_key)
);

CREATE INDEX ix_intelligence_cache_source ON intelligence_cache (source);

CREATE INDEX ix_intelligence_cache_expires_at ON intelligence_cache (expires_at);

CREATE TABLE scan_findings (
    id UUID NOT NULL, 
    scan_id UUID NOT NULL, 
    component_id UUID NOT NULL, 
    vulnerability_id UUID NOT NULL, 
    cvss FLOAT, 
    official_severity VARCHAR(20) NOT NULL, 
    kev_status VARCHAR(20) NOT NULL, 
    fixed_versions JSON NOT NULL, 
    risk_score INTEGER, 
    priority VARCHAR(20) NOT NULL, 
    risk_factors JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(component_id) REFERENCES scan_components (id) ON DELETE CASCADE, 
    FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities (id) ON DELETE RESTRICT, 
    UNIQUE (scan_id, component_id, vulnerability_id)
);

CREATE INDEX ix_scan_findings_scan_id ON scan_findings (scan_id);

CREATE INDEX ix_scan_findings_component_id ON scan_findings (component_id);

CREATE INDEX ix_scan_findings_vulnerability_id ON scan_findings (vulnerability_id);

CREATE TABLE audit_logs (
    id UUID NOT NULL, 
    actor_id UUID, 
    action VARCHAR(80) NOT NULL, 
    target_type VARCHAR(50) NOT NULL, 
    target_id VARCHAR(80), 
    outcome VARCHAR(20) NOT NULL, 
    metadata JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(actor_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_audit_logs_actor_id ON audit_logs (actor_id);

CREATE INDEX ix_audit_logs_action ON audit_logs (action);

CREATE INDEX ix_audit_logs_created_at ON audit_logs (created_at);

INSERT INTO alembic_version (version_num) VALUES ('0001_initial') RETURNING alembic_version.version_num;

-- Running upgrade 0001_initial -> 0002_security_center

ALTER TABLE scans ADD COLUMN policy_result JSON;

ALTER TABLE scan_findings ADD COLUMN affected_ranges JSON DEFAULT '[]' NOT NULL;

CREATE TABLE imported_sboms (
    id UUID NOT NULL, 
    project_id UUID NOT NULL, 
    uploaded_by UUID, 
    filename VARCHAR(255) NOT NULL, 
    spec_version VARCHAR(10) NOT NULL, 
    document JSON NOT NULL, 
    sha256 VARCHAR(64) NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE, 
    FOREIGN KEY(uploaded_by) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_imported_sboms_project_id ON imported_sboms (project_id);

CREATE INDEX ix_imported_sboms_created_at ON imported_sboms (created_at);

CREATE TABLE project_security_policies (
    project_id UUID NOT NULL, 
    max_allowed_priority VARCHAR(20) NOT NULL, 
    fail_on_kev BOOLEAN NOT NULL, 
    partial_behavior VARCHAR(10) NOT NULL, 
    unavailable_behavior VARCHAR(10) NOT NULL, 
    fail_on_unknown_license BOOLEAN NOT NULL, 
    allowed_licenses JSON NOT NULL, 
    restricted_licenses JSON NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (project_id), 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE
);

CREATE TABLE license_evidence (
    id UUID NOT NULL, 
    ecosystem VARCHAR(40) NOT NULL, 
    package_name VARCHAR(255) NOT NULL, 
    package_version VARCHAR(255) NOT NULL, 
    license_expression VARCHAR(500), 
    source_url VARCHAR(1000), 
    status VARCHAR(20) NOT NULL, 
    checked_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT uq_license_evidence_package UNIQUE (ecosystem, package_name, package_version)
);

CREATE TABLE monitoring_schedules (
    id UUID NOT NULL, 
    project_id UUID NOT NULL, 
    interval_hours INTEGER NOT NULL, 
    active BOOLEAN NOT NULL, 
    next_run_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    last_scan_id UUID, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT ck_monitoring_interval_hours CHECK (interval_hours >= 6 and interval_hours <= 720), 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE, 
    FOREIGN KEY(last_scan_id) REFERENCES scans (id) ON DELETE SET NULL, 
    UNIQUE (project_id)
);

CREATE INDEX ix_monitoring_schedules_project_id ON monitoring_schedules (project_id);

CREATE INDEX ix_monitoring_schedules_active ON monitoring_schedules (active);

CREATE INDEX ix_monitoring_schedules_next_run_at ON monitoring_schedules (next_run_at);

CREATE TABLE notification_preferences (
    user_id UUID NOT NULL, 
    email_enabled BOOLEAN NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (user_id), 
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE notifications (
    id UUID NOT NULL, 
    user_id UUID NOT NULL, 
    project_id UUID NOT NULL, 
    event_key VARCHAR(200) NOT NULL, 
    event_type VARCHAR(40) NOT NULL, 
    title VARCHAR(200) NOT NULL, 
    message VARCHAR(1000) NOT NULL, 
    payload JSON NOT NULL, 
    read_at TIMESTAMP WITH TIME ZONE, 
    email_status VARCHAR(20) NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE, 
    CONSTRAINT uq_notification_user_event UNIQUE (user_id, event_key)
);

CREATE INDEX ix_notifications_user_id ON notifications (user_id);

CREATE INDEX ix_notifications_project_id ON notifications (project_id);

CREATE INDEX ix_notifications_event_type ON notifications (event_type);

CREATE INDEX ix_notifications_created_at ON notifications (created_at);

UPDATE alembic_version SET version_num='0002_security_center' WHERE alembic_version.version_num = '0001_initial';

COMMIT;

