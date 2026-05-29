CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    password_secret TEXT NOT NULL,
    mfa_method TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    PRIMARY KEY (user_id, role_name)
);

CREATE TABLE IF NOT EXISTS project_memberships (
    membership_id BIGSERIAL PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    membership_role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, user_id, membership_role)
);

CREATE TABLE IF NOT EXISTS data_sources (
    data_source_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    capabilities_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS field_classifications (
    classification_id BIGSERIAL PRIMARY KEY,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    field_name TEXT NOT NULL,
    classification TEXT NOT NULL,
    UNIQUE (data_source_id, field_name)
);

CREATE TABLE IF NOT EXISTS permission_grants (
    grant_id TEXT PRIMARY KEY,
    applicant_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    fields_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    conditions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permission_applications (
    application_id TEXT PRIMARY KEY,
    applicant_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    requested_fields_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_flows (
    flow_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    definition_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_instances (
    instance_id TEXT PRIMARY KEY,
    application_id TEXT,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    flow_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_actions (
    action_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES approval_instances (instance_id) ON DELETE CASCADE,
    approver_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS query_tasks (
    task_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    project_scope_key TEXT NOT NULL,
    state TEXT NOT NULL,
    snapshot_id TEXT,
    cache_hit BOOLEAN NOT NULL DEFAULT FALSE,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    storage_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    row_count BIGINT NOT NULL,
    dek_id TEXT NOT NULL,
    encrypted_payload_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshot_cache_entries (
    cache_key TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots (snapshot_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    session_kind TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    binding_json JSONB NOT NULL,
    pending_account_json JSONB,
    claims_json JSONB,
    refresh_token TEXT,
    roles_json JSONB,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    step_up_required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS config_versions (
    version_id TEXT PRIMARY KEY,
    config_key TEXT NOT NULL,
    config_payload_json JSONB NOT NULL,
    approved_by_user_id TEXT REFERENCES users (user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS evidence_packages (
    package_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    snapshot_id TEXT REFERENCES snapshots (snapshot_id) ON DELETE SET NULL,
    manifest_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS watermark_jobs (
    job_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_query_tasks_scope ON query_tasks (tenant_id, project_id, user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id, session_kind);
CREATE INDEX IF NOT EXISTS idx_snapshots_scope ON snapshots (tenant_id, project_id, data_source_id);
