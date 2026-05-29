ALTER TABLE evidence_packages
    ADD COLUMN IF NOT EXISTS tenant_id TEXT,
    ADD COLUMN IF NOT EXISTS template TEXT,
    ADD COLUMN IF NOT EXISTS manifest_digest TEXT,
    ADD COLUMN IF NOT EXISTS watermark_token TEXT,
    ADD COLUMN IF NOT EXISTS package_json JSONB,
    ADD COLUMN IF NOT EXISTS file_name TEXT,
    ADD COLUMN IF NOT EXISTS media_type TEXT,
    ADD COLUMN IF NOT EXISTS created_by_user_id TEXT,
    ADD COLUMN IF NOT EXISTS task_id TEXT,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS export_tasks (
    task_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL,
    requested_by_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    package_id TEXT NOT NULL REFERENCES evidence_packages (package_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS download_authorizations (
    download_token TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES export_tasks (task_id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    issued_to_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_packages_task_id
    ON evidence_packages (task_id);

CREATE INDEX IF NOT EXISTS idx_export_tasks_scope
    ON export_tasks (tenant_id, project_id, requested_by_user_id, status);

CREATE INDEX IF NOT EXISTS idx_download_authorizations_task
    ON download_authorizations (task_id, expires_at, consumed_at);
