CREATE TABLE IF NOT EXISTS analysis_templates (
    template_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    visibility TEXT NOT NULL,
    config_json JSONB NOT NULL,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_templates_scope_visibility
    ON analysis_templates (tenant_id, project_id, visibility, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_analysis_templates_owner_scope
    ON analysis_templates (project_id, owner_user_id, updated_at DESC);
