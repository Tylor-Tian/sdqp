ALTER TABLE snapshots
    ADD COLUMN IF NOT EXISTS payload_format TEXT NOT NULL DEFAULT 'json_rows',
    ADD COLUMN IF NOT EXISTS columns_json JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE snapshots
SET
    payload_format = COALESCE(payload_format, 'json_rows'),
    columns_json = COALESCE(columns_json, '[]'::jsonb);

CREATE TABLE IF NOT EXISTS classification_rule_versions (
    rule_version_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    status TEXT NOT NULL,
    rules_json JSONB NOT NULL,
    created_by_user_id TEXT REFERENCES users (user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, data_source_id, version_number)
);

CREATE TABLE IF NOT EXISTS classification_detection_runs (
    detection_run_id TEXT PRIMARY KEY,
    snapshot_id TEXT REFERENCES snapshots (snapshot_id) ON DELETE SET NULL,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    rule_version_id TEXT NOT NULL REFERENCES classification_rule_versions (rule_version_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    findings_json JSONB NOT NULL,
    confirmed_by_user_id TEXT REFERENCES users (user_id) ON DELETE SET NULL,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS classification_field_policies (
    policy_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    field_name TEXT NOT NULL,
    level TEXT NOT NULL,
    status TEXT NOT NULL,
    masking_strategy TEXT NOT NULL,
    watermark_strength TEXT NOT NULL,
    source TEXT NOT NULL,
    rule_version_id TEXT REFERENCES classification_rule_versions (rule_version_id) ON DELETE SET NULL,
    detection_run_id TEXT REFERENCES classification_detection_runs (detection_run_id) ON DELETE SET NULL,
    sample_value TEXT,
    pattern_hints_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    confirmed_by_user_id TEXT REFERENCES users (user_id) ON DELETE SET NULL,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, data_source_id, field_name)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_format_scope
    ON snapshots (project_id, data_source_id, payload_format);

CREATE INDEX IF NOT EXISTS idx_classification_rules_scope
    ON classification_rule_versions (project_id, data_source_id, status);

CREATE INDEX IF NOT EXISTS idx_classification_detection_runs_scope
    ON classification_detection_runs (project_id, data_source_id, status, created_at);

CREATE INDEX IF NOT EXISTS idx_classification_field_policies_scope
    ON classification_field_policies (project_id, data_source_id, status, updated_at);
