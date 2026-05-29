CREATE TABLE IF NOT EXISTS permission_eligibility_rules (
    rule_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    allowed_department_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_user_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_role_names_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    require_active_hr_record BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_permission_eligibility_rules_project
    ON permission_eligibility_rules (project_id);

ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS lifecycle_reason TEXT;

ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS lifecycle_trigger TEXT;

ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS lifecycle_transitioned_at TIMESTAMPTZ;

ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS lifecycle_source_event_id TEXT;

CREATE TABLE IF NOT EXISTS permission_grant_lifecycle_events (
    transition_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES permission_grants (grant_id) ON DELETE CASCADE,
    applicant_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    data_source_id TEXT NOT NULL REFERENCES data_sources (data_source_id) ON DELETE CASCADE,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    trigger TEXT NOT NULL,
    reason TEXT NOT NULL,
    source_event_id TEXT,
    audit_checkpoint_id TEXT,
    context_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_permission_grant_lifecycle_events_grant
    ON permission_grant_lifecycle_events (grant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_permission_grant_lifecycle_events_trigger
    ON permission_grant_lifecycle_events (trigger, created_at DESC);
