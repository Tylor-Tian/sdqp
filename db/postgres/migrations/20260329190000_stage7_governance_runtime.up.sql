ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '8 hours');

ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS org_binding_json JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE permission_grants
    ADD COLUMN IF NOT EXISTS approval_instance_id TEXT REFERENCES approval_instances (instance_id) ON DELETE SET NULL;

ALTER TABLE permission_applications
    ADD COLUMN IF NOT EXISTS approval_instance_id TEXT REFERENCES approval_instances (instance_id) ON DELETE SET NULL;

ALTER TABLE permission_applications
    ADD COLUMN IF NOT EXISTS merge_key TEXT NOT NULL DEFAULT '';

ALTER TABLE permission_applications
    ADD COLUMN IF NOT EXISTS merged_into_application_id TEXT REFERENCES permission_applications (application_id) ON DELETE SET NULL;

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS applicant_user_id TEXT REFERENCES users (user_id) ON DELETE CASCADE;

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS data_source_id TEXT REFERENCES data_sources (data_source_id) ON DELETE CASCADE;

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS flow_id_ref TEXT NOT NULL DEFAULT '';

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS request_json JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS step_states_json JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS audit_log_json JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS current_step_index INTEGER NOT NULL DEFAULT 0;

ALTER TABLE approval_instances
    ADD COLUMN IF NOT EXISTS approval_key TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_permission_grants_scope_status
    ON permission_grants (applicant_user_id, project_id, data_source_id, status);

CREATE INDEX IF NOT EXISTS idx_permission_grants_valid_until
    ON permission_grants (status, valid_until);

CREATE INDEX IF NOT EXISTS idx_permission_applications_merge
    ON permission_applications (merge_key, status, updated_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_instances_active_key
    ON approval_instances (approval_key)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS hr_directory_users (
    user_id TEXT PRIMARY KEY REFERENCES users (user_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    department_id TEXT NOT NULL,
    manager_id TEXT,
    status TEXT NOT NULL,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hr_sync_events (
    event_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notification_deliveries (
    delivery_id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES approval_instances (instance_id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_due
    ON notification_deliveries (status, next_attempt_at, created_at);
