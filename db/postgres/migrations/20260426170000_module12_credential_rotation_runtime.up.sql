CREATE TABLE IF NOT EXISTS integration_api_credentials (
    key_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    scopes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_ips_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    rotated_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credential_rotation_state (
    credential_id TEXT PRIMARY KEY,
    credential_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    last_rotated_at TIMESTAMPTZ,
    next_rotation_due_at TIMESTAMPTZ NOT NULL,
    last_attempt_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    active_version TEXT,
    last_error TEXT,
    manual_intervention_reason TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_credential_rotation_due
    ON credential_rotation_state (status, next_rotation_due_at);
