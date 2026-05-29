ALTER TABLE users
    ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_id TEXT,
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS auth_source TEXT NOT NULL DEFAULT 'local_password';

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id
    ON users (external_id)
    WHERE external_id IS NOT NULL;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS previous_refresh_token_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS auth_source TEXT NOT NULL DEFAULT 'local_password',
    ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS device_posture_json JSONB,
    ADD COLUMN IF NOT EXISTS step_up_challenge_json JSONB,
    ADD COLUMN IF NOT EXISTS mfa_method TEXT NOT NULL DEFAULT 'totp';

CREATE TABLE IF NOT EXISTS identity_groups (
    group_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    members_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_groups_tenant_id
    ON identity_groups (tenant_id);
