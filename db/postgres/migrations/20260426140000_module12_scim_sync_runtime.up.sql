CREATE TABLE IF NOT EXISTS identity_group_members (
    group_id TEXT NOT NULL REFERENCES identity_groups (group_id) ON DELETE CASCADE,
    user_external_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, user_external_id)
);

CREATE INDEX IF NOT EXISTS idx_identity_group_members_user_external_id
    ON identity_group_members (user_external_id);

CREATE TABLE IF NOT EXISTS scim_sync_state (
    provider_id TEXT PRIMARY KEY,
    cursor_json JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
