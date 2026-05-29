CREATE TABLE IF NOT EXISTS audit_controlled_deletions (
    deletion_id TEXT PRIMARY KEY,
    tombstone_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    project_id TEXT,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    state TEXT NOT NULL,
    tombstone_hash TEXT NOT NULL,
    evidence_hash TEXT,
    requested_by_user_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL,
    pre_delete_event_hash TEXT,
    post_delete_event_hash TEXT,
    audit_checkpoint_id TEXT,
    tombstone_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_controlled_deletions_resource
    ON audit_controlled_deletions (resource_kind, resource_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_controlled_deletions_scope
    ON audit_controlled_deletions (tenant_id, project_id, retain_until);

CREATE INDEX IF NOT EXISTS idx_audit_controlled_deletions_hash
    ON audit_controlled_deletions (tombstone_hash);
