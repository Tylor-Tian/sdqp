CREATE TABLE IF NOT EXISTS key_rotation_state (
    inventory_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    kek_id TEXT NOT NULL,
    key_version TEXT,
    dek_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_rewrapped_at TIMESTAMPTZ,
    next_dek_rotation_due_at TIMESTAMPTZ NOT NULL,
    next_kek_rewrap_due_at TIMESTAMPTZ NOT NULL,
    due_state TEXT NOT NULL,
    status TEXT NOT NULL,
    last_operation TEXT NOT NULL,
    last_cycle_id TEXT,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_key_rotation_state_due
    ON key_rotation_state (tenant_id, project_id, due_state, status);

CREATE INDEX IF NOT EXISTS idx_key_rotation_state_snapshot
    ON key_rotation_state (snapshot_id);
