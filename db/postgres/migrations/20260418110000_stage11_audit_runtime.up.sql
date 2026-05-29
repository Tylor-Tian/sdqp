CREATE TABLE IF NOT EXISTS audit_forward_deliveries (
    delivery_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    checkpoint_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    destination TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_forward_deliveries_delivered_at
    ON audit_forward_deliveries (delivered_at DESC);

CREATE TABLE IF NOT EXISTS audit_archive_bundles (
    bundle_id TEXT PRIMARY KEY,
    archive_path TEXT NOT NULL,
    first_event_id TEXT,
    last_event_id TEXT,
    first_event_time TIMESTAMPTZ,
    last_event_time TIMESTAMPTZ,
    event_count INTEGER NOT NULL,
    checkpoint_count INTEGER NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL,
    boundary_checkpoint_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    purged_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audit_archive_bundles_active
    ON audit_archive_bundles (retain_until, created_at DESC)
    WHERE purged_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_chain_boundaries (
    boundary_id TEXT PRIMARY KEY,
    archived_bundle_id TEXT REFERENCES audit_archive_bundles (bundle_id) ON DELETE SET NULL,
    checkpoint_id TEXT NOT NULL,
    event_count BIGINT NOT NULL,
    latest_event_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signer_provider TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    signer_key_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_boundaries_single_active
    ON audit_chain_boundaries (active)
    WHERE active;

CREATE TABLE IF NOT EXISTS audit_retention_runs (
    run_id TEXT PRIMARY KEY,
    archived_bundle_id TEXT REFERENCES audit_archive_bundles (bundle_id) ON DELETE SET NULL,
    archived_events INTEGER NOT NULL DEFAULT 0,
    archived_checkpoints INTEGER NOT NULL DEFAULT 0,
    purged_bundles INTEGER NOT NULL DEFAULT 0,
    archive_path TEXT,
    status TEXT NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_retention_runs_created_at
    ON audit_retention_runs (created_at DESC);
