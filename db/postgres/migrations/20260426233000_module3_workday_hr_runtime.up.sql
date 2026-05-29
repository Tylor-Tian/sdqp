ALTER TABLE hr_directory_users
    ADD COLUMN IF NOT EXISTS provider_id TEXT;

ALTER TABLE hr_sync_events
    ADD COLUMN IF NOT EXISTS provider_id TEXT,
    ADD COLUMN IF NOT EXISTS provider_cursor TEXT;

CREATE TABLE IF NOT EXISTS hr_sync_checkpoints (
    provider_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    event_cursor TEXT,
    snapshot_cursor TEXT,
    last_snapshot_at TIMESTAMPTZ,
    last_event_poll_at TIMESTAMPTZ,
    last_webhook_at TIMESTAMPTZ,
    auth_mode TEXT NOT NULL,
    provider_base_url TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hr_sync_events_provider
    ON hr_sync_events (provider_id, processed_at DESC);
