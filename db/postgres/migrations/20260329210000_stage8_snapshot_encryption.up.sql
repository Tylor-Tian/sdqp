ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS grant_id TEXT,
    ADD COLUMN IF NOT EXISTS grant_valid_until TIMESTAMPTZ;

UPDATE query_tasks
SET
    grant_id = COALESCE(
        grant_id,
        (
            SELECT grant_id
            FROM permission_grants
            ORDER BY created_at, grant_id
            LIMIT 1
        )
    ),
    grant_valid_until = COALESCE(grant_valid_until, NOW() + INTERVAL '8 hours');

ALTER TABLE snapshots
    ADD COLUMN IF NOT EXISTS owner_user_id TEXT REFERENCES users (user_id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS grant_id TEXT REFERENCES permission_grants (grant_id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS grant_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '8 hours',
    ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '8 hours',
    ADD COLUMN IF NOT EXISTS data_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS object_bucket TEXT NOT NULL DEFAULT 'sdqp-snapshots',
    ADD COLUMN IF NOT EXISTS object_size_bytes BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delete_state TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS delete_reason TEXT,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS purged_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_rewrapped_at TIMESTAMPTZ;

UPDATE snapshots
SET
    owner_user_id = COALESCE(owner_user_id, 'user-analyst'),
    grant_id = COALESCE(
        grant_id,
        (
            SELECT grant_id
            FROM permission_grants
            WHERE applicant_user_id = 'user-analyst'
            ORDER BY created_at, grant_id
            LIMIT 1
        )
    ),
    grant_expires_at = COALESCE(grant_expires_at, NOW() + INTERVAL '8 hours'),
    retention_until = COALESCE(retention_until, NOW() + INTERVAL '8 hours'),
    data_fingerprint = COALESCE(data_fingerprint, ''),
    object_bucket = COALESCE(object_bucket, 'sdqp-snapshots'),
    object_size_bytes = COALESCE(object_size_bytes, 0),
    delete_state = COALESCE(delete_state, 'active');

ALTER TABLE snapshots
    ALTER COLUMN owner_user_id SET NOT NULL,
    ALTER COLUMN grant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_snapshots_grant_state
    ON snapshots (grant_id, delete_state, retention_until);
