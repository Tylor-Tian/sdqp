DROP INDEX IF EXISTS idx_snapshots_grant_state;

ALTER TABLE snapshots
    DROP COLUMN IF EXISTS last_rewrapped_at,
    DROP COLUMN IF EXISTS purged_at,
    DROP COLUMN IF EXISTS deleted_at,
    DROP COLUMN IF EXISTS delete_reason,
    DROP COLUMN IF EXISTS delete_state,
    DROP COLUMN IF EXISTS object_size_bytes,
    DROP COLUMN IF EXISTS object_bucket,
    DROP COLUMN IF EXISTS data_fingerprint,
    DROP COLUMN IF EXISTS retention_until,
    DROP COLUMN IF EXISTS grant_expires_at,
    DROP COLUMN IF EXISTS grant_id,
    DROP COLUMN IF EXISTS owner_user_id;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS grant_valid_until,
    DROP COLUMN IF EXISTS grant_id;
