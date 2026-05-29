ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS object_bucket TEXT NOT NULL DEFAULT 'sdqp-snapshots',
    ADD COLUMN IF NOT EXISTS object_prefix TEXT,
    ADD COLUMN IF NOT EXISTS created_by_user_id TEXT,
    ADD COLUMN IF NOT EXISTS deletion_reason TEXT,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

UPDATE projects
SET object_prefix = 'snapshots/' || tenant_id || '/' || project_id || '/'
WHERE object_prefix IS NULL OR object_prefix = '';

ALTER TABLE projects
    ALTER COLUMN object_prefix SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_object_namespace
    ON projects (object_bucket, object_prefix);
