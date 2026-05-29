DROP INDEX IF EXISTS idx_download_authorizations_task;
DROP INDEX IF EXISTS idx_export_tasks_scope;
DROP INDEX IF EXISTS idx_evidence_packages_task_id;

DROP TABLE IF EXISTS download_authorizations;
DROP TABLE IF EXISTS export_tasks;

ALTER TABLE evidence_packages
    DROP COLUMN IF EXISTS tenant_id,
    DROP COLUMN IF EXISTS template,
    DROP COLUMN IF EXISTS manifest_digest,
    DROP COLUMN IF EXISTS watermark_token,
    DROP COLUMN IF EXISTS package_json,
    DROP COLUMN IF EXISTS file_name,
    DROP COLUMN IF EXISTS media_type,
    DROP COLUMN IF EXISTS created_by_user_id,
    DROP COLUMN IF EXISTS task_id,
    DROP COLUMN IF EXISTS updated_at;
