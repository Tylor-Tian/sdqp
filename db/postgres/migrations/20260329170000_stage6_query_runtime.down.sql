DROP INDEX IF EXISTS idx_query_tasks_lease;
DROP INDEX IF EXISTS idx_query_tasks_scheduler;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS completion_audited;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS lease_expires_at;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS lease_owner;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS max_attempts;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS attempt_count;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS priority;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS cache_key;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS query_payload_json;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS source_type;

ALTER TABLE query_tasks
    DROP COLUMN IF EXISTS data_source_id;

ALTER TABLE data_sources
    DROP COLUMN IF EXISTS adapter_config_json;

ALTER TABLE data_sources
    DROP COLUMN IF EXISTS connection_uri;
