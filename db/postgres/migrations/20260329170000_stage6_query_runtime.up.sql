ALTER TABLE data_sources
    ADD COLUMN IF NOT EXISTS connection_uri TEXT NOT NULL DEFAULT '';

ALTER TABLE data_sources
    ADD COLUMN IF NOT EXISTS adapter_config_json JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE data_sources
SET
    connection_uri = CASE data_source_id
        WHEN 'datasource-rest' THEN 'mock://rest'
        WHEN 'datasource-rpc' THEN 'mock://rpc'
        WHEN 'datasource-hive' THEN 'mock://hive'
        ELSE connection_uri
    END,
    adapter_config_json = CASE data_source_id
        WHEN 'datasource-hive' THEN jsonb_build_object('table', 'stage6_employee_rows', 'delay_ms', 150)
        ELSE adapter_config_json
    END
WHERE connection_uri = '';

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS data_source_id TEXT REFERENCES data_sources (data_source_id) ON DELETE CASCADE;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS source_type TEXT;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS query_payload_json JSONB;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS cache_key TEXT;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 2;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS lease_owner TEXT;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

ALTER TABLE query_tasks
    ADD COLUMN IF NOT EXISTS completion_audited BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_query_tasks_scheduler
    ON query_tasks (state, priority, created_at);

CREATE INDEX IF NOT EXISTS idx_query_tasks_lease
    ON query_tasks (state, lease_expires_at);
