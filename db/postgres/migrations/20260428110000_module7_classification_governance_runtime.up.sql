ALTER TABLE classification_rule_versions
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS catalog_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS governance_note TEXT;

CREATE INDEX IF NOT EXISTS idx_classification_rule_versions_scope_status
    ON classification_rule_versions(project_id, data_source_id, status, version_number DESC);

ALTER TABLE classification_detection_runs
    ADD COLUMN IF NOT EXISTS catalog_json JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE classification_field_policies
    ADD COLUMN IF NOT EXISTS data_category TEXT NOT NULL DEFAULT 'general_confidential',
    ADD COLUMN IF NOT EXISTS catalog_entry_id TEXT,
    ADD COLUMN IF NOT EXISTS applicable_regulations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS retention_policy_json JSONB NOT NULL DEFAULT
        '{"policy_id":"retention-general-confidential","retain_for_days":365,"disposal_action":"Review","legal_hold_supported":true}'::jsonb,
    ADD COLUMN IF NOT EXISTS manual_confirmation_required BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS reviewer_note TEXT;

CREATE INDEX IF NOT EXISTS idx_classification_field_policies_catalog
    ON classification_field_policies(project_id, data_source_id, catalog_entry_id);
