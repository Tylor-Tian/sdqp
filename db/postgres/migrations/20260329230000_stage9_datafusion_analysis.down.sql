DROP INDEX IF EXISTS idx_classification_field_policies_scope;
DROP INDEX IF EXISTS idx_classification_detection_runs_scope;
DROP INDEX IF EXISTS idx_classification_rules_scope;
DROP INDEX IF EXISTS idx_snapshots_format_scope;

DROP TABLE IF EXISTS classification_field_policies;
DROP TABLE IF EXISTS classification_detection_runs;
DROP TABLE IF EXISTS classification_rule_versions;

ALTER TABLE snapshots
    DROP COLUMN IF EXISTS columns_json,
    DROP COLUMN IF EXISTS payload_format;
