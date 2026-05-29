DROP INDEX IF EXISTS idx_notification_deliveries_due;
DROP TABLE IF EXISTS notification_deliveries;

DROP TABLE IF EXISTS hr_sync_events;
DROP TABLE IF EXISTS hr_directory_users;

DROP INDEX IF EXISTS idx_approval_instances_active_key;
DROP INDEX IF EXISTS idx_permission_applications_merge;
DROP INDEX IF EXISTS idx_permission_grants_valid_until;
DROP INDEX IF EXISTS idx_permission_grants_scope_status;

ALTER TABLE approval_instances
    DROP COLUMN IF EXISTS approval_key,
    DROP COLUMN IF EXISTS current_step_index,
    DROP COLUMN IF EXISTS audit_log_json,
    DROP COLUMN IF EXISTS step_states_json,
    DROP COLUMN IF EXISTS request_json,
    DROP COLUMN IF EXISTS flow_id_ref,
    DROP COLUMN IF EXISTS data_source_id,
    DROP COLUMN IF EXISTS applicant_user_id;

ALTER TABLE permission_applications
    DROP COLUMN IF EXISTS merged_into_application_id,
    DROP COLUMN IF EXISTS merge_key,
    DROP COLUMN IF EXISTS approval_instance_id;

ALTER TABLE permission_grants
    DROP COLUMN IF EXISTS approval_instance_id,
    DROP COLUMN IF EXISTS org_binding_json,
    DROP COLUMN IF EXISTS valid_until,
    DROP COLUMN IF EXISTS valid_from;
