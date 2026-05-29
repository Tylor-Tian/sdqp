DROP INDEX IF EXISTS idx_identity_groups_tenant_id;
DROP TABLE IF EXISTS identity_groups;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS mfa_method,
    DROP COLUMN IF EXISTS step_up_challenge_json,
    DROP COLUMN IF EXISTS device_posture_json,
    DROP COLUMN IF EXISTS risk_score,
    DROP COLUMN IF EXISTS auth_source,
    DROP COLUMN IF EXISTS previous_refresh_token_fingerprint;

DROP INDEX IF EXISTS idx_users_external_id;

ALTER TABLE users
    DROP COLUMN IF EXISTS auth_source,
    DROP COLUMN IF EXISTS active,
    DROP COLUMN IF EXISTS external_id,
    DROP COLUMN IF EXISTS email,
    DROP COLUMN IF EXISTS display_name;
