ALTER TABLE hr_directory_users
    DROP COLUMN IF EXISTS delegate_user_id,
    DROP COLUMN IF EXISTS availability;
