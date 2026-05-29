ALTER TABLE hr_directory_users
    ADD COLUMN IF NOT EXISTS availability TEXT NOT NULL DEFAULT 'available';

ALTER TABLE hr_directory_users
    ADD COLUMN IF NOT EXISTS delegate_user_id TEXT REFERENCES users (user_id) ON DELETE SET NULL;
