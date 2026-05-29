ALTER TABLE export_tasks
    ADD COLUMN IF NOT EXISTS verification_status TEXT,
    ADD COLUMN IF NOT EXISTS integrity_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS anchor_status TEXT,
    ADD COLUMN IF NOT EXISTS anchor_provider TEXT,
    ADD COLUMN IF NOT EXISTS timestamp_provider TEXT,
    ADD COLUMN IF NOT EXISTS provider_runtime_mode TEXT,
    ADD COLUMN IF NOT EXISTS external_final_uat_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS refresh_recommended BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS failure_reason TEXT,
    ADD COLUMN IF NOT EXISTS last_anchor_refresh_at TIMESTAMPTZ;

ALTER TABLE evidence_packages
    ADD COLUMN IF NOT EXISTS verification_status TEXT,
    ADD COLUMN IF NOT EXISTS anchor_status TEXT,
    ADD COLUMN IF NOT EXISTS provider_runtime_mode TEXT,
    ADD COLUMN IF NOT EXISTS external_final_uat_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS certificate_serial_number TEXT;

CREATE INDEX IF NOT EXISTS idx_export_tasks_provider_runtime
    ON export_tasks (provider_runtime_mode, anchor_status, verification_status);

CREATE INDEX IF NOT EXISTS idx_evidence_packages_certification_state
    ON evidence_packages (provider_runtime_mode, anchor_status, verification_status);
