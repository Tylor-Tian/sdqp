ALTER TABLE sdqp.audit_checkpoints
    ADD COLUMN IF NOT EXISTS signature_algorithm String AFTER signature;

ALTER TABLE sdqp.audit_checkpoints
    ADD COLUMN IF NOT EXISTS signer_provider String AFTER signature_algorithm;

ALTER TABLE sdqp.audit_checkpoints
    ADD COLUMN IF NOT EXISTS signer_key_id String AFTER signer_provider;

ALTER TABLE sdqp.audit_checkpoints
    ADD COLUMN IF NOT EXISTS signer_key_version Nullable(String) AFTER signer_key_id;
