ALTER TABLE sdqp.audit_events
    ADD COLUMN IF NOT EXISTS event_id String AFTER event_hash;

ALTER TABLE sdqp.audit_checkpoints
    ADD COLUMN IF NOT EXISTS signature String AFTER latest_event_hash;
