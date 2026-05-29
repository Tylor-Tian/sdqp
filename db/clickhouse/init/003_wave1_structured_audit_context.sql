ALTER TABLE sdqp.audit_events
    ADD COLUMN IF NOT EXISTS context_fields_json Nullable(String) AFTER context;
