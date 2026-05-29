ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS notification_json JSONB;

UPDATE notification_deliveries
SET notification_json = jsonb_build_object(
    'recipient', recipient,
    'message', message,
    'kind', 'informational'
)
WHERE notification_json IS NULL;

ALTER TABLE notification_deliveries
    ALTER COLUMN notification_json SET NOT NULL;
