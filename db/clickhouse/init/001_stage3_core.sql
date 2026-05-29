CREATE DATABASE IF NOT EXISTS sdqp;

CREATE TABLE IF NOT EXISTS sdqp.audit_events
(
    event_hash String,
    prev_hash String,
    tenant_id String,
    project_id Nullable(String),
    resource_id String,
    actor_user_id String,
    session_id String,
    ip_address String,
    action_type String,
    action_result String,
    context String,
    context_fields_json Nullable(String),
    data_fingerprint Nullable(String),
    event_time DateTime64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (tenant_id, ifNull(project_id, ''), event_time, event_hash);

CREATE TABLE IF NOT EXISTS sdqp.audit_checkpoints
(
    checkpoint_id String,
    event_count UInt64,
    latest_event_hash String,
    checkpoint_time DateTime64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (checkpoint_time, checkpoint_id);

CREATE TABLE IF NOT EXISTS sdqp.ueba_user_baselines
(
    tenant_id String,
    user_id String,
    baseline_window String,
    baseline_json String,
    updated_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, user_id, baseline_window);

CREATE TABLE IF NOT EXISTS sdqp.ueba_entity_baselines
(
    tenant_id String,
    entity_type String,
    entity_id String,
    baseline_window String,
    baseline_json String,
    updated_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, entity_type, entity_id, baseline_window);

CREATE TABLE IF NOT EXISTS sdqp.ueba_alerts
(
    alert_id String,
    tenant_id String,
    user_id String,
    severity String,
    mitigation_action String,
    reason String,
    created_at DateTime64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (tenant_id, created_at, alert_id);

CREATE TABLE IF NOT EXISTS sdqp.ueba_rule_hits
(
    hit_id String,
    alert_id String,
    tenant_id String,
    rule_name String,
    score UInt16,
    created_at DateTime64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (tenant_id, created_at, alert_id, hit_id);
