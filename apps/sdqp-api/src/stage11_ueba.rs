use std::{
    collections::BTreeMap, collections::HashMap, collections::HashSet, sync::Arc, time::Duration,
};

use rskafka::{
    client::{
        ClientBuilder,
        partition::{Compression, UnknownTopicHandling},
    },
    record::Record,
};
use sdqp_audit::AuditEvent;
use tokio::time::sleep;

use crate::{ApiState, phase6};

const AUDIT_TOPIC_PARTITION: i32 = 0;
const UEBA_STREAM_MAX_WAIT_MS: i32 = 250;
const UEBA_STREAM_MAX_BYTES: i32 = 1_048_576;
const UEBA_STREAM_LOOP_INTERVAL_MS: u64 = 50;

pub(crate) fn spawn_ueba_runtime(state: Arc<ApiState>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = run_ueba_stream_tick(state.clone()).await {
                tracing::warn!(error = %error, "stage11 ueba stream tick failed");
                sleep(Duration::from_millis(UEBA_STREAM_LOOP_INTERVAL_MS)).await;
            }
        }
    });
}

pub(crate) async fn publish_audit_event(state: Arc<ApiState>, event: AuditEvent) {
    match tokio::time::timeout(
        Duration::from_secs(3),
        try_publish_audit_event(&state, &event),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "failed to publish audit event");
        }
        Err(_) => {
            tracing::warn!("timed out publishing audit event");
        }
    }
}

async fn try_publish_audit_event(state: &Arc<ApiState>, event: &AuditEvent) -> Result<(), String> {
    if state.persistence.is_none() {
        return Ok(());
    }

    let client = ClientBuilder::new(state.kafka.brokers.clone())
        .build()
        .await
        .map_err(|error| error.to_string())?;
    ensure_topic(&client, &state.kafka.audit_topic).await;
    let partition_client = client
        .partition_client(
            state.kafka.audit_topic.clone(),
            AUDIT_TOPIC_PARTITION,
            UnknownTopicHandling::Retry,
        )
        .await
        .map_err(|error| error.to_string())?;
    let payload = serde_json::to_vec(event).map_err(|error| error.to_string())?;
    partition_client
        .produce(
            vec![Record {
                key: Some(event.event_id.as_bytes().to_vec()),
                value: Some(payload),
                headers: BTreeMap::new(),
                timestamp: event.timestamp,
            }],
            Compression::default(),
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn run_ueba_stream_tick(state: Arc<ApiState>) -> Result<(), String> {
    let Some(persistence) = state.persistence.as_ref().cloned() else {
        return Ok(());
    };

    let client = ClientBuilder::new(state.kafka.brokers.clone())
        .build()
        .await
        .map_err(|error| error.to_string())?;
    ensure_topic(&client, &state.kafka.audit_topic).await;
    let partition_client = client
        .partition_client(
            state.kafka.audit_topic.clone(),
            AUDIT_TOPIC_PARTITION,
            UnknownTopicHandling::Retry,
        )
        .await
        .map_err(|error| error.to_string())?;
    let next_offset = persistence
        .load_stream_offset(&state.kafka.audit_topic, AUDIT_TOPIC_PARTITION)
        .await
        .map_err(|error| error.to_string())?;
    let (records, _) = partition_client
        .fetch_records(
            next_offset,
            1..UEBA_STREAM_MAX_BYTES,
            UEBA_STREAM_MAX_WAIT_MS,
        )
        .await
        .map_err(|error| error.to_string())?;

    if records.is_empty() {
        sleep(Duration::from_millis(UEBA_STREAM_LOOP_INTERVAL_MS)).await;
        return Ok(());
    }

    let mut affected_tenants = HashSet::new();
    let mut staged_events: HashMap<String, Vec<AuditEvent>> = HashMap::new();
    let mut highest_offset = next_offset;
    for record in records {
        highest_offset = highest_offset.max(record.offset + 1);
        let Some(payload) = record.record.value.as_ref() else {
            continue;
        };
        let event: AuditEvent =
            serde_json::from_slice(payload).map_err(|error| error.to_string())?;
        affected_tenants.insert(event.target.tenant_id.clone());
        staged_events
            .entry(event.target.tenant_id.clone())
            .or_default()
            .push(event);
    }

    for tenant_id in affected_tenants {
        let tenant_events = staged_events.remove(&tenant_id).unwrap_or_default();
        phase6::process_persistent_ueba_tenant(&state, &persistence, &tenant_id, &tenant_events)
            .await
            .map_err(|error| error.to_string())?;
    }

    persistence
        .save_stream_offset(
            &state.kafka.audit_topic,
            AUDIT_TOPIC_PARTITION,
            highest_offset,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn ensure_topic(client: &rskafka::client::Client, topic: &str) {
    if let Ok(controller) = client.controller_client() {
        let _ = controller.create_topic(topic, 1, 1, 5_000).await;
    }
}
