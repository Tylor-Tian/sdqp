use std::{collections::BTreeMap, sync::Arc, time::Duration as StdDuration};

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{ApiState, AuthenticatedSession, json_error, phase2};
use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditCheckpoint, AuditContextFields,
    ControlledDeletionChainEvidence, ControlledDeletionContentRef, ControlledDeletionFlow,
    ControlledDeletionRecord, ControlledDeletionState, ControlledDeletionSubject,
    ControlledDeletionSubjectKind, TargetRef, controlled_deletion_digest,
};
use sdqp_core::RequestContext;
use sdqp_encryption::{
    EncryptedSnapshotRecord, KeyRotationDueState, KeyRotationInventoryItem, KeyRotationOperation,
    KeyRotationRuntimeStatus, KeyRotationState, KeyRotationTrigger, SnapshotDeleteState,
    SnapshotStoreError,
};
use sdqp_system_security::{Role, enforce_separation_of_duties};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotLifecycleResponse {
    pub snapshot_id: String,
    pub grant_id: String,
    pub delete_state: String,
    pub delete_reason: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub purged_at: Option<DateTime<Utc>>,
    pub grant_expires_at: DateTime<Utc>,
    pub retention_until: DateTime<Utc>,
    pub last_rewrapped_at: Option<DateTime<Utc>>,
    pub kms_provider: String,
    pub kek_id: String,
    pub key_version: Option<String>,
    pub object_bucket: String,
    pub object_key: String,
    pub object_size_bytes: usize,
    pub object_present: bool,
    pub controlled_deletion: Option<ControlledDeletionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRefreshResponse {
    pub snapshot_id: String,
    pub refreshed: bool,
    pub kms_provider: String,
    pub kek_id: String,
    pub key_version: Option<String>,
    pub previous_kms_provider: String,
    pub previous_kek_id: String,
    pub previous_key_version: Option<String>,
    pub last_rewrapped_at: Option<DateTime<Utc>>,
    pub rotate_dek_due: bool,
    pub rotate_kek_wrap_due: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationStateResponse {
    pub inventory_id: String,
    pub snapshot_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub provider: String,
    pub kek_id: String,
    pub key_version: Option<String>,
    pub dek_id: String,
    pub created_at: DateTime<Utc>,
    pub last_rewrapped_at: Option<DateTime<Utc>>,
    pub next_dek_rotation_due_at: DateTime<Utc>,
    pub next_kek_rewrap_due_at: DateTime<Utc>,
    pub due_state: String,
    pub status: String,
    pub last_operation: String,
    pub last_cycle_id: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationStatesResponse {
    pub states: Vec<KeyRotationStateResponse>,
    pub tee_key_release_boundary: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KeyRotationRunRequest {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub include_dek_rotation: Option<bool>,
    #[serde(default)]
    pub include_kek_rewrap: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationAttemptResponse {
    pub snapshot_id: String,
    pub status: String,
    pub operation: String,
    pub rotate_dek_due: bool,
    pub rotate_kek_wrap_due: bool,
    pub previous_kms_provider: String,
    pub previous_kek_id: String,
    pub previous_key_version: Option<String>,
    pub previous_dek_id: String,
    pub current_kms_provider: String,
    pub current_kek_id: String,
    pub current_key_version: Option<String>,
    pub current_dek_id: String,
    pub last_rewrapped_at: Option<DateTime<Utc>>,
    pub due_state: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRunResponse {
    pub cycle_id: String,
    pub trigger: String,
    pub evaluated: usize,
    pub rotated_deks: usize,
    pub rewrapped_keks: usize,
    pub skipped: usize,
    pub failed: usize,
    pub audit_checkpoint_id: String,
    pub results: Vec<KeyRotationAttemptResponse>,
    pub tee_key_release_boundary: String,
}

pub async fn soft_delete_snapshot_handler(
    State(state): State<Arc<ApiState>>,
    Path(snapshot_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record =
        match load_scoped_snapshot_any(&state, &snapshot_id, &request_context, &session).await {
            Ok(record) => record,
            Err(response) => return *response,
        };
    let now = Utc::now();
    let actor = actor_from_session(&session);
    let mut flow = snapshot_controlled_deletion_flow(
        &state,
        &record,
        actor.clone(),
        "manual controlled snapshot delete",
        now,
    );
    flow.transition_to(
        ControlledDeletionState::Authorized,
        actor.user_id.clone(),
        "authenticated project-scoped delete request accepted",
        now,
    );

    {
        let mut store = state.snapshots.lock().expect("snapshot store");
        if let Err(error) = store.soft_delete(&snapshot_id, "controlled logical delete", now) {
            return snapshot_store_error_response(error);
        }
    }
    remove_snapshot_from_cache(&state, &snapshot_id).await;

    let updated = match refresh_snapshot_record(&state, &snapshot_id).await {
        Ok(record) => record,
        Err(response) => return *response,
    };

    populate_logical_delete_tombstone(&mut flow, &record, &updated, now);
    flow.transition_to(
        ControlledDeletionState::LogicalDeleted,
        actor.user_id.clone(),
        "snapshot lifecycle moved out of active state",
        now,
    );
    flow.transition_to(
        ControlledDeletionState::TombstoneWritten,
        actor.user_id.clone(),
        "logical deletion tombstone materialized",
        now,
    );

    let mut audit_fields = snapshot_lifecycle_audit_fields(&updated);
    extend_controlled_deletion_audit_fields(&mut audit_fields, flow.record());
    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::ConfigChange,
        ActionResult::Success,
        &snapshot_id,
        "snapshot controlled deletion tombstone written",
        phase2::Phase2AuditDetails::new(
            audit_fields,
            Some(flow.record().tombstone.tombstone_hash.clone()),
        ),
    )
    .await;
    let checkpoint = latest_audit_checkpoint(&state).expect("controlled deletion audit checkpoint");

    seal_controlled_deletion_flow(&state, &mut flow, &checkpoint, actor.user_id.clone(), now);
    let controlled_deletion = flow.into_record();
    if let Err(response) = save_controlled_deletion_record(&state, controlled_deletion).await {
        return response;
    }

    lifecycle_response(&state, updated).await
}

pub async fn restore_snapshot_handler(
    State(state): State<Arc<ApiState>>,
    Path(snapshot_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record =
        match load_scoped_snapshot_any(&state, &snapshot_id, &request_context, &session).await {
            Ok(record) => record,
            Err(response) => return *response,
        };

    {
        let mut store = state.snapshots.lock().expect("snapshot store");
        if let Err(error) = store.restore(&snapshot_id) {
            return snapshot_store_error_response(error);
        }
    }

    let updated = match refresh_snapshot_record(&state, &snapshot_id).await {
        Ok(record) => record,
        Err(response) => return *response,
    };

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::ConfigChange,
        ActionResult::Success,
        &snapshot_id,
        "snapshot restored",
        phase2::Phase2AuditDetails::new(
            snapshot_lifecycle_audit_fields(&updated),
            Some(record.lifecycle.data_fingerprint),
        ),
    )
    .await;

    lifecycle_response(&state, updated).await
}

pub async fn refresh_snapshot_handler(
    State(state): State<Arc<ApiState>>,
    Path(snapshot_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record =
        match load_scoped_snapshot_any(&state, &snapshot_id, &request_context, &session).await {
            Ok(record) => record,
            Err(response) => return *response,
        };
    if record.lifecycle.delete_state != SnapshotDeleteState::Active {
        return json_error(StatusCode::CONFLICT, "snapshot is not active");
    }

    let recommendation = state.rotation_policy.evaluate(
        record.created_at,
        record.lifecycle.last_rewrapped_at,
        Utc::now(),
    );
    let previous_provider = record.encrypted_payload.kms_provider.clone();
    let previous_kek_id = record.encrypted_payload.kek_id.clone();
    let previous_key_version = record.encrypted_payload.key_version.clone();

    let rewrapped = match state.cipher.rewrap(&record.encrypted_payload) {
        Ok(payload) => payload,
        Err(error) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to refresh snapshot key wrap: {error}"),
            );
        }
    };

    let updated = {
        let mut store = state.snapshots.lock().expect("snapshot store");
        if let Err(error) = store.mark_rewrapped(&snapshot_id, rewrapped, Utc::now()) {
            return snapshot_store_error_response(error);
        }
        match store.get_any(&snapshot_id) {
            Ok(record) => record,
            Err(error) => return snapshot_store_error_response(error),
        }
    };
    if let Some(persistence) = &state.persistence
        && persistence.save_snapshot(&updated).await.is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist refreshed snapshot",
        );
    }

    let mut audit_fields = snapshot_lifecycle_audit_fields(&updated);
    audit_fields.insert("previous_kms_provider", previous_provider.clone());
    audit_fields.insert("previous_kek_id", previous_kek_id.clone());
    if let Some(previous_key_version) = &previous_key_version {
        audit_fields.insert("previous_key_version", previous_key_version.clone());
    }
    audit_fields.insert("rotate_dek_due", recommendation.rotate_dek);
    audit_fields.insert("rotate_kek_wrap_due", recommendation.rotate_kek_wrap);

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::ConfigChange,
        ActionResult::Success,
        &snapshot_id,
        "snapshot key wrap refreshed",
        phase2::Phase2AuditDetails::new(audit_fields, Some(record.lifecycle.data_fingerprint)),
    )
    .await;

    Json(SnapshotRefreshResponse {
        snapshot_id,
        refreshed: true,
        kms_provider: updated.encrypted_payload.kms_provider.clone(),
        kek_id: updated.encrypted_payload.kek_id.clone(),
        key_version: updated.encrypted_payload.key_version.clone(),
        previous_kms_provider: previous_provider,
        previous_kek_id,
        previous_key_version,
        last_rewrapped_at: updated.lifecycle.last_rewrapped_at,
        rotate_dek_due: recommendation.rotate_dek,
        rotate_kek_wrap_due: recommendation.rotate_kek_wrap,
    })
    .into_response()
}

pub(crate) fn spawn_key_rotation_runtime(state: Arc<ApiState>) {
    if !state.key_rotation.enabled || state.persistence.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(
            state.key_rotation.cycle_interval_secs.max(1),
        ));
        loop {
            interval.tick().await;
            let actor = ActorInfo {
                user_id: "system-key-rotation".into(),
                session_id: "runtime-job".into(),
                ip_address: "127.0.0.1".into(),
            };
            let _ = run_key_rotation_cycle(
                state.clone(),
                actor,
                "system".into(),
                None,
                KeyRotationRunRequest::default(),
                KeyRotationTrigger::Runtime,
                false,
            )
            .await;
        }
    });
}

pub async fn key_rotation_states_handler(
    State(state): State<Arc<ApiState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Extension(request_context): Extension<RequestContext>,
) -> Response {
    if let Err(response) = authorize_key_rotation_admin(&state, &session, &request_context).await {
        return response;
    }

    match ensure_key_rotation_states(&state, Some(request_context.tenant_id.as_str())).await {
        Ok(states) => Json(KeyRotationStatesResponse {
            states: states
                .into_iter()
                .map(key_rotation_state_response)
                .collect(),
            tee_key_release_boundary: tee_key_release_boundary(),
        })
        .into_response(),
        Err(response) => response,
    }
}

pub async fn key_rotation_run_handler(
    State(state): State<Arc<ApiState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Extension(request_context): Extension<RequestContext>,
    Json(payload): Json<KeyRotationRunRequest>,
) -> Response {
    if let Err(response) = authorize_key_rotation_admin(&state, &session, &request_context).await {
        return response;
    }

    let actor = actor_from_session(&session);
    let tenant_id = request_context.tenant_id.as_str().to_string();
    let project_id = payload.project_id.clone().or_else(|| {
        request_context
            .project_id
            .as_ref()
            .map(|project| project.as_str().to_string())
    });
    let response = run_key_rotation_cycle(
        state,
        actor,
        tenant_id,
        project_id,
        payload,
        KeyRotationTrigger::Manual,
        true,
    )
    .await;
    Json(response).into_response()
}

pub async fn purge_snapshot_handler(
    State(state): State<Arc<ApiState>>,
    Path(snapshot_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record =
        match load_scoped_snapshot_any(&state, &snapshot_id, &request_context, &session).await {
            Ok(record) => record,
            Err(response) => return *response,
        };
    let now = Utc::now();
    let actor = actor_from_session(&session);
    let mut flow = snapshot_controlled_deletion_flow(
        &state,
        &record,
        actor.clone(),
        "manual controlled snapshot purge",
        now,
    );
    flow.transition_to(
        ControlledDeletionState::Authorized,
        actor.user_id.clone(),
        "authenticated project-scoped purge request accepted",
        now,
    );

    let object_existed = match delete_snapshot_object_if_present(&state, &record).await {
        Ok(existed) => existed,
        Err(response) => return response,
    };

    {
        let mut store = state.snapshots.lock().expect("snapshot store");
        if let Err(error) = store.mark_purged(&snapshot_id, "controlled content purge", now) {
            return snapshot_store_error_response(error);
        }
    }
    remove_snapshot_from_cache(&state, &snapshot_id).await;

    let updated = match refresh_snapshot_record(&state, &snapshot_id).await {
        Ok(record) => record,
        Err(response) => return *response,
    };

    populate_content_purge_tombstone(&mut flow, &record, &updated, object_existed, now);
    flow.transition_to(
        ControlledDeletionState::ContentPurged,
        actor.user_id.clone(),
        "snapshot object content removed or confirmed absent",
        now,
    );
    flow.transition_to(
        ControlledDeletionState::TombstoneWritten,
        actor.user_id.clone(),
        "purge tombstone materialized",
        now,
    );

    let mut audit_fields = snapshot_lifecycle_audit_fields(&updated);
    extend_controlled_deletion_audit_fields(&mut audit_fields, flow.record());
    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::ConfigChange,
        ActionResult::Success,
        &snapshot_id,
        "snapshot controlled deletion content purged",
        phase2::Phase2AuditDetails::new(
            audit_fields,
            Some(flow.record().tombstone.tombstone_hash.clone()),
        ),
    )
    .await;
    let checkpoint = latest_audit_checkpoint(&state).expect("controlled deletion audit checkpoint");

    seal_controlled_deletion_flow(&state, &mut flow, &checkpoint, actor.user_id.clone(), now);
    let controlled_deletion = flow.into_record();
    if let Err(response) = save_controlled_deletion_record(&state, controlled_deletion).await {
        return response;
    }

    lifecycle_response(&state, updated).await
}

pub async fn snapshot_tombstone_handler(
    State(state): State<Arc<ApiState>>,
    Path(snapshot_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record =
        match load_scoped_snapshot_any(&state, &snapshot_id, &request_context, &session).await {
            Ok(record) => record,
            Err(response) => return *response,
        };
    match load_controlled_deletion_for_snapshot(&state, &record).await {
        Some(tombstone) => Json(tombstone).into_response(),
        None => json_error(StatusCode::NOT_FOUND, "snapshot tombstone not found"),
    }
}

async fn authorize_key_rotation_admin(
    state: &Arc<ApiState>,
    session: &AuthenticatedSession,
    request_context: &RequestContext,
) -> Result<(), Response> {
    if !session.roles.iter().any(|role| role == &Role::SystemAdmin) {
        phase2::append_phase2_audit(
            state,
            session,
            request_context,
            ActionType::ConfigChange,
            ActionResult::Denied,
            "key-rotation",
            "missing system admin role",
            None,
        )
        .await;
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "system admin role required",
        ));
    }

    if enforce_separation_of_duties(&session.roles).is_err() {
        phase2::append_phase2_audit(
            state,
            session,
            request_context,
            ActionType::ConfigChange,
            ActionResult::Denied,
            "key-rotation",
            "separation of duties violation",
            None,
        )
        .await;
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "separation of duties violation",
        ));
    }

    Ok(())
}

async fn run_key_rotation_cycle(
    state: Arc<ApiState>,
    actor: ActorInfo,
    tenant_id: String,
    project_id: Option<String>,
    request: KeyRotationRunRequest,
    trigger: KeyRotationTrigger,
    emit_noop_audit: bool,
) -> KeyRotationRunResponse {
    let cycle_id = ulid::Ulid::new().to_string();
    let mut results = Vec::new();
    let mut audit_checkpoint_id = String::new();
    let snapshots = match load_key_rotation_snapshots(&state).await {
        Ok(snapshots) => snapshots,
        Err(error) => {
            let result = KeyRotationAttemptResponse {
                snapshot_id: request.snapshot_id.clone().unwrap_or_else(|| "*".into()),
                status: KeyRotationRuntimeStatus::Failed.as_str().into(),
                operation: KeyRotationOperation::None.as_str().into(),
                rotate_dek_due: false,
                rotate_kek_wrap_due: false,
                previous_kms_provider: String::new(),
                previous_kek_id: String::new(),
                previous_key_version: None,
                previous_dek_id: String::new(),
                current_kms_provider: String::new(),
                current_kek_id: String::new(),
                current_key_version: None,
                current_dek_id: String::new(),
                last_rewrapped_at: None,
                due_state: KeyRotationDueState::Current.as_str().into(),
                error: Some(error),
            };
            let checkpoint = append_key_rotation_audit(
                &state,
                actor,
                &tenant_id,
                project_id.as_deref(),
                &cycle_id,
                trigger,
                &result,
            )
            .await;
            audit_checkpoint_id = checkpoint.checkpoint_id;
            results.push(result);
            return key_rotation_run_response(cycle_id, trigger, results, audit_checkpoint_id);
        }
    };

    let mut processed = 0usize;
    let batch_limit = state.key_rotation.batch_limit.max(1) as usize;
    for snapshot in snapshots {
        if trigger == KeyRotationTrigger::Manual && snapshot.tenant_id != tenant_id {
            continue;
        }
        if let Some(project_id) = project_id.as_deref()
            && snapshot.project_id != project_id
        {
            continue;
        }
        if let Some(requested_snapshot_id) = request.snapshot_id.as_deref()
            && snapshot.snapshot_id != requested_snapshot_id
        {
            continue;
        }
        if processed >= batch_limit && !request.force {
            break;
        }
        processed += 1;

        let result = rotate_snapshot_key_material(&state, &snapshot, &request, &cycle_id).await;
        let checkpoint = append_key_rotation_audit(
            &state,
            actor.clone(),
            &snapshot.tenant_id,
            Some(&snapshot.project_id),
            &cycle_id,
            trigger,
            &result,
        )
        .await;
        audit_checkpoint_id = checkpoint.checkpoint_id;
        results.push(result);
    }

    if results.is_empty() && emit_noop_audit {
        let result = KeyRotationAttemptResponse {
            snapshot_id: request.snapshot_id.unwrap_or_else(|| "*".into()),
            status: KeyRotationRuntimeStatus::Skipped.as_str().into(),
            operation: KeyRotationOperation::None.as_str().into(),
            rotate_dek_due: false,
            rotate_kek_wrap_due: false,
            previous_kms_provider: String::new(),
            previous_kek_id: String::new(),
            previous_key_version: None,
            previous_dek_id: String::new(),
            current_kms_provider: String::new(),
            current_kek_id: String::new(),
            current_key_version: None,
            current_dek_id: String::new(),
            last_rewrapped_at: None,
            due_state: KeyRotationDueState::Current.as_str().into(),
            error: None,
        };
        let checkpoint = append_key_rotation_audit(
            &state,
            actor,
            &tenant_id,
            project_id.as_deref(),
            &cycle_id,
            trigger,
            &result,
        )
        .await;
        audit_checkpoint_id = checkpoint.checkpoint_id;
        results.push(result);
    }

    key_rotation_run_response(cycle_id, trigger, results, audit_checkpoint_id)
}

async fn rotate_snapshot_key_material(
    state: &Arc<ApiState>,
    record: &EncryptedSnapshotRecord,
    request: &KeyRotationRunRequest,
    cycle_id: &str,
) -> KeyRotationAttemptResponse {
    let now = Utc::now();
    let previous_key_material = PreviousKeyMaterial {
        provider: record.encrypted_payload.kms_provider.clone(),
        kek_id: record.encrypted_payload.kek_id.clone(),
        key_version: record.encrypted_payload.key_version.clone(),
        dek_id: record.encrypted_payload.dek_id.clone(),
    };
    let purged = record.lifecycle.delete_state.as_str() == "purged";
    let mut state_record = rotation_state_for_record(state, record, now);
    let recommendation = state.rotation_policy.evaluate(
        state_record.created_at,
        state_record.last_rewrapped_at,
        now,
    );
    state_record.last_cycle_id = Some(cycle_id.to_string());

    if purged {
        state_record.status = KeyRotationRuntimeStatus::Skipped;
        state_record.due_state = KeyRotationDueState::Purged;
        state_record.last_operation = KeyRotationOperation::None;
        persist_key_rotation_state(state, &state_record).await;
        return key_rotation_attempt_response(
            record,
            &state_record,
            KeyRotationOperation::None,
            recommendation,
            &previous_key_material,
            Some("snapshot is purged".into()),
        );
    }

    let operation = choose_key_rotation_operation(state, &recommendation, request);
    if operation == KeyRotationOperation::None {
        state_record.status = if state_record.due_state == KeyRotationDueState::Current {
            KeyRotationRuntimeStatus::Current
        } else {
            KeyRotationRuntimeStatus::Skipped
        };
        state_record.last_operation = KeyRotationOperation::None;
        persist_key_rotation_state(state, &state_record).await;
        return key_rotation_attempt_response(
            record,
            &state_record,
            operation,
            recommendation,
            &previous_key_material,
            None,
        );
    }

    state_record.status = KeyRotationRuntimeStatus::Running;
    state_record.last_operation = operation;
    persist_key_rotation_state(state, &state_record).await;

    let rotated_payload = match operation {
        KeyRotationOperation::KekRewrap => state.cipher.rewrap(&record.encrypted_payload),
        KeyRotationOperation::DekRotation | KeyRotationOperation::DekRotationAndKekRefresh => state
            .cipher
            .decrypt(&record.encrypted_payload)
            .and_then(|plaintext| state.cipher.encrypt(&plaintext)),
        KeyRotationOperation::None => Ok(record.encrypted_payload.clone()),
    };

    let rotated_payload = match rotated_payload {
        Ok(payload) => payload,
        Err(error) => {
            state_record.status = KeyRotationRuntimeStatus::Failed;
            state_record.last_error = Some(error.to_string());
            state_record.updated_at = Utc::now();
            persist_key_rotation_state(state, &state_record).await;
            return key_rotation_attempt_response(
                record,
                &state_record,
                operation,
                recommendation,
                &previous_key_material,
                state_record.last_error.clone(),
            );
        }
    };

    let updated_result = {
        let mut snapshots = state.snapshots.lock().expect("snapshot store");
        if snapshots.get_any(&record.snapshot_id).is_err() {
            snapshots.restore_record(record.clone());
        }
        if let Err(error) = snapshots.mark_rewrapped(&record.snapshot_id, rotated_payload, now) {
            Err(error.to_string())
        } else {
            snapshots
                .get_any(&record.snapshot_id)
                .map_err(|error| error.to_string())
        }
    };
    let updated = match updated_result {
        Ok(updated) => updated,
        Err(error) => {
            state_record.status = KeyRotationRuntimeStatus::Failed;
            state_record.last_error = Some(error);
            state_record.updated_at = Utc::now();
            persist_key_rotation_state(state, &state_record).await;
            return key_rotation_attempt_response(
                record,
                &state_record,
                operation,
                recommendation,
                &previous_key_material,
                state_record.last_error.clone(),
            );
        }
    };

    if let Some(persistence) = &state.persistence
        && let Err(error) = persistence.save_snapshot(&updated).await
    {
        state_record.status = KeyRotationRuntimeStatus::Failed;
        state_record.last_error = Some(error.to_string());
        state_record.updated_at = Utc::now();
        persist_key_rotation_state(state, &state_record).await;
        return key_rotation_attempt_response(
            &updated,
            &state_record,
            operation,
            recommendation,
            &previous_key_material,
            state_record.last_error.clone(),
        );
    }

    let key_material_created_at = if matches!(
        operation,
        KeyRotationOperation::DekRotation | KeyRotationOperation::DekRotationAndKekRefresh
    ) {
        Some(now)
    } else {
        None
    };
    state_record = rotation_state_for_record_with_key_created_at(
        state,
        &updated,
        Utc::now(),
        key_material_created_at,
    );
    state_record.status = KeyRotationRuntimeStatus::Completed;
    state_record.last_operation = operation;
    state_record.last_cycle_id = Some(cycle_id.to_string());
    state_record.last_error = None;
    persist_key_rotation_state(state, &state_record).await;
    key_rotation_attempt_response(
        &updated,
        &state_record,
        operation,
        recommendation,
        &previous_key_material,
        None,
    )
}

fn choose_key_rotation_operation(
    state: &Arc<ApiState>,
    recommendation: &sdqp_encryption::RotationRecommendation,
    request: &KeyRotationRunRequest,
) -> KeyRotationOperation {
    let include_dek = request.include_dek_rotation.unwrap_or(true);
    let include_kek = request.include_kek_rewrap.unwrap_or(true);
    let dek_requested = state.key_rotation.allow_dek_rotation
        && include_dek
        && (recommendation.rotate_dek || request.force);
    let kek_requested = state.key_rotation.allow_kek_rewrap
        && include_kek
        && (recommendation.rotate_kek_wrap || request.force);

    match (dek_requested, kek_requested) {
        (true, true) => KeyRotationOperation::DekRotationAndKekRefresh,
        (true, false) => KeyRotationOperation::DekRotation,
        (false, true) => KeyRotationOperation::KekRewrap,
        (false, false) => KeyRotationOperation::None,
    }
}

async fn ensure_key_rotation_states(
    state: &Arc<ApiState>,
    tenant_filter: Option<&str>,
) -> Result<Vec<KeyRotationState>, Response> {
    let now = Utc::now();
    let snapshots = load_key_rotation_snapshots(state).await.map_err(|error| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to load key rotation inventory: {error}"),
        )
    })?;
    let mut states = Vec::new();
    for snapshot in snapshots {
        if tenant_filter.is_some_and(|tenant_id| snapshot.tenant_id != tenant_id) {
            continue;
        }
        let computed = rotation_state_for_record(state, &snapshot, now);
        let existing = state
            .key_rotation_states
            .lock()
            .expect("key rotation states")
            .get(&computed.inventory_id)
            .cloned();
        let merged = merge_key_rotation_state(computed, existing);
        persist_key_rotation_state(state, &merged).await;
        states.push(merged);
    }

    states.sort_by(|left, right| {
        left.tenant_id
            .cmp(&right.tenant_id)
            .then(left.project_id.cmp(&right.project_id))
            .then(left.snapshot_id.cmp(&right.snapshot_id))
    });
    Ok(states)
}

async fn load_key_rotation_snapshots(
    state: &Arc<ApiState>,
) -> Result<Vec<EncryptedSnapshotRecord>, String> {
    if let Some(persistence) = &state.persistence {
        let snapshots = persistence
            .load_snapshots()
            .await
            .map_err(|error| error.to_string())?;
        {
            let mut store = state.snapshots.lock().expect("snapshot store");
            for snapshot in &snapshots {
                store.restore_record(snapshot.clone());
            }
        }
        return Ok(snapshots);
    }

    let states = state
        .key_rotation_states
        .lock()
        .expect("key rotation states");
    Ok(states
        .values()
        .filter_map(|rotation_state| {
            state
                .snapshots
                .lock()
                .expect("snapshot store")
                .get_any(&rotation_state.snapshot_id)
                .ok()
        })
        .collect())
}

fn rotation_state_for_record(
    state: &Arc<ApiState>,
    record: &EncryptedSnapshotRecord,
    now: DateTime<Utc>,
) -> KeyRotationState {
    let inventory_id = format!("snapshot:{}", record.snapshot_id);
    let key_material_created_at = state
        .key_rotation_states
        .lock()
        .expect("key rotation states")
        .get(&inventory_id)
        .filter(|existing| existing.dek_id == record.encrypted_payload.dek_id)
        .map(|existing| existing.created_at);

    rotation_state_for_record_with_key_created_at(state, record, now, key_material_created_at)
}

fn rotation_state_for_record_with_key_created_at(
    state: &Arc<ApiState>,
    record: &EncryptedSnapshotRecord,
    now: DateTime<Utc>,
    key_material_created_at: Option<DateTime<Utc>>,
) -> KeyRotationState {
    state.rotation_policy.inventory_state(
        &KeyRotationInventoryItem {
            snapshot_id: record.snapshot_id.clone(),
            tenant_id: record.tenant_id.clone(),
            project_id: record.project_id.clone(),
            provider: record.encrypted_payload.kms_provider.clone(),
            kek_id: record.encrypted_payload.kek_id.clone(),
            key_version: record.encrypted_payload.key_version.clone(),
            dek_id: record.encrypted_payload.dek_id.clone(),
            created_at: key_material_created_at.unwrap_or(record.created_at),
            last_rewrapped_at: record.lifecycle.last_rewrapped_at,
            purged: record.lifecycle.delete_state.as_str() == "purged",
        },
        now,
        state.key_rotation.enabled,
    )
}

fn merge_key_rotation_state(
    mut computed: KeyRotationState,
    existing: Option<KeyRotationState>,
) -> KeyRotationState {
    let Some(existing) = existing else {
        return computed;
    };
    if computed.due_state == KeyRotationDueState::Current
        && matches!(
            existing.status,
            KeyRotationRuntimeStatus::Completed | KeyRotationRuntimeStatus::Current
        )
    {
        computed.status = existing.status;
        computed.last_operation = existing.last_operation;
        computed.last_cycle_id = existing.last_cycle_id;
        computed.last_error = existing.last_error;
    }
    computed
}

async fn persist_key_rotation_state(state: &Arc<ApiState>, rotation_state: &KeyRotationState) {
    {
        state
            .key_rotation_states
            .lock()
            .expect("key rotation states")
            .insert(rotation_state.inventory_id.clone(), rotation_state.clone());
    }
    if let Some(persistence) = &state.persistence
        && let Err(error) = persistence.save_key_rotation_state(rotation_state).await
    {
        tracing::warn!(?error, "failed to persist key rotation state");
    }
}

struct PreviousKeyMaterial {
    provider: String,
    kek_id: String,
    key_version: Option<String>,
    dek_id: String,
}

fn key_rotation_attempt_response(
    record: &EncryptedSnapshotRecord,
    rotation_state: &KeyRotationState,
    operation: KeyRotationOperation,
    recommendation: sdqp_encryption::RotationRecommendation,
    previous: &PreviousKeyMaterial,
    error: Option<String>,
) -> KeyRotationAttemptResponse {
    KeyRotationAttemptResponse {
        snapshot_id: record.snapshot_id.clone(),
        status: rotation_state.status.as_str().into(),
        operation: operation.as_str().into(),
        rotate_dek_due: recommendation.rotate_dek,
        rotate_kek_wrap_due: recommendation.rotate_kek_wrap,
        previous_kms_provider: previous.provider.clone(),
        previous_kek_id: previous.kek_id.clone(),
        previous_key_version: previous.key_version.clone(),
        previous_dek_id: previous.dek_id.clone(),
        current_kms_provider: record.encrypted_payload.kms_provider.clone(),
        current_kek_id: record.encrypted_payload.kek_id.clone(),
        current_key_version: record.encrypted_payload.key_version.clone(),
        current_dek_id: record.encrypted_payload.dek_id.clone(),
        last_rewrapped_at: record.lifecycle.last_rewrapped_at,
        due_state: rotation_state.due_state.as_str().into(),
        error,
    }
}

fn key_rotation_state_response(state: KeyRotationState) -> KeyRotationStateResponse {
    KeyRotationStateResponse {
        inventory_id: state.inventory_id,
        snapshot_id: state.snapshot_id,
        tenant_id: state.tenant_id,
        project_id: state.project_id,
        provider: state.provider,
        kek_id: state.kek_id,
        key_version: state.key_version,
        dek_id: state.dek_id,
        created_at: state.created_at,
        last_rewrapped_at: state.last_rewrapped_at,
        next_dek_rotation_due_at: state.next_dek_rotation_due_at,
        next_kek_rewrap_due_at: state.next_kek_rewrap_due_at,
        due_state: state.due_state.as_str().into(),
        status: state.status.as_str().into(),
        last_operation: state.last_operation.as_str().into(),
        last_cycle_id: state.last_cycle_id,
        last_error: state.last_error,
        updated_at: state.updated_at,
    }
}

fn key_rotation_run_response(
    cycle_id: String,
    trigger: KeyRotationTrigger,
    results: Vec<KeyRotationAttemptResponse>,
    audit_checkpoint_id: String,
) -> KeyRotationRunResponse {
    let rotated_deks = results
        .iter()
        .filter(|result| {
            matches!(
                result.operation.as_str(),
                "dek_rotation" | "dek_rotation_and_kek_refresh"
            ) && result.status == "completed"
        })
        .count();
    let rewrapped_keks = results
        .iter()
        .filter(|result| {
            matches!(
                result.operation.as_str(),
                "kek_rewrap" | "dek_rotation_and_kek_refresh"
            ) && result.status == "completed"
        })
        .count();
    let skipped = results
        .iter()
        .filter(|result| result.status == "skipped" || result.operation == "none")
        .count();
    let failed = results
        .iter()
        .filter(|result| result.status == "failed")
        .count();

    KeyRotationRunResponse {
        cycle_id,
        trigger: trigger.as_str().into(),
        evaluated: results.len(),
        rotated_deks,
        rewrapped_keks,
        skipped,
        failed,
        audit_checkpoint_id,
        results,
        tee_key_release_boundary: tee_key_release_boundary(),
    }
}

async fn append_key_rotation_audit(
    state: &Arc<ApiState>,
    actor: ActorInfo,
    tenant_id: &str,
    project_id: Option<&str>,
    cycle_id: &str,
    trigger: KeyRotationTrigger,
    result: &KeyRotationAttemptResponse,
) -> AuditCheckpoint {
    let action_result = match result.status.as_str() {
        "completed" | "current" | "skipped" => ActionResult::Success,
        "failed" => ActionResult::Failure,
        _ => ActionResult::Denied,
    };
    crate::record_audit_event_from_parts_with_fields(
        state,
        actor,
        ActionType::ConfigChange,
        TargetRef {
            tenant_id: tenant_id.to_string(),
            project_id: project_id.map(str::to_string),
            resource_id: format!("key-rotation/{}", result.snapshot_id),
        },
        format!(
            "key lifecycle rotation {} for {}",
            result.status, result.snapshot_id
        ),
        AuditContextFields::builder()
            .field("cycle_id", cycle_id.to_string())
            .field("trigger", trigger.as_str())
            .field("snapshot_id", result.snapshot_id.clone())
            .field("operation", result.operation.clone())
            .field("status", result.status.clone())
            .field("provider", result.current_kms_provider.clone())
            .field("kek_id", result.current_kek_id.clone())
            .field(
                "key_version",
                result
                    .current_key_version
                    .clone()
                    .unwrap_or_else(|| "none".into()),
            )
            .field("dek_id", result.current_dek_id.clone())
            .field("previous_provider", result.previous_kms_provider.clone())
            .field(
                "previous_key_version",
                result
                    .previous_key_version
                    .clone()
                    .unwrap_or_else(|| "none".into()),
            )
            .field("previous_dek_id", result.previous_dek_id.clone())
            .field(
                "last_rewrapped_at",
                result
                    .last_rewrapped_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "none".into()),
            )
            .field("due_state", result.due_state.clone())
            .field("rotate_dek_due", result.rotate_dek_due)
            .field("rotate_kek_wrap_due", result.rotate_kek_wrap_due)
            .field("tee_key_release_boundary", tee_key_release_boundary())
            .build(),
        action_result,
        None,
    )
    .await
}

fn tee_key_release_boundary() -> String {
    "provider-ready boundary: protected snapshot routes enforce TEE attestation before decrypt; external enclave-bound KMS release requires real TEE provider infrastructure".into()
}

async fn load_scoped_snapshot_any(
    state: &Arc<ApiState>,
    snapshot_id: &str,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
) -> Result<EncryptedSnapshotRecord, crate::ApiErrorResponse> {
    let cached = state
        .snapshots
        .lock()
        .expect("snapshot store")
        .get_any(snapshot_id)
        .ok();

    let record = match cached {
        Some(record) => record,
        None => {
            let Some(persistence) = &state.persistence else {
                return Err(Box::new(json_error(
                    StatusCode::NOT_FOUND,
                    "snapshot not found",
                )));
            };
            match persistence.load_snapshot(snapshot_id).await {
                Ok(Some(record)) => {
                    state
                        .snapshots
                        .lock()
                        .expect("snapshot store")
                        .restore_record(record.clone());
                    record
                }
                _ => {
                    return Err(Box::new(json_error(
                        StatusCode::NOT_FOUND,
                        "snapshot not found",
                    )));
                }
            }
        }
    };

    let scoped_project = request_context
        .project_id
        .as_ref()
        .expect("project scope")
        .as_str();
    if record.tenant_id != request_context.tenant_id.as_str() || record.project_id != scoped_project
    {
        phase2::append_phase2_audit(
            state,
            session,
            request_context,
            ActionType::View,
            ActionResult::Denied,
            snapshot_id,
            "snapshot scope mismatch",
            None,
        )
        .await;
        return Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "snapshot scope mismatch",
        )));
    }

    Ok(record)
}

async fn lifecycle_response(state: &Arc<ApiState>, record: EncryptedSnapshotRecord) -> Response {
    let object_present = state
        .snapshot_objects
        .exists(&record.lifecycle.object_bucket, &record.storage_key)
        .await
        .unwrap_or(false);
    let controlled_deletion = load_controlled_deletion_for_snapshot(state, &record).await;

    Json(SnapshotLifecycleResponse {
        snapshot_id: record.snapshot_id,
        grant_id: record.lifecycle.grant_id,
        delete_state: record.lifecycle.delete_state.as_str().to_string(),
        delete_reason: record.lifecycle.delete_reason,
        deleted_at: record.lifecycle.deleted_at,
        purged_at: record.lifecycle.purged_at,
        grant_expires_at: record.lifecycle.grant_expires_at,
        retention_until: record.lifecycle.retention_until,
        last_rewrapped_at: record.lifecycle.last_rewrapped_at,
        kms_provider: record.encrypted_payload.kms_provider,
        kek_id: record.encrypted_payload.kek_id,
        key_version: record.encrypted_payload.key_version,
        object_bucket: record.lifecycle.object_bucket,
        object_key: record.storage_key,
        object_size_bytes: record.lifecycle.object_size_bytes,
        object_present,
        controlled_deletion,
    })
    .into_response()
}

fn snapshot_lifecycle_audit_fields(
    record: &EncryptedSnapshotRecord,
) -> sdqp_audit::AuditContextFields {
    let mut fields = phase2::snapshot_encryption_audit_fields(record);
    if let Some(delete_reason) = &record.lifecycle.delete_reason {
        fields.insert("delete_reason", delete_reason.clone());
    }
    if let Some(deleted_at) = record.lifecycle.deleted_at {
        fields.insert("deleted_at", deleted_at.to_rfc3339());
    }
    if let Some(purged_at) = record.lifecycle.purged_at {
        fields.insert("purged_at", purged_at.to_rfc3339());
    }
    fields
}

async fn refresh_snapshot_record(
    state: &Arc<ApiState>,
    snapshot_id: &str,
) -> Result<EncryptedSnapshotRecord, crate::ApiErrorResponse> {
    let record = {
        let store = state.snapshots.lock().expect("snapshot store");
        match store.get_any(snapshot_id) {
            Ok(record) => record,
            Err(error) => return Err(snapshot_store_error_response_boxed(error)),
        }
    };

    if let Some(persistence) = &state.persistence
        && persistence.save_snapshot(&record).await.is_err()
    {
        return Err(Box::new(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist snapshot lifecycle",
        )));
    }

    Ok(record)
}

async fn remove_snapshot_from_cache(state: &Arc<ApiState>, snapshot_id: &str) {
    state
        .cache_index
        .lock()
        .expect("cache index")
        .retain(|_, cached_snapshot_id| cached_snapshot_id != snapshot_id);
    if let Some(persistence) = &state.persistence {
        let _ = persistence
            .delete_cache_entries_for_snapshot(snapshot_id)
            .await;
    }
}

async fn delete_snapshot_object_if_present(
    state: &Arc<ApiState>,
    record: &EncryptedSnapshotRecord,
) -> Result<bool, Response> {
    let exists = state
        .snapshot_objects
        .exists(&record.lifecycle.object_bucket, &record.storage_key)
        .await
        .map_err(|error| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to inspect snapshot object: {error}"),
            )
        })?;
    if exists {
        state
            .snapshot_objects
            .delete_object(&record.lifecycle.object_bucket, &record.storage_key)
            .await
            .map_err(|error| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to purge snapshot object: {error}"),
                )
            })?;
    }
    Ok(exists)
}

fn actor_from_session(session: &AuthenticatedSession) -> ActorInfo {
    ActorInfo {
        user_id: session.claims.user_id.clone(),
        session_id: session.claims.session_id.clone(),
        ip_address: session.claims.binding.ip_address.clone(),
    }
}

fn snapshot_controlled_deletion_flow(
    state: &Arc<ApiState>,
    record: &EncryptedSnapshotRecord,
    actor: ActorInfo,
    reason: &str,
    now: DateTime<Utc>,
) -> ControlledDeletionFlow {
    ControlledDeletionFlow::new(
        ControlledDeletionSubject {
            kind: ControlledDeletionSubjectKind::Snapshot,
            tenant_id: record.tenant_id.clone(),
            project_id: Some(record.project_id.clone()),
            resource_id: record.snapshot_id.clone(),
            content_fingerprint: Some(record.lifecycle.data_fingerprint.clone()),
            storage_fingerprint: Some(storage_fingerprint(record)),
        },
        actor,
        reason,
        tombstone_retain_until(state, record, now),
        current_audit_chain_evidence(state, now),
        now,
    )
}

fn tombstone_retain_until(
    state: &Arc<ApiState>,
    record: &EncryptedSnapshotRecord,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    let audit_retain_until =
        now + Duration::seconds(state.audit_retention.evidence_retention_secs.max(0));
    record.lifecycle.retention_until.max(audit_retain_until)
}

fn current_audit_chain_evidence(
    state: &Arc<ApiState>,
    captured_at: DateTime<Utc>,
) -> ControlledDeletionChainEvidence {
    let audit = state.audit.lock().expect("audit");
    let latest_checkpoint = audit.checkpoints().last();
    ControlledDeletionChainEvidence {
        captured_at,
        event_count: audit.events().len(),
        latest_event_hash: audit.latest_event_hash(),
        checkpoint_id: latest_checkpoint.map(|checkpoint| checkpoint.checkpoint_id.clone()),
        checkpoint_signature: latest_checkpoint.map(|checkpoint| checkpoint.signature.clone()),
    }
}

fn checkpoint_chain_evidence(
    checkpoint: &AuditCheckpoint,
    captured_at: DateTime<Utc>,
) -> ControlledDeletionChainEvidence {
    ControlledDeletionChainEvidence {
        captured_at,
        event_count: checkpoint.event_count,
        latest_event_hash: Some(checkpoint.last_event_hash.clone()),
        checkpoint_id: Some(checkpoint.checkpoint_id.clone()),
        checkpoint_signature: Some(checkpoint.signature.clone()),
    }
}

fn latest_audit_checkpoint(state: &Arc<ApiState>) -> Option<AuditCheckpoint> {
    state
        .audit
        .lock()
        .expect("audit")
        .checkpoints()
        .last()
        .cloned()
}

fn populate_logical_delete_tombstone(
    flow: &mut ControlledDeletionFlow,
    before: &EncryptedSnapshotRecord,
    after: &EncryptedSnapshotRecord,
    at: DateTime<Utc>,
) {
    let record = flow.record_mut();
    record.tombstone.logical_deleted_at = Some(at);
    record.tombstone.retained_fields = retained_snapshot_fields(before, after);
    record.tombstone.redacted_fields = redacted_snapshot_fields();
    record.tombstone.logically_deleted_content = vec![ControlledDeletionContentRef {
        content_type: "encrypted_snapshot".into(),
        content_id: before.snapshot_id.clone(),
        fingerprint: Some(before.lifecycle.data_fingerprint.clone()),
        effect: "logical_delete:lifecycle_non_active".into(),
    }];
    record.tombstone.purged_content = vec![ControlledDeletionContentRef {
        content_type: "snapshot_cache_entries".into(),
        content_id: before.snapshot_id.clone(),
        fingerprint: None,
        effect: "cache_unlinked_from_deleted_snapshot".into(),
    }];
    record.tombstone.retained_evidence = retained_evidence_refs(before, &record.tombstone);
    record.tombstone.refresh_hash();
}

fn populate_content_purge_tombstone(
    flow: &mut ControlledDeletionFlow,
    before: &EncryptedSnapshotRecord,
    after: &EncryptedSnapshotRecord,
    object_existed: bool,
    at: DateTime<Utc>,
) {
    let record = flow.record_mut();
    record.tombstone.logical_deleted_at = after.lifecycle.deleted_at;
    record.tombstone.content_purged_at = Some(at);
    record.tombstone.retained_fields = retained_snapshot_fields(before, after);
    record.tombstone.redacted_fields = redacted_snapshot_fields();
    record.tombstone.logically_deleted_content = vec![ControlledDeletionContentRef {
        content_type: "snapshot_lifecycle".into(),
        content_id: before.snapshot_id.clone(),
        fingerprint: Some(before.lifecycle.data_fingerprint.clone()),
        effect: "retained_as_purged_metadata_only".into(),
    }];
    record.tombstone.purged_content = vec![
        ControlledDeletionContentRef {
            content_type: "snapshot_object".into(),
            content_id: storage_fingerprint(before),
            fingerprint: Some(encrypted_payload_fingerprint(before)),
            effect: if object_existed {
                "object_deleted"
            } else {
                "object_absence_verified"
            }
            .into(),
        },
        ControlledDeletionContentRef {
            content_type: "snapshot_cache_entries".into(),
            content_id: before.snapshot_id.clone(),
            fingerprint: None,
            effect: "cache_unlinked_from_purged_snapshot".into(),
        },
    ];
    record.tombstone.retained_evidence = retained_evidence_refs(before, &record.tombstone);
    record.tombstone.refresh_hash();
}

fn retained_snapshot_fields(
    before: &EncryptedSnapshotRecord,
    after: &EncryptedSnapshotRecord,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("snapshot_id".into(), before.snapshot_id.clone()),
        ("tenant_id".into(), before.tenant_id.clone()),
        ("project_id".into(), before.project_id.clone()),
        ("data_source_id".into(), before.data_source_id.clone()),
        (
            "owner_user_id".into(),
            before.lifecycle.owner_user_id.clone(),
        ),
        ("grant_id".into(), before.lifecycle.grant_id.clone()),
        (
            "delete_state_before".into(),
            before.lifecycle.delete_state.as_str().to_string(),
        ),
        (
            "delete_state_after".into(),
            after.lifecycle.delete_state.as_str().to_string(),
        ),
        ("row_count".into(), before.row_count.to_string()),
        ("columns_count".into(), before.columns.len().to_string()),
        (
            "payload_format".into(),
            before.payload_format.as_str().into(),
        ),
        (
            "data_fingerprint".into(),
            before.lifecycle.data_fingerprint.clone(),
        ),
        (
            "object_bucket".into(),
            before.lifecycle.object_bucket.clone(),
        ),
        ("object_key_hash".into(), storage_fingerprint(before)),
        (
            "object_size_bytes".into(),
            before.lifecycle.object_size_bytes.to_string(),
        ),
        (
            "encrypted_payload_hash".into(),
            encrypted_payload_fingerprint(before),
        ),
        (
            "retention_until".into(),
            before.lifecycle.retention_until.to_rfc3339(),
        ),
    ])
}

fn redacted_snapshot_fields() -> Vec<String> {
    vec![
        "encrypted_payload_json".into(),
        "wrapped_dek_b64".into(),
        "ciphertext".into(),
        "snapshot_storage_key_plaintext".into(),
        "raw_columns".into(),
    ]
}

fn retained_evidence_refs(
    before: &EncryptedSnapshotRecord,
    tombstone: &sdqp_audit::AuditTombstone,
) -> Vec<ControlledDeletionContentRef> {
    let mut evidence = vec![
        ControlledDeletionContentRef {
            content_type: "audit_tombstone".into(),
            content_id: tombstone.tombstone_id.clone(),
            fingerprint: None,
            effect: "retained_until_regulatory_deadline".into(),
        },
        ControlledDeletionContentRef {
            content_type: "snapshot_metadata".into(),
            content_id: before.snapshot_id.clone(),
            fingerprint: Some(before.lifecycle.data_fingerprint.clone()),
            effect: "metadata_retained_without_payload".into(),
        },
    ];
    if let Some(hash) = &tombstone.pre_delete_chain.latest_event_hash {
        evidence.push(ControlledDeletionContentRef {
            content_type: "audit_chain_pre_delete_hash".into(),
            content_id: hash.clone(),
            fingerprint: Some(hash.clone()),
            effect: "verifies_chain_state_before_delete".into(),
        });
    }
    evidence
}

fn storage_fingerprint(record: &EncryptedSnapshotRecord) -> String {
    controlled_deletion_digest(
        format!("{}:{}", record.lifecycle.object_bucket, record.storage_key).as_bytes(),
    )
}

fn encrypted_payload_fingerprint(record: &EncryptedSnapshotRecord) -> String {
    controlled_deletion_digest(
        &serde_json::to_vec(&record.encrypted_payload).expect("encrypted payload serializes"),
    )
}

fn extend_controlled_deletion_audit_fields(
    fields: &mut AuditContextFields,
    record: &ControlledDeletionRecord,
) {
    fields.insert("controlled_deletion_id", record.deletion_id.clone());
    fields.insert("controlled_deletion_state", record.state.as_str());
    fields.insert("evidence_grade_delete_flow", true);
    fields.insert("tombstone_id", record.tombstone.tombstone_id.clone());
    fields.insert("tombstone_hash", record.tombstone.tombstone_hash.clone());
    fields.insert(
        "tombstone_retain_until",
        record.tombstone.retain_until.to_rfc3339(),
    );
    fields.insert(
        "logically_deleted_content",
        serde_json::to_string(&record.tombstone.logically_deleted_content)
            .expect("logically deleted content serializes"),
    );
    fields.insert(
        "purged_content",
        serde_json::to_string(&record.tombstone.purged_content).expect("purged content serializes"),
    );
    fields.insert(
        "retained_evidence",
        serde_json::to_string(&record.tombstone.retained_evidence)
            .expect("retained evidence serializes"),
    );
    if let Some(hash) = &record.tombstone.pre_delete_chain.latest_event_hash {
        fields.insert("pre_delete_audit_hash", hash.clone());
    }
    if let Some(checkpoint_id) = &record.tombstone.pre_delete_chain.checkpoint_id {
        fields.insert("pre_delete_checkpoint_id", checkpoint_id.clone());
    }
}

fn seal_controlled_deletion_flow(
    state: &Arc<ApiState>,
    flow: &mut ControlledDeletionFlow,
    checkpoint: &AuditCheckpoint,
    actor_user_id: String,
    at: DateTime<Utc>,
) {
    flow.transition_to(
        ControlledDeletionState::AuditRecorded,
        actor_user_id.clone(),
        "controlled deletion audit event appended to hash chain",
        at,
    );
    flow.transition_to(
        ControlledDeletionState::Completed,
        actor_user_id,
        "controlled deletion evidence sealed",
        at,
    );
    flow.seal_audit_evidence(
        checkpoint_chain_evidence(checkpoint, at),
        Some(checkpoint.last_event_hash.clone()),
        Some(checkpoint.checkpoint_id.clone()),
    );
    debug_assert!(sdqp_audit::verify_chain(
        state.audit.lock().expect("audit").events()
    ));
}

async fn save_controlled_deletion_record(
    state: &Arc<ApiState>,
    record: ControlledDeletionRecord,
) -> Result<(), Response> {
    state
        .controlled_deletions
        .lock()
        .expect("controlled deletions")
        .insert(
            controlled_deletion_key(&record.tombstone.subject),
            record.clone(),
        );
    if let Some(persistence) = &state.persistence
        && persistence
            .save_controlled_deletion_record(&record)
            .await
            .is_err()
    {
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist controlled deletion tombstone",
        ));
    }
    Ok(())
}

async fn load_controlled_deletion_for_snapshot(
    state: &Arc<ApiState>,
    record: &EncryptedSnapshotRecord,
) -> Option<ControlledDeletionRecord> {
    let subject = ControlledDeletionSubject {
        kind: ControlledDeletionSubjectKind::Snapshot,
        tenant_id: record.tenant_id.clone(),
        project_id: Some(record.project_id.clone()),
        resource_id: record.snapshot_id.clone(),
        content_fingerprint: Some(record.lifecycle.data_fingerprint.clone()),
        storage_fingerprint: Some(storage_fingerprint(record)),
    };
    let key = controlled_deletion_key(&subject);
    if let Some(record) = state
        .controlled_deletions
        .lock()
        .expect("controlled deletions")
        .get(&key)
        .cloned()
    {
        return Some(record);
    }
    if let Some(persistence) = &state.persistence
        && let Ok(Some(record)) = persistence
            .load_controlled_deletion_record(
                ControlledDeletionSubjectKind::Snapshot,
                &subject.resource_id,
            )
            .await
    {
        state
            .controlled_deletions
            .lock()
            .expect("controlled deletions")
            .insert(key, record.clone());
        return Some(record);
    }
    None
}

fn controlled_deletion_key(subject: &ControlledDeletionSubject) -> String {
    format!("{}:{}", subject.kind.as_str(), subject.resource_id)
}

fn snapshot_store_error_response(error: SnapshotStoreError) -> Response {
    match error {
        SnapshotStoreError::NotFound => json_error(StatusCode::NOT_FOUND, "snapshot not found"),
        SnapshotStoreError::NotActive => json_error(StatusCode::CONFLICT, "snapshot is not active"),
        SnapshotStoreError::Purged => json_error(StatusCode::CONFLICT, "snapshot has been purged"),
    }
}

fn snapshot_store_error_response_boxed(error: SnapshotStoreError) -> crate::ApiErrorResponse {
    Box::new(snapshot_store_error_response(error))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Extension,
        extract::{Path, State},
        http::StatusCode,
    };
    use chrono::{Duration, Utc};
    use sdqp_config::AppSettings;
    use sdqp_core::{ProjectId, TenantId, UserId};
    use sdqp_encryption::{
        EnvelopeCipher, SnapshotDeleteState, SnapshotStore, SnapshotWriteRequest,
    };
    use sdqp_system_security::{Role, SessionBinding, SessionPolicy};

    use crate::{AuthenticatedSession, phase2::build_query_runtime};

    use super::{purge_snapshot_handler, soft_delete_snapshot_handler};

    #[test]
    fn phase8_refresh_rewraps_snapshot_to_active_provider() {
        let mut mock_settings = AppSettings::local_dev();
        mock_settings.kms.provider = "mock".into();
        let (_, _, mut snapshots, _, _, _, _, mock_cipher, _) = build_query_runtime(&mock_settings);
        let encrypted = mock_cipher.encrypt(b"snapshot-refresh").expect("encrypted");
        let record = snapshots.put(
            SnapshotWriteRequest {
                tenant_id: "tenant-alpha".into(),
                project_id: "project-alpha".into(),
                owner_user_id: "user-analyst".into(),
                grant_id: "grant-alpha".into(),
                grant_expires_at: Utc::now() + Duration::hours(8),
                retention_until: Utc::now() + Duration::hours(8),
                data_source_id: "datasource-rest".into(),
                object_bucket: "sdqp-snapshots".into(),
                data_fingerprint: "fingerprint-a".into(),
                columns: vec!["employee_id".into()],
                payload_format: sdqp_encryption::SnapshotPayloadFormat::JsonRows,
            },
            encrypted,
            1,
        );

        let mut vault_settings = AppSettings::local_dev();
        vault_settings.kms.provider = "vault".into();
        vault_settings.kms.key_version = "5".into();
        let (_, _, _, _, _, _, _, vault_cipher, _) = build_query_runtime(&vault_settings);
        let rewrapped = vault_cipher
            .rewrap(&record.encrypted_payload)
            .expect("rewrapped");
        let decrypted = vault_cipher.decrypt(&rewrapped).expect("decrypted");

        assert_eq!(decrypted, b"snapshot-refresh");
        assert_eq!(rewrapped.kms_provider, "vault");
        assert_eq!(rewrapped.key_version.as_deref(), Some("5"));
        assert_ne!(
            rewrapped.wrapped_dek_b64,
            record.encrypted_payload.wrapped_dek_b64
        );
    }

    #[tokio::test]
    async fn key_rotation_dek_rotation_advances_dek_due_from_new_key_material() {
        let mut settings = AppSettings::local_dev();
        settings.kms.provider = "mock".into();
        settings.kms.rotation.dek_rotation_days = 90;
        settings.kms.rotation.kek_rotation_days = 365;
        let state = Arc::new(crate::ApiState::from_app_settings(settings.clone()));
        let now = Utc::now();
        let encrypted = state
            .cipher
            .encrypt(b"key-rotation-lifecycle")
            .expect("encrypted");
        let mut record = {
            let mut snapshots = state.snapshots.lock().expect("snapshot store");
            snapshots.put(
                SnapshotWriteRequest {
                    tenant_id: "tenant-alpha".into(),
                    project_id: "project-alpha".into(),
                    owner_user_id: "user-sysadmin".into(),
                    grant_id: "grant-key-rotation".into(),
                    grant_expires_at: now + Duration::hours(8),
                    retention_until: now + Duration::hours(8),
                    data_source_id: "datasource-rest".into(),
                    object_bucket: settings.object_store.bucket_snapshots.clone(),
                    data_fingerprint: "fingerprint-key-rotation".into(),
                    columns: vec!["employee_id".into()],
                    payload_format: sdqp_encryption::SnapshotPayloadFormat::JsonRows,
                },
                encrypted,
                1,
            )
        };
        let original_dek_id = record.encrypted_payload.dek_id.clone();
        record.created_at = now - Duration::days(120);
        record.lifecycle.last_rewrapped_at = Some(now - Duration::days(10));
        {
            state
                .snapshots
                .lock()
                .expect("snapshot store")
                .restore_record(record.clone());
        }

        let initial_state = super::rotation_state_for_record(&state, &record, now);
        assert_eq!(
            initial_state.due_state,
            sdqp_encryption::KeyRotationDueState::DekRotationDue
        );

        let result = super::rotate_snapshot_key_material(
            &state,
            &record,
            &super::KeyRotationRunRequest::default(),
            "cycle-unit",
        )
        .await;

        assert_eq!(result.status, "completed");
        assert_eq!(result.operation, "dek_rotation");
        assert_eq!(result.due_state, "current");
        assert_ne!(result.current_dek_id, original_dek_id);

        let updated = state
            .snapshots
            .lock()
            .expect("snapshot store")
            .get_any(&record.snapshot_id)
            .expect("updated snapshot");
        let after_state = super::rotation_state_for_record(&state, &updated, Utc::now());
        assert_eq!(
            after_state.due_state,
            sdqp_encryption::KeyRotationDueState::Current
        );
        assert!(after_state.created_at > record.created_at);
        assert!(after_state.next_dek_rotation_due_at > now + Duration::days(80));
    }

    #[tokio::test]
    async fn controlled_deletion_uat_records_tombstone_and_audit_chain_evidence() {
        let settings = AppSettings::local_dev();
        let state = Arc::new(crate::ApiState::from_app_settings(settings.clone()));
        let encrypted = state
            .cipher
            .encrypt(b"controlled-delete-snapshot")
            .expect("encrypted");
        let snapshot = {
            let mut snapshots = state.snapshots.lock().expect("snapshot store");
            snapshots.put(
                SnapshotWriteRequest {
                    tenant_id: "tenant-alpha".into(),
                    project_id: "project-alpha".into(),
                    owner_user_id: "user-sysadmin".into(),
                    grant_id: "grant-delete".into(),
                    grant_expires_at: Utc::now() + Duration::hours(8),
                    retention_until: Utc::now() + Duration::hours(8),
                    data_source_id: "datasource-rest".into(),
                    object_bucket: settings.object_store.bucket_snapshots.clone(),
                    data_fingerprint: "fingerprint-delete".into(),
                    columns: vec!["employee_id".into(), "department".into()],
                    payload_format: sdqp_encryption::SnapshotPayloadFormat::JsonRows,
                },
                encrypted,
                2,
            )
        };

        let delete_response = soft_delete_snapshot_handler(
            State(state.clone()),
            Path(snapshot.snapshot_id.clone()),
            Extension(scoped_request_context()),
            Extension(authenticated_admin_session()),
        )
        .await;
        assert_eq!(delete_response.status(), StatusCode::OK);

        let deleted_record = state
            .snapshots
            .lock()
            .expect("snapshot store")
            .get_any(&snapshot.snapshot_id)
            .expect("deleted snapshot record");
        assert_ne!(
            deleted_record.lifecycle.delete_state,
            SnapshotDeleteState::Active
        );
        assert!(deleted_record.lifecycle.deleted_at.is_some());

        let logical_tombstone = state
            .controlled_deletions
            .lock()
            .expect("controlled deletions")
            .get(&format!("snapshot:{}", snapshot.snapshot_id))
            .expect("logical tombstone")
            .clone();
        assert!(sdqp_audit::verify_controlled_deletion_record(
            &logical_tombstone
        ));
        assert_eq!(
            logical_tombstone.state,
            sdqp_audit::ControlledDeletionState::Completed
        );
        assert!(
            logical_tombstone
                .tombstone
                .logically_deleted_content
                .iter()
                .any(|content| content.content_type == "encrypted_snapshot")
        );
        assert!(logical_tombstone.audit_checkpoint_id.is_some());
        assert!(logical_tombstone.evidence_hash.is_some());

        let purge_response = purge_snapshot_handler(
            State(state.clone()),
            Path(snapshot.snapshot_id.clone()),
            Extension(scoped_request_context()),
            Extension(authenticated_admin_session()),
        )
        .await;
        assert_eq!(purge_response.status(), StatusCode::OK);

        let purged_record = state
            .snapshots
            .lock()
            .expect("snapshot store")
            .get_any(&snapshot.snapshot_id)
            .expect("purged snapshot record");
        assert!(purged_record.lifecycle.purged_at.is_some());

        let purge_tombstone = state
            .controlled_deletions
            .lock()
            .expect("controlled deletions")
            .get(&format!("snapshot:{}", snapshot.snapshot_id))
            .expect("purge tombstone")
            .clone();
        assert!(sdqp_audit::verify_controlled_deletion_record(
            &purge_tombstone
        ));
        assert!(
            purge_tombstone
                .tombstone
                .purged_content
                .iter()
                .any(|content| content.content_type == "snapshot_object")
        );
        assert!(
            purge_tombstone
                .tombstone
                .retained_evidence
                .iter()
                .any(|content| content.content_type == "audit_tombstone")
        );

        let audit = state.audit.lock().expect("audit");
        assert!(sdqp_audit::verify_chain(audit.events()));
        assert!(audit.events().iter().any(|event| {
            event.context.contains("controlled deletion")
                && serde_json::to_string(&event.context_fields)
                    .expect("audit fields")
                    .contains("tombstone_hash")
        }));
    }

    fn scoped_request_context() -> sdqp_core::RequestContext {
        sdqp_core::RequestContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            UserId::new("user-sysadmin").expect("user"),
        )
        .with_project(ProjectId::new("project-alpha").expect("project"))
    }

    fn authenticated_admin_session() -> AuthenticatedSession {
        let request = sdqp_core::RequestContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            UserId::new("user-sysadmin").expect("user"),
        );
        let claims = SessionPolicy { ttl_minutes: 15 }.issue(
            &request,
            SessionBinding {
                ip_address: "127.0.0.1".into(),
                device_fingerprint: "device-delete".into(),
            },
        );
        AuthenticatedSession {
            claims,
            roles: vec![Role::SystemAdmin],
        }
    }
}
