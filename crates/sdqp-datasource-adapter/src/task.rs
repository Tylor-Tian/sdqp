use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use ulid::Ulid;

use crate::{SourceType, UnifiedQuery};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryTaskState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryTaskSnapshot {
    pub task_id: String,
    pub state: QueryTaskState,
    pub snapshot_id: Option<String>,
    pub cache_hit: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryTaskEvent {
    pub task_id: String,
    pub state: QueryTaskState,
    pub snapshot_id: Option<String>,
    pub cache_hit: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredQueryTask {
    pub task_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub user_id: String,
    pub project_scope_key: String,
    pub grant_id: String,
    pub grant_valid_until: DateTime<Utc>,
    pub data_source_id: String,
    pub source_type: SourceType,
    pub query: UnifiedQuery,
    pub cache_key: String,
    pub priority: i32,
    pub attempt_count: u32,
    pub max_attempts: u32,
}

#[derive(Debug)]
struct QueryTaskRecord {
    snapshot: QueryTaskSnapshot,
    sender: broadcast::Sender<QueryTaskEvent>,
}

#[derive(Debug, Default)]
pub struct QueryTaskRegistry {
    tasks: HashMap<String, QueryTaskRecord>,
}

impl QueryTaskRegistry {
    pub fn create_task(&mut self) -> String {
        let task_id = Ulid::new().to_string();
        self.restore_task(QueryTaskSnapshot {
            task_id: task_id.clone(),
            state: QueryTaskState::Pending,
            snapshot_id: None,
            cache_hit: false,
            error: None,
        });
        self.publish(&task_id);
        task_id
    }

    pub fn restore_task(&mut self, snapshot: QueryTaskSnapshot) {
        let (sender, _) = broadcast::channel(16);
        let record = QueryTaskRecord {
            snapshot: snapshot.clone(),
            sender,
        };
        self.tasks.insert(snapshot.task_id.clone(), record);
    }

    pub fn upsert_snapshot(&mut self, snapshot: QueryTaskSnapshot) {
        if let Some(record) = self.tasks.get_mut(&snapshot.task_id) {
            if record.snapshot == snapshot {
                return;
            }
            record.snapshot = snapshot.clone();
            let _ = record.sender.send(QueryTaskEvent {
                task_id: snapshot.task_id,
                state: snapshot.state,
                snapshot_id: snapshot.snapshot_id,
                cache_hit: snapshot.cache_hit,
                error: snapshot.error,
            });
            return;
        }

        self.restore_task(snapshot.clone());
        self.publish(&snapshot.task_id);
    }

    pub fn subscribe(&self, task_id: &str) -> Option<broadcast::Receiver<QueryTaskEvent>> {
        self.tasks
            .get(task_id)
            .map(|record| record.sender.subscribe())
    }

    pub fn mark_running(&mut self, task_id: &str) -> bool {
        self.update(task_id, |snapshot| snapshot.state = QueryTaskState::Running)
    }

    pub fn mark_completed(&mut self, task_id: &str, snapshot_id: String, cache_hit: bool) -> bool {
        self.update(task_id, |snapshot| {
            snapshot.state = QueryTaskState::Completed;
            snapshot.snapshot_id = Some(snapshot_id);
            snapshot.cache_hit = cache_hit;
            snapshot.error = None;
        })
    }

    pub fn mark_failed(&mut self, task_id: &str, error: String) -> bool {
        self.update(task_id, |snapshot| {
            snapshot.state = QueryTaskState::Failed;
            snapshot.error = Some(error);
        })
    }

    pub fn cancel(&mut self, task_id: &str) -> bool {
        self.update(task_id, |snapshot| {
            snapshot.state = QueryTaskState::Cancelled
        })
    }

    pub fn snapshot(&self, task_id: &str) -> Option<QueryTaskSnapshot> {
        self.tasks
            .get(task_id)
            .map(|record| record.snapshot.clone())
    }

    pub fn state(&self, task_id: &str) -> Option<QueryTaskState> {
        self.snapshot(task_id).map(|snapshot| snapshot.state)
    }

    pub fn update_state(&mut self, task_id: &str, state: QueryTaskState) -> bool {
        match state {
            QueryTaskState::Pending => self.update(task_id, |snapshot| {
                snapshot.state = QueryTaskState::Pending;
                snapshot.snapshot_id = None;
                snapshot.cache_hit = false;
                snapshot.error = None;
            }),
            QueryTaskState::Running => self.mark_running(task_id),
            QueryTaskState::Completed => {
                self.mark_completed(task_id, format!("snapshot-{task_id}"), false)
            }
            QueryTaskState::Failed => self.mark_failed(task_id, "task failed".into()),
            QueryTaskState::Cancelled => self.cancel(task_id),
        }
    }

    fn update(&mut self, task_id: &str, mutate: impl FnOnce(&mut QueryTaskSnapshot)) -> bool {
        let Some(record) = self.tasks.get_mut(task_id) else {
            return false;
        };
        mutate(&mut record.snapshot);
        let _ = record.sender.send(QueryTaskEvent {
            task_id: record.snapshot.task_id.clone(),
            state: record.snapshot.state.clone(),
            snapshot_id: record.snapshot.snapshot_id.clone(),
            cache_hit: record.snapshot.cache_hit,
            error: record.snapshot.error.clone(),
        });
        true
    }

    fn publish(&self, task_id: &str) {
        if let Some(record) = self.tasks.get(task_id) {
            let _ = record.sender.send(QueryTaskEvent {
                task_id: record.snapshot.task_id.clone(),
                state: record.snapshot.state.clone(),
                snapshot_id: record.snapshot.snapshot_id.clone(),
                cache_hit: record.snapshot.cache_hit,
                error: record.snapshot.error.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{QueryTaskRegistry, QueryTaskSnapshot, QueryTaskState};

    #[tokio::test]
    async fn task_registry_tracks_state_progression_and_events() {
        let mut registry = QueryTaskRegistry::default();
        let task_id = registry.create_task();
        let mut receiver = registry.subscribe(&task_id).expect("receiver");
        assert!(registry.mark_running(&task_id));
        let event = receiver.recv().await.expect("event");
        assert_eq!(event.state, QueryTaskState::Running);
    }

    #[test]
    fn restore_task_rehydrates_existing_snapshot() {
        let mut registry = QueryTaskRegistry::default();
        registry.restore_task(QueryTaskSnapshot {
            task_id: "task-recovered".into(),
            state: QueryTaskState::Completed,
            snapshot_id: Some("snapshot-1".into()),
            cache_hit: true,
            error: None,
        });

        let snapshot = registry.snapshot("task-recovered").expect("snapshot");
        assert_eq!(snapshot.state, QueryTaskState::Completed);
        assert_eq!(snapshot.snapshot_id.as_deref(), Some("snapshot-1"));
    }

    #[tokio::test]
    async fn upsert_snapshot_preserves_existing_subscription() {
        let mut registry = QueryTaskRegistry::default();
        let task_id = registry.create_task();
        let mut receiver = registry.subscribe(&task_id).expect("receiver");

        registry.upsert_snapshot(QueryTaskSnapshot {
            task_id: task_id.clone(),
            state: QueryTaskState::Completed,
            snapshot_id: Some("snapshot-2".into()),
            cache_hit: true,
            error: None,
        });

        let event = receiver.recv().await.expect("event");
        assert_eq!(event.state, QueryTaskState::Completed);
        assert_eq!(event.snapshot_id.as_deref(), Some("snapshot-2"));
    }
}
