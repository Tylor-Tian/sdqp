use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, Notify, Semaphore},
    time::{sleep, timeout},
};

use crate::{
    AdapterHealthStatus, AdapterRegistry, CircuitBreaker, DataSourceConfig, QueryResult,
    SourceType, UnifiedQuery,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterRuntimeState {
    Registered,
    Starting,
    Healthy,
    Degraded,
    Stopping,
    Stopped,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterAvailability {
    Available,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterQueryRuntimeState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterHealthSnapshot {
    pub data_source_id: String,
    pub source_type: SourceType,
    pub lifecycle_state: AdapterRuntimeState,
    pub availability: AdapterAvailability,
    pub registered_at: DateTime<Utc>,
    pub last_started_at: Option<DateTime<Utc>>,
    pub last_stopped_at: Option<DateTime<Utc>>,
    pub last_health_check_at: Option<DateTime<Utc>>,
    pub queued_tasks: usize,
    pub running_tasks: usize,
    pub completed_tasks: u64,
    pub failed_tasks: u64,
    pub cancelled_tasks: u64,
    pub total_submitted_tasks: u64,
    pub consecutive_failures: u32,
    pub circuit_open: bool,
    pub retry_after_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterQueryTaskSnapshot {
    pub task_id: String,
    pub data_source_id: String,
    pub source_type: SourceType,
    pub state: AdapterQueryRuntimeState,
    pub submitted_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub priority: i32,
    pub attempts: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AdapterRetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for AdapterRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdapterSchedulerConfig {
    pub circuit_failure_threshold: u32,
    pub circuit_retry_backoff: Duration,
    pub retry_policy: AdapterRetryPolicy,
    pub rest_concurrency: usize,
    pub rpc_concurrency: usize,
    pub hive_concurrency: usize,
    pub rdbms_concurrency: usize,
}

impl Default for AdapterSchedulerConfig {
    fn default() -> Self {
        Self {
            circuit_failure_threshold: 2,
            circuit_retry_backoff: Duration::from_secs(30),
            retry_policy: AdapterRetryPolicy::default(),
            rest_concurrency: 8,
            rpc_concurrency: 8,
            hive_concurrency: 2,
            rdbms_concurrency: 4,
        }
    }
}

impl AdapterSchedulerConfig {
    fn concurrency_for_source(&self, source_type: &SourceType) -> usize {
        let configured = match source_type {
            SourceType::Rest => self.rest_concurrency,
            SourceType::Rpc => self.rpc_concurrency,
            SourceType::Hive => self.hive_concurrency,
            SourceType::Rdbms => self.rdbms_concurrency,
        };
        configured.max(1)
    }
}

#[derive(Debug, Clone)]
pub struct ScheduledQueryRequest {
    pub task_id: String,
    pub data_source_id: String,
    pub source_type: SourceType,
    pub query: UnifiedQuery,
    pub priority: i32,
}

#[derive(Debug, Clone)]
pub struct ScheduledQueryResult {
    pub result: QueryResult,
    pub attempts: u32,
    pub runtime: AdapterHealthSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterSchedulerErrorKind {
    Unavailable,
    Cancelled,
    Timeout,
    ExecutionFailed,
}

#[derive(Debug, Clone)]
pub struct AdapterSchedulerError {
    pub kind: AdapterSchedulerErrorKind,
    pub message: String,
    pub attempts: u32,
    pub runtime: Option<AdapterHealthSnapshot>,
}

impl AdapterSchedulerError {
    fn new(
        kind: AdapterSchedulerErrorKind,
        message: impl Into<String>,
        attempts: u32,
        runtime: Option<AdapterHealthSnapshot>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            attempts,
            runtime,
        }
    }
}

impl fmt::Display for AdapterSchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for AdapterSchedulerError {}

#[derive(Clone)]
pub struct AdapterLifecycleScheduler {
    inner: Arc<SchedulerInner>,
}

struct SchedulerInner {
    adapters: Arc<AdapterRegistry>,
    runtimes: Mutex<HashMap<String, AdapterRuntimeRecord>>,
    tasks: Mutex<HashMap<String, AdapterQueryRecord>>,
    circuit: Mutex<CircuitBreaker>,
    config: AdapterSchedulerConfig,
}

struct AdapterRuntimeRecord {
    config: DataSourceConfig,
    state: AdapterRuntimeState,
    registered_at: DateTime<Utc>,
    last_started_at: Option<DateTime<Utc>>,
    last_stopped_at: Option<DateTime<Utc>>,
    last_health_check_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    queued_tasks: usize,
    running_tasks: usize,
    completed_tasks: u64,
    failed_tasks: u64,
    cancelled_tasks: u64,
    total_submitted_tasks: u64,
    semaphore: Arc<Semaphore>,
}

struct AdapterQueryRecord {
    task_id: String,
    data_source_id: String,
    source_type: SourceType,
    state: AdapterQueryRuntimeState,
    submitted_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    priority: i32,
    attempts: u32,
    error: Option<String>,
    cancellation: Arc<QueryCancellation>,
}

struct QueryCancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

impl QueryCancellation {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn cancelled(&self) {
        if self.cancelled.load(Ordering::SeqCst) {
            return;
        }
        self.notify.notified().await;
    }
}

impl AdapterLifecycleScheduler {
    pub fn new(adapters: Arc<AdapterRegistry>, config: AdapterSchedulerConfig) -> Self {
        Self {
            inner: Arc::new(SchedulerInner {
                adapters,
                runtimes: Mutex::new(HashMap::new()),
                tasks: Mutex::new(HashMap::new()),
                circuit: Mutex::new(CircuitBreaker::with_backoff(
                    config.circuit_failure_threshold,
                    config.circuit_retry_backoff,
                )),
                config,
            }),
        }
    }

    pub fn from_started_configs(
        adapters: Arc<AdapterRegistry>,
        configs: impl IntoIterator<Item = DataSourceConfig>,
        config: AdapterSchedulerConfig,
    ) -> Self {
        let now = Utc::now();
        let mut runtimes = HashMap::new();
        for adapter_config in configs {
            adapters.upsert_config(adapter_config.clone());
            let concurrency = adapter_config_concurrency(
                &adapter_config,
                config.concurrency_for_source(&adapter_config.source_type),
            );
            runtimes.insert(
                adapter_config.data_source_id.clone(),
                AdapterRuntimeRecord::started(adapter_config, now, concurrency),
            );
        }

        Self {
            inner: Arc::new(SchedulerInner {
                adapters,
                runtimes: Mutex::new(runtimes),
                tasks: Mutex::new(HashMap::new()),
                circuit: Mutex::new(CircuitBreaker::with_backoff(
                    config.circuit_failure_threshold,
                    config.circuit_retry_backoff,
                )),
                config,
            }),
        }
    }

    pub async fn register_adapter(
        &self,
        config: DataSourceConfig,
    ) -> Result<AdapterHealthSnapshot, String> {
        self.inner.adapters.upsert_config(config.clone());
        let data_source_id = config.data_source_id.clone();
        let concurrency = adapter_config_concurrency(
            &config,
            self.inner
                .config
                .concurrency_for_source(&config.source_type),
        );
        let now = Utc::now();
        {
            let mut runtimes = self.inner.runtimes.lock().await;
            runtimes.insert(
                data_source_id.clone(),
                AdapterRuntimeRecord::registered(config, now, concurrency),
            );
        }
        self.health_snapshot(&data_source_id)
            .await
            .ok_or_else(|| "adapter runtime registration failed".into())
    }

    pub async fn start_adapter(
        &self,
        data_source_id: &str,
    ) -> Result<AdapterHealthSnapshot, String> {
        let source_type = {
            let mut runtimes = self.inner.runtimes.lock().await;
            let Some(record) = runtimes.get_mut(data_source_id) else {
                return Err("adapter runtime not registered".into());
            };
            record.state = AdapterRuntimeState::Starting;
            record.last_error = None;
            record.config.source_type.clone()
        };

        let connect_result = self
            .inner
            .adapters
            .connect(data_source_id, &source_type)
            .await;
        let now = Utc::now();
        {
            let mut runtimes = self.inner.runtimes.lock().await;
            if let Some(record) = runtimes.get_mut(data_source_id) {
                match connect_result {
                    Ok(()) => {
                        record.state = AdapterRuntimeState::Healthy;
                        record.last_started_at = Some(now);
                        record.last_error = None;
                    }
                    Err(error) => {
                        record.state = AdapterRuntimeState::Unavailable;
                        record.last_error = Some(error);
                    }
                }
            }
        }

        self.health_snapshot(data_source_id)
            .await
            .ok_or_else(|| "adapter runtime not registered".into())
    }

    pub async fn stop_adapter(
        &self,
        data_source_id: &str,
    ) -> Result<AdapterHealthSnapshot, String> {
        let source_type = {
            let mut runtimes = self.inner.runtimes.lock().await;
            let Some(record) = runtimes.get_mut(data_source_id) else {
                return Err("adapter runtime not registered".into());
            };
            record.state = AdapterRuntimeState::Stopping;
            record.config.source_type.clone()
        };

        let cancellations = {
            let tasks = self.inner.tasks.lock().await;
            tasks
                .values()
                .filter(|task| {
                    task.data_source_id == data_source_id && !is_terminal_query_state(&task.state)
                })
                .map(|task| task.cancellation.clone())
                .collect::<Vec<_>>()
        };
        for cancellation in cancellations {
            cancellation.cancel();
        }

        let disconnect_result = self
            .inner
            .adapters
            .disconnect(data_source_id, &source_type)
            .await;
        let now = Utc::now();
        {
            let mut runtimes = self.inner.runtimes.lock().await;
            if let Some(record) = runtimes.get_mut(data_source_id) {
                match disconnect_result {
                    Ok(()) => {
                        record.state = AdapterRuntimeState::Stopped;
                        record.last_stopped_at = Some(now);
                        record.last_error = None;
                    }
                    Err(error) => {
                        record.state = AdapterRuntimeState::Degraded;
                        record.last_error = Some(error);
                    }
                }
            }
        }

        self.health_snapshot(data_source_id)
            .await
            .ok_or_else(|| "adapter runtime not registered".into())
    }

    pub async fn refresh_health(
        &self,
        data_source_id: &str,
    ) -> Result<AdapterHealthSnapshot, String> {
        let (source_type, state) = {
            let runtimes = self.inner.runtimes.lock().await;
            let Some(record) = runtimes.get(data_source_id) else {
                return Err("adapter runtime not registered".into());
            };
            (record.config.source_type.clone(), record.state.clone())
        };

        if matches!(
            state,
            AdapterRuntimeState::Registered
                | AdapterRuntimeState::Starting
                | AdapterRuntimeState::Stopped
                | AdapterRuntimeState::Stopping
        ) {
            return self
                .health_snapshot(data_source_id)
                .await
                .ok_or_else(|| "adapter runtime not registered".into());
        }

        let health = self
            .inner
            .adapters
            .health_check(data_source_id, &source_type)
            .await;
        let circuit = self
            .inner
            .circuit
            .lock()
            .await
            .source_snapshot(data_source_id);
        {
            let mut runtimes = self.inner.runtimes.lock().await;
            if let Some(record) = runtimes.get_mut(data_source_id) {
                record.last_health_check_at = Some(Utc::now());
                record.last_error = health.message.clone();
                record.state = match health.status {
                    AdapterHealthStatus::Healthy if circuit.open => {
                        AdapterRuntimeState::Unavailable
                    }
                    AdapterHealthStatus::Healthy if circuit.failure_count > 0 => {
                        AdapterRuntimeState::Degraded
                    }
                    AdapterHealthStatus::Healthy => AdapterRuntimeState::Healthy,
                    AdapterHealthStatus::Degraded => AdapterRuntimeState::Degraded,
                    AdapterHealthStatus::Unavailable => AdapterRuntimeState::Unavailable,
                };
            }
        }

        self.health_snapshot(data_source_id)
            .await
            .ok_or_else(|| "adapter runtime not registered".into())
    }

    pub async fn refresh_all_health(&self) -> Vec<AdapterHealthSnapshot> {
        let ids = {
            let runtimes = self.inner.runtimes.lock().await;
            runtimes.keys().cloned().collect::<Vec<_>>()
        };
        let mut snapshots = Vec::with_capacity(ids.len());
        for data_source_id in ids {
            if let Ok(snapshot) = self.refresh_health(&data_source_id).await {
                snapshots.push(snapshot);
            }
        }
        snapshots
    }

    pub async fn health_snapshot(&self, data_source_id: &str) -> Option<AdapterHealthSnapshot> {
        let circuit = self
            .inner
            .circuit
            .lock()
            .await
            .source_snapshot(data_source_id);
        let runtimes = self.inner.runtimes.lock().await;
        let record = runtimes.get(data_source_id)?;
        Some(record.snapshot(&circuit))
    }

    pub async fn health_snapshots(&self) -> Vec<AdapterHealthSnapshot> {
        let data_source_ids = {
            let runtimes = self.inner.runtimes.lock().await;
            runtimes.keys().cloned().collect::<Vec<_>>()
        };
        let mut snapshots = Vec::with_capacity(data_source_ids.len());
        for data_source_id in data_source_ids {
            if let Some(snapshot) = self.health_snapshot(&data_source_id).await {
                snapshots.push(snapshot);
            }
        }
        snapshots
    }

    pub async fn task_snapshot(&self, task_id: &str) -> Option<AdapterQueryTaskSnapshot> {
        self.inner
            .tasks
            .lock()
            .await
            .get(task_id)
            .map(AdapterQueryRecord::snapshot)
    }

    pub async fn cancel_task(&self, task_id: &str) -> bool {
        let cancellation = {
            let tasks = self.inner.tasks.lock().await;
            let Some(task) = tasks.get(task_id) else {
                return false;
            };
            if is_terminal_query_state(&task.state) {
                return false;
            }
            task.cancellation.clone()
        };
        cancellation.cancel();
        true
    }

    pub async fn execute_query(
        &self,
        request: ScheduledQueryRequest,
    ) -> Result<ScheduledQueryResult, AdapterSchedulerError> {
        let cancellation = Arc::new(QueryCancellation::new());
        self.create_task_record(&request, cancellation.clone())
            .await;
        let semaphore = self.reserve_runtime_slot(&request).await?;
        let permit = tokio::select! {
            permit = semaphore.acquire_owned() => permit.map_err(|_| {
                AdapterSchedulerError::new(
                    AdapterSchedulerErrorKind::Unavailable,
                    "adapter scheduler semaphore closed",
                    0,
                    None,
                )
            })?,
            _ = cancellation.cancelled() => {
                let runtime = self.mark_task_cancelled(&request.task_id).await;
                return Err(AdapterSchedulerError::new(
                    AdapterSchedulerErrorKind::Cancelled,
                    "query task cancelled",
                    0,
                    runtime,
                ));
            }
        };
        self.mark_task_running(&request.task_id).await;

        let execution = self
            .execute_with_retry(&request, cancellation.clone())
            .await;
        match execution {
            Ok((query_result, attempts)) => {
                let runtime = self
                    .mark_task_completed(&request.task_id, &request.data_source_id)
                    .await;
                drop(permit);
                Ok(ScheduledQueryResult {
                    result: query_result,
                    attempts,
                    runtime: runtime.expect("runtime exists for completed adapter task"),
                })
            }
            Err(error) if error.kind == AdapterSchedulerErrorKind::Cancelled => {
                let runtime = self.mark_task_cancelled(&request.task_id).await;
                drop(permit);
                Err(AdapterSchedulerError { runtime, ..error })
            }
            Err(error) => {
                let runtime = self
                    .mark_task_failed(&request.task_id, &request.data_source_id, &error.message)
                    .await;
                drop(permit);
                Err(AdapterSchedulerError { runtime, ..error })
            }
        }
    }

    async fn create_task_record(
        &self,
        request: &ScheduledQueryRequest,
        cancellation: Arc<QueryCancellation>,
    ) {
        let record = AdapterQueryRecord {
            task_id: request.task_id.clone(),
            data_source_id: request.data_source_id.clone(),
            source_type: request.source_type.clone(),
            state: AdapterQueryRuntimeState::Pending,
            submitted_at: Utc::now(),
            started_at: None,
            completed_at: None,
            priority: request.priority,
            attempts: 0,
            error: None,
            cancellation,
        };
        self.inner
            .tasks
            .lock()
            .await
            .insert(request.task_id.clone(), record);
    }

    async fn reserve_runtime_slot(
        &self,
        request: &ScheduledQueryRequest,
    ) -> Result<Arc<Semaphore>, AdapterSchedulerError> {
        let circuit = self
            .inner
            .circuit
            .lock()
            .await
            .source_snapshot(&request.data_source_id);
        let mut runtimes = self.inner.runtimes.lock().await;
        if !runtimes.contains_key(&request.data_source_id) {
            drop(runtimes);
            self.mark_task_failed_without_runtime(
                &request.task_id,
                "adapter runtime not registered",
            )
            .await;
            return Err(AdapterSchedulerError::new(
                AdapterSchedulerErrorKind::Unavailable,
                "adapter runtime not registered",
                0,
                None,
            ));
        }
        let record = runtimes
            .get_mut(&request.data_source_id)
            .expect("adapter runtime checked above");
        if !matches!(
            record.state,
            AdapterRuntimeState::Healthy | AdapterRuntimeState::Degraded
        ) {
            drop(runtimes);
            let snapshot = self
                .mark_task_rejected(
                    &request.task_id,
                    &request.data_source_id,
                    "adapter runtime unavailable",
                )
                .await;
            return Err(AdapterSchedulerError::new(
                AdapterSchedulerErrorKind::Unavailable,
                "adapter runtime unavailable",
                0,
                snapshot,
            ));
        }
        if circuit.open {
            record.state = AdapterRuntimeState::Unavailable;
            record.last_error = Some("circuit breaker open".into());
            drop(runtimes);
            let snapshot = self
                .mark_task_rejected(
                    &request.task_id,
                    &request.data_source_id,
                    "circuit breaker open",
                )
                .await;
            return Err(AdapterSchedulerError::new(
                AdapterSchedulerErrorKind::Unavailable,
                "circuit breaker open",
                0,
                snapshot,
            ));
        }

        if circuit.failure_count > 0 {
            record.state = AdapterRuntimeState::Degraded;
        }
        record.queued_tasks += 1;
        record.total_submitted_tasks += 1;
        Ok(record.semaphore.clone())
    }

    async fn execute_with_retry(
        &self,
        request: &ScheduledQueryRequest,
        cancellation: Arc<QueryCancellation>,
    ) -> Result<(QueryResult, u32), AdapterSchedulerError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            self.record_task_attempt(&request.task_id, attempts).await;
            let attempt = timeout(
                request.query.timeout(),
                self.inner.adapters.execute_query(
                    &request.data_source_id,
                    &request.source_type,
                    request.query.clone(),
                ),
            );
            let outcome = tokio::select! {
                result = attempt => result,
                _ = cancellation.cancelled() => {
                    return Err(AdapterSchedulerError::new(
                        AdapterSchedulerErrorKind::Cancelled,
                        "query task cancelled",
                        attempts,
                        self.health_snapshot(&request.data_source_id).await,
                    ));
                }
            };

            match outcome {
                Ok(Ok(result)) => {
                    self.record_adapter_success(&request.data_source_id).await;
                    return Ok((result, attempts));
                }
                Ok(Err(error)) => {
                    let runtime = self
                        .record_adapter_failure(&request.data_source_id, &error)
                        .await;
                    if attempts >= self.inner.config.retry_policy.max_attempts
                        || !is_retryable_adapter_error(&error)
                        || runtime
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.circuit_open)
                    {
                        return Err(AdapterSchedulerError::new(
                            AdapterSchedulerErrorKind::ExecutionFailed,
                            error,
                            attempts,
                            runtime,
                        ));
                    }
                    self.sleep_backoff(attempts, cancellation.clone()).await?;
                }
                Err(_) => {
                    let message = "query timed out".to_string();
                    let runtime = self
                        .record_adapter_failure(&request.data_source_id, &message)
                        .await;
                    if attempts >= self.inner.config.retry_policy.max_attempts
                        || runtime
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.circuit_open)
                    {
                        return Err(AdapterSchedulerError::new(
                            AdapterSchedulerErrorKind::Timeout,
                            message,
                            attempts,
                            runtime,
                        ));
                    }
                    self.sleep_backoff(attempts, cancellation.clone()).await?;
                }
            }
        }
    }

    async fn sleep_backoff(
        &self,
        attempts: u32,
        cancellation: Arc<QueryCancellation>,
    ) -> Result<(), AdapterSchedulerError> {
        let backoff = backoff_duration(&self.inner.config.retry_policy, attempts);
        tokio::select! {
            _ = sleep(backoff) => Ok(()),
            _ = cancellation.cancelled() => Err(AdapterSchedulerError::new(
                AdapterSchedulerErrorKind::Cancelled,
                "query task cancelled",
                attempts,
                None,
            )),
        }
    }

    async fn record_task_attempt(&self, task_id: &str, attempts: u32) {
        if let Some(task) = self.inner.tasks.lock().await.get_mut(task_id) {
            task.attempts = attempts;
        }
    }

    async fn mark_task_running(&self, task_id: &str) {
        let data_source_id = {
            let mut tasks = self.inner.tasks.lock().await;
            let Some(task) = tasks.get_mut(task_id) else {
                return;
            };
            task.state = AdapterQueryRuntimeState::Running;
            task.started_at = Some(Utc::now());
            task.data_source_id.clone()
        };
        let mut runtimes = self.inner.runtimes.lock().await;
        if let Some(runtime) = runtimes.get_mut(&data_source_id) {
            runtime.queued_tasks = runtime.queued_tasks.saturating_sub(1);
            runtime.running_tasks += 1;
        }
    }

    async fn mark_task_completed(
        &self,
        task_id: &str,
        data_source_id: &str,
    ) -> Option<AdapterHealthSnapshot> {
        {
            let mut tasks = self.inner.tasks.lock().await;
            if let Some(task) = tasks.get_mut(task_id) {
                task.state = AdapterQueryRuntimeState::Completed;
                task.completed_at = Some(Utc::now());
                task.error = None;
            }
        }
        let circuit = self
            .inner
            .circuit
            .lock()
            .await
            .source_snapshot(data_source_id);
        let mut runtimes = self.inner.runtimes.lock().await;
        let runtime = runtimes.get_mut(data_source_id)?;
        runtime.running_tasks = runtime.running_tasks.saturating_sub(1);
        runtime.completed_tasks += 1;
        runtime.last_error = None;
        runtime.state = if circuit.failure_count > 0 {
            AdapterRuntimeState::Degraded
        } else {
            AdapterRuntimeState::Healthy
        };
        Some(runtime.snapshot(&circuit))
    }

    async fn mark_task_failed(
        &self,
        task_id: &str,
        data_source_id: &str,
        error: &str,
    ) -> Option<AdapterHealthSnapshot> {
        {
            let mut tasks = self.inner.tasks.lock().await;
            if let Some(task) = tasks.get_mut(task_id) {
                task.state = AdapterQueryRuntimeState::Failed;
                task.completed_at = Some(Utc::now());
                task.error = Some(error.to_string());
            }
        }
        let circuit = self
            .inner
            .circuit
            .lock()
            .await
            .source_snapshot(data_source_id);
        let mut runtimes = self.inner.runtimes.lock().await;
        let runtime = runtimes.get_mut(data_source_id)?;
        runtime.running_tasks = runtime.running_tasks.saturating_sub(1);
        runtime.queued_tasks = runtime.queued_tasks.saturating_sub(1);
        runtime.failed_tasks += 1;
        runtime.last_error = Some(error.to_string());
        runtime.state = if circuit.open {
            AdapterRuntimeState::Unavailable
        } else {
            AdapterRuntimeState::Degraded
        };
        Some(runtime.snapshot(&circuit))
    }

    async fn mark_task_failed_without_runtime(&self, task_id: &str, error: &str) {
        let mut tasks = self.inner.tasks.lock().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.state = AdapterQueryRuntimeState::Failed;
            task.completed_at = Some(Utc::now());
            task.error = Some(error.to_string());
        }
    }

    async fn mark_task_rejected(
        &self,
        task_id: &str,
        data_source_id: &str,
        error: &str,
    ) -> Option<AdapterHealthSnapshot> {
        self.mark_task_failed_without_runtime(task_id, error).await;
        let circuit = self
            .inner
            .circuit
            .lock()
            .await
            .source_snapshot(data_source_id);
        let mut runtimes = self.inner.runtimes.lock().await;
        let runtime = runtimes.get_mut(data_source_id)?;
        runtime.failed_tasks += 1;
        runtime.last_error = Some(error.to_string());
        if circuit.open {
            runtime.state = AdapterRuntimeState::Unavailable;
        }
        Some(runtime.snapshot(&circuit))
    }

    async fn mark_task_cancelled(&self, task_id: &str) -> Option<AdapterHealthSnapshot> {
        let (data_source_id, previous_state) = {
            let mut tasks = self.inner.tasks.lock().await;
            let task = tasks.get_mut(task_id)?;
            let previous_state = task.state.clone();
            task.state = AdapterQueryRuntimeState::Cancelled;
            task.completed_at = Some(Utc::now());
            task.error = None;
            (task.data_source_id.clone(), previous_state)
        };
        let circuit = self
            .inner
            .circuit
            .lock()
            .await
            .source_snapshot(&data_source_id);
        let mut runtimes = self.inner.runtimes.lock().await;
        let runtime = runtimes.get_mut(&data_source_id)?;
        match previous_state {
            AdapterQueryRuntimeState::Pending => {
                runtime.queued_tasks = runtime.queued_tasks.saturating_sub(1)
            }
            AdapterQueryRuntimeState::Running => {
                runtime.running_tasks = runtime.running_tasks.saturating_sub(1)
            }
            AdapterQueryRuntimeState::Completed
            | AdapterQueryRuntimeState::Failed
            | AdapterQueryRuntimeState::Cancelled => {}
        }
        runtime.cancelled_tasks += 1;
        Some(runtime.snapshot(&circuit))
    }

    async fn record_adapter_success(&self, data_source_id: &str) {
        self.inner
            .circuit
            .lock()
            .await
            .record_success(data_source_id);
    }

    async fn record_adapter_failure(
        &self,
        data_source_id: &str,
        error: &str,
    ) -> Option<AdapterHealthSnapshot> {
        let circuit = {
            let mut circuit = self.inner.circuit.lock().await;
            circuit.record_failure(data_source_id);
            circuit.source_snapshot(data_source_id)
        };
        let mut runtimes = self.inner.runtimes.lock().await;
        let runtime = runtimes.get_mut(data_source_id)?;
        runtime.last_error = Some(error.to_string());
        runtime.state = if circuit.open {
            AdapterRuntimeState::Unavailable
        } else {
            AdapterRuntimeState::Degraded
        };
        Some(runtime.snapshot(&circuit))
    }
}

impl AdapterRuntimeRecord {
    fn registered(
        config: DataSourceConfig,
        registered_at: DateTime<Utc>,
        concurrency: usize,
    ) -> Self {
        Self {
            config,
            state: AdapterRuntimeState::Registered,
            registered_at,
            last_started_at: None,
            last_stopped_at: None,
            last_health_check_at: None,
            last_error: None,
            queued_tasks: 0,
            running_tasks: 0,
            completed_tasks: 0,
            failed_tasks: 0,
            cancelled_tasks: 0,
            total_submitted_tasks: 0,
            semaphore: Arc::new(Semaphore::new(concurrency)),
        }
    }

    fn started(config: DataSourceConfig, started_at: DateTime<Utc>, concurrency: usize) -> Self {
        let mut record = Self::registered(config, started_at, concurrency);
        record.state = AdapterRuntimeState::Healthy;
        record.last_started_at = Some(started_at);
        record
    }

    fn snapshot(&self, circuit: &crate::circuit::CircuitBreakerSnapshot) -> AdapterHealthSnapshot {
        let availability = if circuit.open {
            AdapterAvailability::Unavailable
        } else {
            match self.state {
                AdapterRuntimeState::Healthy => AdapterAvailability::Available,
                AdapterRuntimeState::Degraded => AdapterAvailability::Degraded,
                AdapterRuntimeState::Registered
                | AdapterRuntimeState::Starting
                | AdapterRuntimeState::Stopping
                | AdapterRuntimeState::Stopped
                | AdapterRuntimeState::Unavailable => AdapterAvailability::Unavailable,
            }
        };
        AdapterHealthSnapshot {
            data_source_id: self.config.data_source_id.clone(),
            source_type: self.config.source_type.clone(),
            lifecycle_state: if circuit.open {
                AdapterRuntimeState::Unavailable
            } else {
                self.state.clone()
            },
            availability,
            registered_at: self.registered_at,
            last_started_at: self.last_started_at,
            last_stopped_at: self.last_stopped_at,
            last_health_check_at: self.last_health_check_at,
            queued_tasks: self.queued_tasks,
            running_tasks: self.running_tasks,
            completed_tasks: self.completed_tasks,
            failed_tasks: self.failed_tasks,
            cancelled_tasks: self.cancelled_tasks,
            total_submitted_tasks: self.total_submitted_tasks,
            consecutive_failures: circuit.failure_count,
            circuit_open: circuit.open,
            retry_after_ms: circuit.retry_after.map(duration_millis_u64),
            last_error: self.last_error.clone(),
        }
    }
}

impl AdapterQueryRecord {
    fn snapshot(&self) -> AdapterQueryTaskSnapshot {
        AdapterQueryTaskSnapshot {
            task_id: self.task_id.clone(),
            data_source_id: self.data_source_id.clone(),
            source_type: self.source_type.clone(),
            state: self.state.clone(),
            submitted_at: self.submitted_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
            priority: self.priority,
            attempts: self.attempts,
            error: self.error.clone(),
        }
    }
}

fn adapter_config_concurrency(config: &DataSourceConfig, default_concurrency: usize) -> usize {
    config
        .adapter_config
        .get("max_concurrent_tasks")
        .and_then(|value| value.as_u64())
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_concurrency)
}

fn backoff_duration(policy: &AdapterRetryPolicy, attempts: u32) -> Duration {
    let multiplier = 2_u32.saturating_pow(attempts.saturating_sub(1));
    policy
        .initial_backoff
        .saturating_mul(multiplier)
        .min(policy.max_backoff)
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn is_retryable_adapter_error(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    ![
        "unauthorized",
        "forbidden",
        "permission",
        "invalid identifier",
        "unsupported",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn is_terminal_query_state(state: &AdapterQueryRuntimeState) -> bool {
    matches!(
        state,
        AdapterQueryRuntimeState::Completed
            | AdapterQueryRuntimeState::Failed
            | AdapterQueryRuntimeState::Cancelled
    )
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use sdqp_core::FieldSelector;
    use serde_json::json;
    use tokio::time::sleep;

    use super::{
        AdapterAvailability, AdapterLifecycleScheduler, AdapterQueryRuntimeState,
        AdapterRetryPolicy, AdapterRuntimeState, AdapterSchedulerConfig, AdapterSchedulerErrorKind,
        ScheduledQueryRequest,
    };
    use crate::{AdapterRegistry, DataSourceConfig, SourceType, UnifiedQuery};

    fn test_config() -> AdapterSchedulerConfig {
        AdapterSchedulerConfig {
            circuit_failure_threshold: 1,
            circuit_retry_backoff: Duration::from_secs(60),
            retry_policy: AdapterRetryPolicy {
                max_attempts: 1,
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(1),
            },
            rest_concurrency: 1,
            rpc_concurrency: 1,
            hive_concurrency: 1,
            rdbms_concurrency: 1,
        }
    }

    fn query() -> UnifiedQuery {
        UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")])
    }

    #[tokio::test]
    async fn scheduler_tracks_registration_start_health_and_completion() {
        let adapters = Arc::new(AdapterRegistry::development());
        let scheduler = AdapterLifecycleScheduler::new(adapters, test_config());
        let registered = scheduler
            .register_adapter(DataSourceConfig {
                data_source_id: "datasource-rest".into(),
                source_type: SourceType::Rest,
                connection_uri: "mock://rest".into(),
                adapter_config: json!({"max_concurrent_tasks": 1}),
            })
            .await
            .expect("registered");
        assert_eq!(registered.lifecycle_state, AdapterRuntimeState::Registered);

        let started = scheduler
            .start_adapter("datasource-rest")
            .await
            .expect("started");
        assert_eq!(started.availability, AdapterAvailability::Available);

        let result = scheduler
            .execute_query(ScheduledQueryRequest {
                task_id: "task-1".into(),
                data_source_id: "datasource-rest".into(),
                source_type: SourceType::Rest,
                query: query(),
                priority: 50,
            })
            .await
            .expect("query");

        assert_eq!(result.result.rows.len(), 2);
        assert_eq!(result.runtime.completed_tasks, 1);
        let task = scheduler.task_snapshot("task-1").await.expect("task");
        assert_eq!(task.state, AdapterQueryRuntimeState::Completed);
    }

    #[tokio::test]
    async fn scheduler_degrades_and_opens_circuit_after_adapter_failure() {
        let adapters = Arc::new(AdapterRegistry::development());
        let scheduler = AdapterLifecycleScheduler::new(adapters, test_config());
        scheduler
            .register_adapter(DataSourceConfig {
                data_source_id: "datasource-failing".into(),
                source_type: SourceType::Rest,
                connection_uri: "mock://rest".into(),
                adapter_config: json!({"force_error": "temporary upstream outage"}),
            })
            .await
            .expect("registered");
        scheduler
            .start_adapter("datasource-failing")
            .await
            .expect("started");

        let error = scheduler
            .execute_query(ScheduledQueryRequest {
                task_id: "task-failing".into(),
                data_source_id: "datasource-failing".into(),
                source_type: SourceType::Rest,
                query: query(),
                priority: 50,
            })
            .await
            .expect_err("failure");

        assert_eq!(error.kind, AdapterSchedulerErrorKind::ExecutionFailed);
        let health = scheduler
            .health_snapshot("datasource-failing")
            .await
            .expect("health");
        assert_eq!(health.lifecycle_state, AdapterRuntimeState::Unavailable);
        assert!(health.circuit_open);
        assert_eq!(health.failed_tasks, 1);
    }

    #[tokio::test]
    async fn scheduler_keeps_adapter_degraded_before_circuit_threshold() {
        let adapters = Arc::new(AdapterRegistry::development());
        let mut config = test_config();
        config.circuit_failure_threshold = 2;
        let scheduler = AdapterLifecycleScheduler::new(adapters, config);
        scheduler
            .register_adapter(DataSourceConfig {
                data_source_id: "datasource-degraded".into(),
                source_type: SourceType::Rest,
                connection_uri: "mock://rest".into(),
                adapter_config: json!({"force_error": "temporary upstream outage"}),
            })
            .await
            .expect("registered");
        scheduler
            .start_adapter("datasource-degraded")
            .await
            .expect("started");

        scheduler
            .execute_query(ScheduledQueryRequest {
                task_id: "task-degraded".into(),
                data_source_id: "datasource-degraded".into(),
                source_type: SourceType::Rest,
                query: query(),
                priority: 50,
            })
            .await
            .expect_err("failure");

        let health = scheduler
            .health_snapshot("datasource-degraded")
            .await
            .expect("health");
        assert_eq!(health.lifecycle_state, AdapterRuntimeState::Degraded);
        assert_eq!(health.availability, AdapterAvailability::Degraded);
        assert!(!health.circuit_open);
        assert_eq!(health.failed_tasks, 1);
    }

    #[tokio::test]
    async fn scheduler_cancels_running_async_source_task() {
        let adapters = Arc::new(AdapterRegistry::development());
        let scheduler = AdapterLifecycleScheduler::new(adapters, test_config());
        scheduler
            .register_adapter(DataSourceConfig {
                data_source_id: "datasource-hive".into(),
                source_type: SourceType::Hive,
                connection_uri: "mock://hive".into(),
                adapter_config: json!({}),
            })
            .await
            .expect("registered");
        scheduler
            .start_adapter("datasource-hive")
            .await
            .expect("started");

        let scheduler_for_task = scheduler.clone();
        let handle = tokio::spawn(async move {
            scheduler_for_task
                .execute_query(ScheduledQueryRequest {
                    task_id: "task-cancel".into(),
                    data_source_id: "datasource-hive".into(),
                    source_type: SourceType::Hive,
                    query: query(),
                    priority: 100,
                })
                .await
        });
        sleep(Duration::from_millis(10)).await;
        assert!(scheduler.cancel_task("task-cancel").await);
        let error = handle.await.expect("join").expect_err("cancelled");

        assert_eq!(error.kind, AdapterSchedulerErrorKind::Cancelled);
        let task = scheduler.task_snapshot("task-cancel").await.expect("task");
        assert_eq!(task.state, AdapterQueryRuntimeState::Cancelled);
        let health = scheduler
            .health_snapshot("datasource-hive")
            .await
            .expect("health");
        assert_eq!(health.cancelled_tasks, 1);
        assert_eq!(health.running_tasks, 0);
    }
}
