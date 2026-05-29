pub mod adapters;
pub mod circuit;
pub mod scheduler;
pub mod task;
pub mod traits;

pub use adapters::{
    AdapterRegistry, MockAdapterRegistry, MockHiveAdapter, MockRestAdapter, MockRpcAdapter,
};
pub use circuit::CircuitBreaker;
pub use scheduler::{
    AdapterAvailability, AdapterHealthSnapshot, AdapterLifecycleScheduler,
    AdapterQueryRuntimeState, AdapterQueryTaskSnapshot, AdapterRetryPolicy, AdapterRuntimeState,
    AdapterSchedulerConfig, AdapterSchedulerError, AdapterSchedulerErrorKind,
    ScheduledQueryRequest, ScheduledQueryResult,
};
pub use task::{QueryTaskRegistry, QueryTaskState, StoredQueryTask};
pub use traits::{
    AdapterHealthCheck, AdapterHealthStatus, DataSourceAdapter, DataSourceConfig, ExecutionMode,
    FieldQueryResult, LogicalOperator, Operator, QueryExecutionPlan, QueryResult, QueryStatus,
    SourceCapabilities, SourceType, UnifiedQuery, build_execution_plan,
};
