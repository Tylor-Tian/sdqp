use sdqp_core::{FieldSelector, Pagination};
use sdqp_datasource_adapter::{ExecutionMode, QueryTaskRegistry, QueryTaskState, UnifiedQuery};

#[test]
fn uat_unified_query_and_task_registry_support_async_query_lifecycle() {
    let mut query = UnifiedQuery::new(vec![
        FieldSelector::new("employee_id").expect("field"),
        FieldSelector::new("employee_email").expect("field"),
    ]);
    query.pagination = Some(Pagination::bounded(100, None).expect("pagination"));
    query.execution_mode = ExecutionMode::Snapshot;

    let mut registry = QueryTaskRegistry::default();
    let task_id = registry.create_task();
    registry.update_state(&task_id, QueryTaskState::Running);

    assert_eq!(query.fields.len(), 2);
    assert_eq!(query.execution_mode, ExecutionMode::Snapshot);
    assert_eq!(registry.state(&task_id), Some(QueryTaskState::Running));
}
