use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use sdqp_core::{FieldSelector, FilterCondition, FilterConditionGroup, Pagination};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    Rest,
    Rpc,
    Hive,
    Rdbms,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSourceConfig {
    pub data_source_id: String,
    pub source_type: SourceType,
    pub connection_uri: String,
    #[serde(default)]
    pub adapter_config: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    Async,
    Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    Eq,
    Gt,
    Lt,
    In,
    Like,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedQuery {
    pub fields: Vec<FieldSelector>,
    pub conditions: Vec<FilterCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition_groups: Vec<FilterConditionGroup>,
    pub pagination: Option<Pagination>,
    pub timeout_secs: u64,
    pub execution_mode: ExecutionMode,
}

impl UnifiedQuery {
    pub fn new(fields: Vec<FieldSelector>) -> Self {
        Self {
            fields,
            conditions: Vec::new(),
            condition_groups: Vec::new(),
            pagination: None,
            timeout_secs: 30,
            execution_mode: ExecutionMode::Async,
        }
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCapabilities {
    pub supported_operators: Vec<Operator>,
    pub supported_logical_operators: Vec<LogicalOperator>,
    pub supports_field_projection: bool,
    pub supports_pagination: bool,
}

impl SourceCapabilities {
    pub fn rest_defaults() -> Self {
        Self {
            supported_operators: vec![Operator::Eq, Operator::In],
            supported_logical_operators: vec![LogicalOperator::And],
            supports_field_projection: true,
            supports_pagination: true,
        }
    }

    pub fn rpc_defaults() -> Self {
        Self {
            supported_operators: vec![Operator::Eq, Operator::In, Operator::Like],
            supported_logical_operators: vec![LogicalOperator::And],
            supports_field_projection: true,
            supports_pagination: true,
        }
    }

    pub fn sql_defaults() -> Self {
        Self {
            supported_operators: vec![
                Operator::Eq,
                Operator::Gt,
                Operator::Lt,
                Operator::In,
                Operator::Like,
            ],
            supported_logical_operators: vec![LogicalOperator::And],
            supports_field_projection: true,
            supports_pagination: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryExecutionPlan {
    pub query: UnifiedQuery,
    pub pushed_conditions: Vec<FilterCondition>,
    pub residual_conditions: Vec<FilterCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residual_condition_groups: Vec<FilterConditionGroup>,
}

pub fn build_execution_plan(
    capabilities: &SourceCapabilities,
    query: &UnifiedQuery,
) -> QueryExecutionPlan {
    let mut pushed_conditions = Vec::new();
    let mut residual_conditions = Vec::new();

    for condition in &query.conditions {
        let pushable = match condition.operator {
            sdqp_core::FilterOperator::Eq => {
                capabilities.supported_operators.contains(&Operator::Eq)
            }
            sdqp_core::FilterOperator::Gt => {
                capabilities.supported_operators.contains(&Operator::Gt)
            }
            sdqp_core::FilterOperator::Lt => {
                capabilities.supported_operators.contains(&Operator::Lt)
            }
            sdqp_core::FilterOperator::Like => {
                capabilities.supported_operators.contains(&Operator::Like)
            }
            sdqp_core::FilterOperator::In => {
                capabilities.supported_operators.contains(&Operator::In)
            }
            sdqp_core::FilterOperator::Neq => false,
        };

        if pushable {
            pushed_conditions.push(condition.clone());
        } else {
            residual_conditions.push(condition.clone());
        }
    }

    let mut planned_query = query.clone();
    planned_query.conditions = pushed_conditions.clone();
    planned_query.condition_groups = Vec::new();
    if !capabilities.supports_pagination {
        planned_query.pagination = None;
    }

    QueryExecutionPlan {
        query: planned_query,
        pushed_conditions,
        residual_conditions,
        residual_condition_groups: query.condition_groups.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldQueryResult {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryStatus {
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult {
    pub task_id: String,
    pub rows: Vec<Vec<FieldQueryResult>>,
    pub status: QueryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterHealthStatus {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterHealthCheck {
    pub status: AdapterHealthStatus,
    pub message: Option<String>,
}

impl AdapterHealthCheck {
    pub fn healthy() -> Self {
        Self {
            status: AdapterHealthStatus::Healthy,
            message: None,
        }
    }

    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: AdapterHealthStatus::Degraded,
            message: Some(message.into()),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: AdapterHealthStatus::Unavailable,
            message: Some(message.into()),
        }
    }
}

#[async_trait]
pub trait DataSourceAdapter: Send + Sync {
    async fn connect(&self, _config: &DataSourceConfig) -> Result<(), String> {
        Ok(())
    }

    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String>;
    fn capabilities(&self) -> SourceCapabilities;

    async fn health_check(&self) -> AdapterHealthCheck {
        AdapterHealthCheck::healthy()
    }

    async fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }

    fn plan_query(&self, query: &UnifiedQuery) -> QueryExecutionPlan {
        build_execution_plan(&self.capabilities(), query)
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutionMode, SourceCapabilities, UnifiedQuery, build_execution_plan};
    use sdqp_core::{FieldSelector, FilterCondition, FilterOperator};

    #[test]
    fn unified_query_uses_async_defaults() {
        let query = UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]);
        assert_eq!(query.execution_mode, ExecutionMode::Async);
        assert_eq!(query.timeout_secs, 30);
    }

    #[test]
    fn source_capabilities_expose_rest_defaults() {
        let capabilities = SourceCapabilities::rest_defaults();
        assert!(capabilities.supports_field_projection);
        assert!(capabilities.supports_pagination);
    }

    #[test]
    fn execution_plan_splits_pushdown_and_residual_conditions() {
        let mut query = UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]);
        query.conditions = vec![
            FilterCondition {
                field: "employee_id".into(),
                operator: FilterOperator::Eq,
                value: "E-100".into(),
            },
            FilterCondition {
                field: "department".into(),
                operator: FilterOperator::Neq,
                value: "ops".into(),
            },
        ];

        let plan = build_execution_plan(&SourceCapabilities::rest_defaults(), &query);

        assert_eq!(plan.pushed_conditions.len(), 1);
        assert_eq!(plan.residual_conditions.len(), 1);
        assert_eq!(plan.query.conditions.len(), 1);
    }
}
