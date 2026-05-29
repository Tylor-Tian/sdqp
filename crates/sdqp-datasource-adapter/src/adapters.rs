use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    process::Stdio,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use reqwest::Client;
use sdqp_core::{FieldSelector, FilterCondition, FilterConditionGroup, FilterOperator, Pagination};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use sqlx_postgres::PgPoolOptions;
use tokio::{io::AsyncReadExt, process::Command, time::sleep};

use crate::{
    AdapterHealthCheck, DataSourceAdapter, DataSourceConfig, FieldQueryResult, QueryResult,
    QueryStatus, SourceCapabilities, SourceType, UnifiedQuery,
};

#[derive(Debug, Clone)]
struct MockRow {
    fields: HashMap<String, String>,
}

impl MockRow {
    fn new(fields: &[(&str, &str)]) -> Self {
        Self {
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
        }
    }

    fn project(&self, query: &UnifiedQuery) -> Vec<FieldQueryResult> {
        project_row(&self.fields, query)
    }
}

#[derive(Debug, Clone)]
pub struct MockRestAdapter {
    rows: Vec<MockRow>,
}

#[derive(Debug, Clone)]
pub struct MockRpcAdapter {
    rows: Vec<MockRow>,
}

#[derive(Debug, Clone)]
pub struct MockHiveAdapter {
    rows: Vec<MockRow>,
    delay: Duration,
}

#[derive(Debug, Clone)]
struct HttpRestAdapter {
    client: Client,
    endpoint: String,
}

#[derive(Debug, Clone)]
struct HttpRpcAdapter {
    client: Client,
    endpoint: String,
}

#[derive(Debug, Clone)]
struct SqlAdapter {
    config: DataSourceConfig,
}

#[derive(Debug, Clone)]
struct HiveJdbcCliAdapter {
    config: DataSourceConfig,
}

#[derive(Debug, Deserialize)]
struct AdapterRowsResponse {
    rows: Vec<HashMap<String, String>>,
}

impl Default for MockRestAdapter {
    fn default() -> Self {
        Self {
            rows: vec![
                MockRow::new(&[
                    ("employee_id", "E-100"),
                    ("employee_email", "alice@example.com"),
                    ("department", "fraud"),
                ]),
                MockRow::new(&[
                    ("employee_id", "E-200"),
                    ("employee_email", "bob@example.com"),
                    ("department", "risk"),
                ]),
            ],
        }
    }
}

impl Default for MockRpcAdapter {
    fn default() -> Self {
        Self {
            rows: vec![MockRow::new(&[
                ("employee_id", "R-100"),
                ("employee_email", "rpc@example.com"),
                ("department", "rpc"),
            ])],
        }
    }
}

impl Default for MockHiveAdapter {
    fn default() -> Self {
        Self {
            rows: vec![MockRow::new(&[
                ("employee_id", "H-100"),
                ("employee_email", "hive@example.com"),
                ("department", "archive"),
            ])],
            delay: Duration::from_millis(150),
        }
    }
}

#[async_trait]
impl DataSourceAdapter for MockRestAdapter {
    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String> {
        Ok(QueryResult {
            task_id: "rest-adapter".into(),
            rows: self.rows.iter().map(|row| row.project(&query)).collect(),
            status: QueryStatus::Completed,
        })
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::rest_defaults()
    }
}

#[async_trait]
impl DataSourceAdapter for MockRpcAdapter {
    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String> {
        Ok(QueryResult {
            task_id: "rpc-adapter".into(),
            rows: self.rows.iter().map(|row| row.project(&query)).collect(),
            status: QueryStatus::Completed,
        })
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::rpc_defaults()
    }
}

#[async_trait]
impl DataSourceAdapter for MockHiveAdapter {
    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String> {
        sleep(self.delay).await;
        Ok(QueryResult {
            task_id: "hive-adapter".into(),
            rows: self.rows.iter().map(|row| row.project(&query)).collect(),
            status: QueryStatus::Completed,
        })
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::sql_defaults()
    }
}

#[async_trait]
impl DataSourceAdapter for HttpRestAdapter {
    async fn connect(&self, config: &DataSourceConfig) -> Result<(), String> {
        validate_http_endpoint(&config.connection_uri)
    }

    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String> {
        let response = self
            .client
            .get(&self.endpoint)
            .query(&[
                (
                    "fields",
                    query
                        .fields
                        .iter()
                        .map(|field| field.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "conditions",
                    serde_json::to_string(&query.conditions).unwrap_or_default(),
                ),
            ])
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let payload = response
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json::<AdapterRowsResponse>()
            .await
            .map_err(|error| error.to_string())?;

        Ok(QueryResult {
            task_id: "rest-http".into(),
            rows: payload
                .rows
                .iter()
                .map(|row| project_row(row, &query))
                .collect(),
            status: QueryStatus::Completed,
        })
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::rest_defaults()
    }

    async fn health_check(&self) -> AdapterHealthCheck {
        validate_http_endpoint(&self.endpoint)
            .map(|_| AdapterHealthCheck::healthy())
            .unwrap_or_else(AdapterHealthCheck::unavailable)
    }
}

#[async_trait]
impl DataSourceAdapter for HttpRpcAdapter {
    async fn connect(&self, config: &DataSourceConfig) -> Result<(), String> {
        validate_http_endpoint(&config.connection_uri)
    }

    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String> {
        let response = self
            .client
            .post(&self.endpoint)
            .json(&json!({
                "fields": query.fields.iter().map(|field| field.as_str()).collect::<Vec<_>>(),
                "conditions": query.conditions,
                "pagination": query.pagination,
                "timeout_secs": query.timeout_secs,
                "execution_mode": query.execution_mode,
            }))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let payload = response
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json::<AdapterRowsResponse>()
            .await
            .map_err(|error| error.to_string())?;

        Ok(QueryResult {
            task_id: "rpc-http".into(),
            rows: payload
                .rows
                .iter()
                .map(|row| project_row(row, &query))
                .collect(),
            status: QueryStatus::Completed,
        })
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::rpc_defaults()
    }

    async fn health_check(&self) -> AdapterHealthCheck {
        validate_http_endpoint(&self.endpoint)
            .map(|_| AdapterHealthCheck::healthy())
            .unwrap_or_else(AdapterHealthCheck::unavailable)
    }
}

#[async_trait]
impl DataSourceAdapter for SqlAdapter {
    async fn connect(&self, config: &DataSourceConfig) -> Result<(), String> {
        if config.connection_uri.trim().is_empty() {
            return Err("empty sql connection uri".into());
        }
        Ok(())
    }

    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String> {
        if let Some(delay_ms) = self
            .config
            .adapter_config
            .get("delay_ms")
            .and_then(|value| value.as_u64())
        {
            sleep(Duration::from_millis(delay_ms)).await;
        }

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.config.connection_uri)
            .await
            .map_err(|error| error.to_string())?;
        let fields = query
            .fields
            .iter()
            .map(|field| sanitize_identifier(field.as_str()))
            .collect::<Result<Vec<_>, _>>()?;
        let table_name = sanitize_identifier(
            self.config
                .adapter_config
                .get("table")
                .and_then(|value| value.as_str())
                .unwrap_or("stage6_employee_rows"),
        )?;

        let plan = self.plan_query(&query);
        let mut sql = format!("SELECT {} FROM {table_name}", fields.join(", "));
        let where_clause = sql_where_clause(&plan.pushed_conditions)?;
        if !where_clause.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_clause);
        }
        if let Some(pagination) = &plan.query.pagination {
            sql.push_str(&format!(" LIMIT {}", pagination.page_size));
            if let Some(cursor) = &pagination.cursor
                && let Ok(offset) = cursor.parse::<usize>()
            {
                sql.push_str(&format!(" OFFSET {offset}"));
            }
        }

        let rows = sqlx::query(&sql)
            .fetch_all(&pool)
            .await
            .map_err(|error| error.to_string())?;

        Ok(QueryResult {
            task_id: "sql-adapter".into(),
            rows: rows
                .iter()
                .map(|row| {
                    fields
                        .iter()
                        .map(|field| FieldQueryResult {
                            field: field.clone(),
                            value: row.try_get::<String, _>(field.as_str()).unwrap_or_default(),
                        })
                        .collect()
                })
                .collect(),
            status: QueryStatus::Completed,
        })
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::sql_defaults()
    }

    async fn health_check(&self) -> AdapterHealthCheck {
        if self.config.connection_uri.trim().is_empty() {
            return AdapterHealthCheck::unavailable("empty sql connection uri");
        }
        AdapterHealthCheck::healthy()
    }
}

#[async_trait]
impl DataSourceAdapter for HiveJdbcCliAdapter {
    async fn connect(&self, config: &DataSourceConfig) -> Result<(), String> {
        validate_hive_jdbc_config(config)?;
        let health_sql = hive_config_string(config, "connect_validation_sql")
            .unwrap_or_else(|| "SELECT 1".into());
        self.run_hive_cli(&health_sql).await.map(|_| ())
    }

    async fn execute_query(&self, query: UnifiedQuery) -> Result<QueryResult, String> {
        let sql = self.hive_select_sql(&query)?;
        let output = self.run_hive_cli(&sql).await?;
        let field_names = query
            .fields
            .iter()
            .map(|field| field.as_str().to_string())
            .collect::<Vec<_>>();
        Ok(QueryResult {
            task_id: "hive-jdbc-cli".into(),
            rows: parse_hive_csv_rows(&output.stdout, &field_names)?,
            status: QueryStatus::Completed,
        })
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::sql_defaults()
    }

    async fn health_check(&self) -> AdapterHealthCheck {
        if let Err(error) = validate_hive_jdbc_config(&self.config) {
            return AdapterHealthCheck::unavailable(error);
        }
        let health_sql =
            hive_config_string(&self.config, "health_sql").unwrap_or_else(|| "SELECT 1".into());
        match self.run_hive_cli(&health_sql).await {
            Ok(_) => AdapterHealthCheck::healthy(),
            Err(error) => AdapterHealthCheck::unavailable(error),
        }
    }
}

#[derive(Debug)]
struct HiveCliOutput {
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
struct HiveCliInvocation {
    command: String,
    args: Vec<String>,
}

impl HiveJdbcCliAdapter {
    fn hive_select_sql(&self, query: &UnifiedQuery) -> Result<String, String> {
        let fields = if query.fields.is_empty() {
            "*".into()
        } else {
            query
                .fields
                .iter()
                .map(|field| sanitize_identifier(field.as_str()))
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        };
        let table_name = sanitize_qualified_identifier(
            self.config
                .adapter_config
                .get("table")
                .and_then(|value| value.as_str())
                .unwrap_or("sdqp_fixture_employees"),
        )?;

        let plan = self.plan_query(query);
        let mut sql = format!("SELECT {fields} FROM {table_name}");
        let where_clause = sql_where_clause(&plan.pushed_conditions)?;
        if !where_clause.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_clause);
        }
        if let Some(pagination) = &plan.query.pagination {
            sql.push_str(&format!(" LIMIT {}", pagination.page_size));
        }
        Ok(sql)
    }

    async fn run_hive_cli(&self, sql: &str) -> Result<HiveCliOutput, String> {
        let invocation = hive_cli_invocation(&self.config, sql)?;
        let mut command = Command::new(&invocation.command);
        command
            .args(&invocation.args)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("failed to spawn Hive JDBC command: {error}"))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "failed to capture Hive JDBC stdout".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "failed to capture Hive JDBC stderr".to_string())?;
        let stdout_task = tokio::spawn(read_child_stream(stdout));
        let stderr_task = tokio::spawn(read_child_stream(stderr));
        let poll_interval = hive_poll_interval(&self.config);

        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("failed to poll Hive JDBC command: {error}"))?
            {
                let stdout = stdout_task
                    .await
                    .map_err(|error| format!("failed to join Hive stdout reader: {error}"))?;
                let stderr = stderr_task
                    .await
                    .map_err(|error| format!("failed to join Hive stderr reader: {error}"))?;
                let output = HiveCliOutput { stdout, stderr };
                if status.success() {
                    return Ok(output);
                }
                return Err(format!(
                    "Hive JDBC command failed with status {status}: {}",
                    truncate_for_error(&output.stderr)
                ));
            }
            sleep(poll_interval).await;
        }
    }
}

async fn read_child_stream<R>(mut stream: R) -> String
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes).await;
    String::from_utf8_lossy(&bytes).to_string()
}

#[derive(Debug, Default, Clone)]
pub struct MockAdapterRegistry {
    rest: Arc<MockRestAdapter>,
    rpc: Arc<MockRpcAdapter>,
    hive: Arc<MockHiveAdapter>,
}

impl MockAdapterRegistry {
    pub fn get(&self, source_type: &SourceType) -> Arc<dyn DataSourceAdapter> {
        match source_type {
            SourceType::Rest => self.rest.clone(),
            SourceType::Rpc => self.rpc.clone(),
            SourceType::Hive | SourceType::Rdbms => self.hive.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdapterRegistry {
    configs: Arc<RwLock<HashMap<String, DataSourceConfig>>>,
    client: Client,
    mocks: MockAdapterRegistry,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::development()
    }
}

impl AdapterRegistry {
    pub fn development() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
            client: Client::new(),
            mocks: MockAdapterRegistry::default(),
        }
    }

    pub fn from_configs(configs: impl IntoIterator<Item = DataSourceConfig>) -> Self {
        Self {
            configs: Arc::new(RwLock::new(
                configs
                    .into_iter()
                    .map(|config| (config.data_source_id.clone(), config))
                    .collect(),
            )),
            client: Client::new(),
            mocks: MockAdapterRegistry::default(),
        }
    }

    pub fn upsert_config(&self, config: DataSourceConfig) {
        self.configs
            .write()
            .expect("adapter configs")
            .insert(config.data_source_id.clone(), config);
    }

    pub fn capabilities(
        &self,
        data_source_id: &str,
        source_type: &SourceType,
    ) -> SourceCapabilities {
        if let Some(config) = self.config_snapshot(data_source_id) {
            return capabilities_for_source(&config.source_type);
        }

        self.mocks.get(source_type).capabilities()
    }

    pub fn config_snapshot(&self, data_source_id: &str) -> Option<DataSourceConfig> {
        self.configs
            .read()
            .expect("adapter configs")
            .get(data_source_id)
            .cloned()
    }

    pub async fn connect(
        &self,
        data_source_id: &str,
        source_type: &SourceType,
    ) -> Result<(), String> {
        let config = self
            .config_snapshot(data_source_id)
            .unwrap_or_else(|| default_mock_config(data_source_id, source_type));
        if uses_mock_transport(&config.connection_uri) {
            return self.mocks.get(&config.source_type).connect(&config).await;
        }

        connect_configured_adapter(&self.client, &config).await
    }

    pub async fn disconnect(
        &self,
        data_source_id: &str,
        source_type: &SourceType,
    ) -> Result<(), String> {
        let config = self
            .config_snapshot(data_source_id)
            .unwrap_or_else(|| default_mock_config(data_source_id, source_type));
        if uses_mock_transport(&config.connection_uri) {
            return self.mocks.get(&config.source_type).disconnect().await;
        }

        disconnect_configured_adapter(&self.client, &config).await
    }

    pub async fn health_check(
        &self,
        data_source_id: &str,
        source_type: &SourceType,
    ) -> AdapterHealthCheck {
        let config = self
            .config_snapshot(data_source_id)
            .unwrap_or_else(|| default_mock_config(data_source_id, source_type));
        if let Some(status) = forced_health_check(&config) {
            return status;
        }
        if uses_mock_transport(&config.connection_uri) {
            return self.mocks.get(&config.source_type).health_check().await;
        }

        health_check_configured_adapter(&self.client, &config).await
    }

    pub async fn execute_query(
        &self,
        data_source_id: &str,
        source_type: &SourceType,
        query: UnifiedQuery,
    ) -> Result<QueryResult, String> {
        if let Some(config) = self.config_snapshot(data_source_id) {
            if let Some(error) = forced_query_error(&config) {
                return Err(error);
            }
            if uses_mock_transport(&config.connection_uri) {
                return execute_planned_query(self.mocks.get(&config.source_type).as_ref(), &query)
                    .await;
            }
            return execute_configured_query(&self.client, &config, &query).await;
        }

        execute_planned_query(self.mocks.get(source_type).as_ref(), &query).await
    }
}

fn default_mock_config(data_source_id: &str, source_type: &SourceType) -> DataSourceConfig {
    DataSourceConfig {
        data_source_id: data_source_id.to_string(),
        source_type: source_type.clone(),
        connection_uri: format!("mock://{}", source_type_label(source_type)),
        adapter_config: serde_json::Value::Null,
    }
}

fn source_type_label(source_type: &SourceType) -> &'static str {
    match source_type {
        SourceType::Rest => "rest",
        SourceType::Rpc => "rpc",
        SourceType::Hive => "hive",
        SourceType::Rdbms => "rdbms",
    }
}

fn forced_query_error(config: &DataSourceConfig) -> Option<String> {
    config
        .adapter_config
        .get("force_error")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn forced_health_check(config: &DataSourceConfig) -> Option<AdapterHealthCheck> {
    let status = config
        .adapter_config
        .get("force_health_status")
        .and_then(|value| value.as_str())?;
    match status.to_ascii_lowercase().as_str() {
        "healthy" => Some(AdapterHealthCheck::healthy()),
        "degraded" => Some(AdapterHealthCheck::degraded(
            config
                .adapter_config
                .get("force_health_message")
                .and_then(|value| value.as_str())
                .unwrap_or("forced degraded health"),
        )),
        "unavailable" => Some(AdapterHealthCheck::unavailable(
            config
                .adapter_config
                .get("force_health_message")
                .and_then(|value| value.as_str())
                .unwrap_or("forced unavailable health"),
        )),
        _ => None,
    }
}

fn uses_mock_transport(connection_uri: &str) -> bool {
    connection_uri
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mock://"))
}

fn validate_http_endpoint(endpoint: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(endpoint).map_err(|error| error.to_string())?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(format!("unsupported http adapter scheme: {scheme}")),
    }
}

fn capabilities_for_source(source_type: &SourceType) -> SourceCapabilities {
    match source_type {
        SourceType::Rest => SourceCapabilities::rest_defaults(),
        SourceType::Rpc => SourceCapabilities::rpc_defaults(),
        SourceType::Hive | SourceType::Rdbms => SourceCapabilities::sql_defaults(),
    }
}

async fn execute_configured_query(
    client: &Client,
    config: &DataSourceConfig,
    query: &UnifiedQuery,
) -> Result<QueryResult, String> {
    match config.source_type {
        SourceType::Rest => {
            let adapter = HttpRestAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            execute_planned_query(&adapter, query).await
        }
        SourceType::Rpc => {
            let adapter = HttpRpcAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            execute_planned_query(&adapter, query).await
        }
        SourceType::Hive if !uses_sql_adapter_for_hive(config) => {
            let adapter = HiveJdbcCliAdapter {
                config: config.clone(),
            };
            execute_planned_query(&adapter, query).await
        }
        SourceType::Hive | SourceType::Rdbms => {
            let adapter = SqlAdapter {
                config: config.clone(),
            };
            execute_planned_query(&adapter, query).await
        }
    }
}

async fn connect_configured_adapter(
    client: &Client,
    config: &DataSourceConfig,
) -> Result<(), String> {
    match config.source_type {
        SourceType::Rest => {
            let adapter = HttpRestAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            adapter.connect(config).await
        }
        SourceType::Rpc => {
            let adapter = HttpRpcAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            adapter.connect(config).await
        }
        SourceType::Hive if !uses_sql_adapter_for_hive(config) => {
            let adapter = HiveJdbcCliAdapter {
                config: config.clone(),
            };
            adapter.connect(config).await
        }
        SourceType::Hive | SourceType::Rdbms => {
            let adapter = SqlAdapter {
                config: config.clone(),
            };
            adapter.connect(config).await
        }
    }
}

async fn disconnect_configured_adapter(
    client: &Client,
    config: &DataSourceConfig,
) -> Result<(), String> {
    match config.source_type {
        SourceType::Rest => {
            let adapter = HttpRestAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            adapter.disconnect().await
        }
        SourceType::Rpc => {
            let adapter = HttpRpcAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            adapter.disconnect().await
        }
        SourceType::Hive if !uses_sql_adapter_for_hive(config) => {
            let adapter = HiveJdbcCliAdapter {
                config: config.clone(),
            };
            adapter.disconnect().await
        }
        SourceType::Hive | SourceType::Rdbms => {
            let adapter = SqlAdapter {
                config: config.clone(),
            };
            adapter.disconnect().await
        }
    }
}

async fn health_check_configured_adapter(
    client: &Client,
    config: &DataSourceConfig,
) -> AdapterHealthCheck {
    match config.source_type {
        SourceType::Rest => {
            let adapter = HttpRestAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            adapter.health_check().await
        }
        SourceType::Rpc => {
            let adapter = HttpRpcAdapter {
                client: client.clone(),
                endpoint: config.connection_uri.clone(),
            };
            adapter.health_check().await
        }
        SourceType::Hive if !uses_sql_adapter_for_hive(config) => {
            let adapter = HiveJdbcCliAdapter {
                config: config.clone(),
            };
            adapter.health_check().await
        }
        SourceType::Hive | SourceType::Rdbms => {
            let adapter = SqlAdapter {
                config: config.clone(),
            };
            adapter.health_check().await
        }
    }
}

async fn execute_planned_query(
    adapter: &(impl DataSourceAdapter + ?Sized),
    query: &UnifiedQuery,
) -> Result<QueryResult, String> {
    let plan = adapter.plan_query(query);
    let execution_query = build_execution_query(query, &plan)?;
    let result = adapter.execute_query(execution_query).await?;
    Ok(finalize_query_result(query, result))
}

fn build_execution_query(
    original_query: &UnifiedQuery,
    plan: &crate::QueryExecutionPlan,
) -> Result<UnifiedQuery, String> {
    let mut execution_query = plan.query.clone();
    execution_query.fields = expand_fields_for_filter_closure(
        &original_query.fields,
        &original_query.conditions,
        &original_query.condition_groups,
    )?;
    execution_query.condition_groups = Vec::new();
    // Pagination is finalized after the filter closure so postfilter conditions
    // cannot be bypassed by a partially paginated upstream result.
    execution_query.pagination = None;
    Ok(execution_query)
}

fn expand_fields_for_filter_closure(
    fields: &[FieldSelector],
    conditions: &[FilterCondition],
    condition_groups: &[FilterConditionGroup],
) -> Result<Vec<FieldSelector>, String> {
    let mut expanded = fields.to_vec();
    let mut seen = fields
        .iter()
        .map(|field| field.as_str().to_string())
        .collect::<HashSet<_>>();

    for condition in all_query_conditions(conditions, condition_groups) {
        if seen.insert(condition.field.clone()) {
            expanded.push(
                FieldSelector::new(condition.field.clone()).map_err(|error| error.to_string())?,
            );
        }
    }

    Ok(expanded)
}

fn finalize_query_result(original_query: &UnifiedQuery, result: QueryResult) -> QueryResult {
    let filtered_rows = result
        .rows
        .into_iter()
        .filter(|row| row_matches_query_filters(row, original_query))
        .map(|row| project_result_row(&row, &original_query.fields))
        .collect::<Vec<_>>();

    QueryResult {
        rows: paginate_rows(filtered_rows, original_query.pagination.as_ref()),
        ..result
    }
}

fn paginate_rows(
    rows: Vec<Vec<FieldQueryResult>>,
    pagination: Option<&Pagination>,
) -> Vec<Vec<FieldQueryResult>> {
    let Some(pagination) = pagination else {
        return rows;
    };

    let offset = pagination
        .cursor
        .as_deref()
        .and_then(|cursor| cursor.parse::<usize>().ok())
        .unwrap_or(0);

    rows.into_iter()
        .skip(offset)
        .take(pagination.page_size)
        .collect()
}

fn project_result_row(
    row: &[FieldQueryResult],
    requested_fields: &[FieldSelector],
) -> Vec<FieldQueryResult> {
    let values = row
        .iter()
        .map(|field| (field.field.as_str(), field.value.clone()))
        .collect::<HashMap<_, _>>();

    requested_fields
        .iter()
        .map(|field| FieldQueryResult {
            field: field.as_str().to_string(),
            value: values
                .get(field.as_str())
                .cloned()
                .unwrap_or_else(|| "NULL".into()),
        })
        .collect()
}

fn row_matches_query_filters(row: &[FieldQueryResult], query: &UnifiedQuery) -> bool {
    if !row_matches_conditions(row, &query.conditions) {
        return false;
    }

    if query.condition_groups.is_empty() {
        return true;
    }

    query
        .condition_groups
        .iter()
        .any(|group| group.is_empty() || row_matches_conditions(row, &group.conditions))
}

fn row_matches_conditions(row: &[FieldQueryResult], conditions: &[FilterCondition]) -> bool {
    let values = row
        .iter()
        .map(|field| (field.field.as_str(), field.value.as_str()))
        .collect::<HashMap<_, _>>();

    conditions
        .iter()
        .all(|condition| condition_matches(&values, condition))
}

fn condition_matches(values: &HashMap<&str, &str>, condition: &FilterCondition) -> bool {
    let Some(candidate) = values.get(condition.field.as_str()).copied() else {
        return false;
    };

    match condition.operator {
        FilterOperator::Eq => candidate == condition.value.as_str(),
        FilterOperator::Neq => candidate != condition.value.as_str(),
        FilterOperator::Gt => compare_values(candidate, &condition.value)
            .is_some_and(|ordering| ordering == Ordering::Greater),
        FilterOperator::Lt => compare_values(candidate, &condition.value)
            .is_some_and(|ordering| ordering == Ordering::Less),
        FilterOperator::Like => like_matches(candidate, &condition.value),
        FilterOperator::In => condition
            .value
            .split(',')
            .map(str::trim)
            .any(|value| !value.is_empty() && candidate == value),
    }
}

fn compare_values(left: &str, right: &str) -> Option<Ordering> {
    if let (Ok(left), Ok(right)) = (left.parse::<i128>(), right.parse::<i128>()) {
        return Some(left.cmp(&right));
    }

    if let (Ok(left), Ok(right)) = (left.parse::<f64>(), right.parse::<f64>()) {
        return left.partial_cmp(&right);
    }

    Some(left.cmp(right))
}

fn all_query_conditions<'a>(
    conditions: &'a [FilterCondition],
    condition_groups: &'a [FilterConditionGroup],
) -> impl Iterator<Item = &'a FilterCondition> {
    conditions.iter().chain(
        condition_groups
            .iter()
            .flat_map(|group| group.conditions.iter()),
    )
}

fn like_matches(value: &str, pattern: &str) -> bool {
    let value = value.chars().collect::<Vec<_>>();
    let pattern = pattern.chars().collect::<Vec<_>>();
    let mut dp = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;

    for index in 1..=pattern.len() {
        if pattern[index - 1] == '%' {
            dp[index][0] = dp[index - 1][0];
        }
    }

    for pattern_index in 1..=pattern.len() {
        for value_index in 1..=value.len() {
            dp[pattern_index][value_index] = match pattern[pattern_index - 1] {
                '%' => dp[pattern_index - 1][value_index] || dp[pattern_index][value_index - 1],
                '_' => dp[pattern_index - 1][value_index - 1],
                ch => dp[pattern_index - 1][value_index - 1] && ch == value[value_index - 1],
            };
        }
    }

    dp[pattern.len()][value.len()]
}

fn project_row(row: &HashMap<String, String>, query: &UnifiedQuery) -> Vec<FieldQueryResult> {
    query
        .fields
        .iter()
        .map(|field| FieldQueryResult {
            field: field.as_str().to_string(),
            value: row
                .get(field.as_str())
                .cloned()
                .unwrap_or_else(|| "NULL".into()),
        })
        .collect()
}

fn sanitize_identifier(value: &str) -> Result<String, String> {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Ok(value.to_string());
    }

    Err(format!("invalid identifier: {value}"))
}

fn sanitize_qualified_identifier(value: &str) -> Result<String, String> {
    let parts = value
        .split('.')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(sanitize_identifier)
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() {
        return Err("empty identifier".into());
    }
    Ok(parts.join("."))
}

fn quote_sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn uses_sql_adapter_for_hive(config: &DataSourceConfig) -> bool {
    if config.source_type != SourceType::Hive {
        return false;
    }
    let provider = config
        .adapter_config
        .get("provider")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(provider.as_str(), "postgres" | "sql" | "sqlx")
        || config.connection_uri.starts_with("postgres://")
        || config.connection_uri.starts_with("postgresql://")
}

fn validate_hive_jdbc_config(config: &DataSourceConfig) -> Result<(), String> {
    if config.source_type != SourceType::Hive {
        return Err("Hive JDBC adapter requires source_type=hive".into());
    }
    let command = hive_config_string(config, "command").unwrap_or_else(|| "beeline".into());
    if command.trim().is_empty() {
        return Err("Hive JDBC command is empty".into());
    }
    let jdbc_url = hive_jdbc_url(config)?;
    if !jdbc_url.starts_with("jdbc:hive2://") {
        return Err(format!("unsupported Hive JDBC URL: {jdbc_url}"));
    }
    Ok(())
}

fn hive_jdbc_url(config: &DataSourceConfig) -> Result<String, String> {
    let configured =
        hive_config_string(config, "jdbc_url").unwrap_or_else(|| config.connection_uri.clone());
    let trimmed = configured.trim();
    if trimmed.is_empty() {
        return Err("empty Hive JDBC URL".into());
    }
    Ok(trimmed.to_string())
}

fn hive_config_string(config: &DataSourceConfig, key: &str) -> Option<String> {
    config
        .adapter_config
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn hive_cli_invocation(config: &DataSourceConfig, sql: &str) -> Result<HiveCliInvocation, String> {
    validate_hive_jdbc_config(config)?;
    let command = hive_config_string(config, "command").unwrap_or_else(|| "beeline".into());
    let args = config
        .adapter_config
        .get("command_args")
        .or_else(|| config.adapter_config.get("args"))
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| "Hive command args must be strings".to_string())
                        .map(|arg| replace_hive_placeholders(config, sql, arg))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_else(|| default_beeline_args(config, sql));
    Ok(HiveCliInvocation { command, args })
}

fn default_beeline_args(config: &DataSourceConfig, sql: &str) -> Vec<String> {
    let mut args = vec![
        "-u".into(),
        hive_jdbc_url(config).unwrap_or_else(|_| config.connection_uri.clone()),
        "-n".into(),
        hive_config_string(config, "username").unwrap_or_else(|| "hive".into()),
    ];
    if let Some(password) = hive_config_string(config, "password") {
        args.push("-p".into());
        args.push(password);
    }
    args.extend([
        "--outputformat=csv2".into(),
        "--showHeader=false".into(),
        "--silent=true".into(),
        "-e".into(),
        sql.to_string(),
    ]);
    args
}

fn replace_hive_placeholders(config: &DataSourceConfig, sql: &str, value: &str) -> String {
    value
        .replace("{sql}", sql)
        .replace("{connection_uri}", &config.connection_uri)
        .replace(
            "{jdbc_url}",
            &hive_jdbc_url(config).unwrap_or_else(|_| config.connection_uri.clone()),
        )
        .replace(
            "{username}",
            &hive_config_string(config, "username").unwrap_or_else(|| "hive".into()),
        )
        .replace(
            "{password}",
            &hive_config_string(config, "password").unwrap_or_default(),
        )
}

fn hive_poll_interval(config: &DataSourceConfig) -> Duration {
    Duration::from_millis(
        config
            .adapter_config
            .get("poll_interval_ms")
            .and_then(|value| value.as_u64())
            .unwrap_or(100)
            .clamp(10, 5_000),
    )
}

fn parse_hive_csv_rows(
    stdout: &str,
    field_names: &[String],
) -> Result<Vec<Vec<FieldQueryResult>>, String> {
    let mut rows = Vec::new();
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if should_skip_beeline_line(line) {
            continue;
        }
        let values = parse_csv2_line(line)?;
        if values.len() != field_names.len() {
            continue;
        }
        rows.push(
            field_names
                .iter()
                .cloned()
                .zip(values)
                .map(|(field, value)| FieldQueryResult { field, value })
                .collect(),
        );
    }
    Ok(rows)
}

fn should_skip_beeline_line(line: &str) -> bool {
    let normalized = line.to_ascii_lowercase();
    normalized.starts_with("connecting to")
        || normalized.starts_with("connected to")
        || normalized.starts_with("jdbc:hive2://")
        || normalized.contains(" rows selected")
        || normalized.starts_with("warning:")
        || normalized.starts_with("info")
}

fn parse_csv2_line(line: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                let _ = chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                values.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if in_quotes {
        return Err("unterminated Hive csv2 quote".into());
    }
    values.push(current.trim().to_string());
    Ok(values)
}

fn truncate_for_error(value: &str) -> String {
    const LIMIT: usize = 800;
    if value.len() <= LIMIT {
        value.trim().to_string()
    } else {
        format!("{}...", &value[..LIMIT])
    }
}

fn sql_where_clause(conditions: &[sdqp_core::FilterCondition]) -> Result<String, String> {
    let mut clauses = Vec::with_capacity(conditions.len());
    for condition in conditions {
        let field = sanitize_identifier(&condition.field)?;
        let clause = match condition.operator {
            sdqp_core::FilterOperator::Eq => {
                format!("{field} = {}", quote_sql_literal(&condition.value))
            }
            sdqp_core::FilterOperator::Gt => {
                format!("{field} > {}", quote_sql_literal(&condition.value))
            }
            sdqp_core::FilterOperator::Lt => {
                format!("{field} < {}", quote_sql_literal(&condition.value))
            }
            sdqp_core::FilterOperator::Like => {
                format!("{field} LIKE {}", quote_sql_literal(&condition.value))
            }
            sdqp_core::FilterOperator::In => {
                let values = condition
                    .value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(quote_sql_literal)
                    .collect::<Vec<_>>();
                format!("{field} IN ({})", values.join(", "))
            }
            sdqp_core::FilterOperator::Neq => {
                return Err("operator neq is not supported for sql pushdown".into());
            }
        };
        clauses.push(clause);
    }

    Ok(clauses.join(" AND "))
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterRegistry, MockAdapterRegistry, MockRestAdapter, hive_cli_invocation,
        parse_hive_csv_rows, sanitize_identifier, sanitize_qualified_identifier,
    };
    use crate::{DataSourceAdapter, DataSourceConfig, SourceType, UnifiedQuery};
    use sdqp_core::{
        FieldSelector, FilterCondition, FilterConditionGroup, FilterOperator, Pagination,
    };
    use serde_json::json;

    #[tokio::test]
    async fn mock_rest_adapter_projects_requested_fields() {
        let adapter = MockRestAdapter::default();
        let query = UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]);
        let result = adapter.execute_query(query).await.expect("query result");
        assert_eq!(result.rows[0][0].field, "employee_id");
    }

    #[test]
    fn registry_routes_by_source_type() {
        let registry = MockAdapterRegistry::default();
        let adapter = registry.get(&SourceType::Rest);
        assert!(adapter.capabilities().supports_field_projection);
    }

    #[tokio::test]
    async fn adapter_registry_falls_back_to_mock_when_no_config_exists() {
        let registry = AdapterRegistry::development();
        let result = registry
            .execute_query(
                "datasource-rest",
                &SourceType::Rest,
                UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]),
            )
            .await
            .expect("query");

        assert_eq!(result.rows[0][0].value, "E-100");
    }

    #[tokio::test]
    async fn adapter_registry_uses_mock_for_configured_mock_uri() {
        let registry = AdapterRegistry::from_configs([DataSourceConfig {
            data_source_id: "datasource-rest".into(),
            source_type: SourceType::Rest,
            connection_uri: "mock://rest".into(),
            adapter_config: json!({}),
        }]);
        let result = registry
            .execute_query(
                "datasource-rest",
                &SourceType::Rest,
                UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]),
            )
            .await
            .expect("query");

        assert_eq!(result.rows[0][0].value, "E-100");
    }

    #[test]
    fn registry_uses_source_capabilities_from_configured_source() {
        let registry = AdapterRegistry::from_configs([DataSourceConfig {
            data_source_id: "datasource-rpc".into(),
            source_type: SourceType::Rpc,
            connection_uri: "http://127.0.0.1:18080/rpc".into(),
            adapter_config: json!({}),
        }]);

        assert!(
            registry
                .capabilities("datasource-rpc", &SourceType::Rpc)
                .supported_operators
                .len()
                > 2
        );
    }

    #[test]
    fn sanitize_identifier_rejects_unsafe_name() {
        assert!(sanitize_identifier("employee_id").is_ok());
        assert!(sanitize_identifier("employee-id").is_err());
    }

    #[test]
    fn sanitize_qualified_identifier_accepts_database_table_names() {
        assert_eq!(
            sanitize_qualified_identifier("default.sdqp_fixture_employees").expect("identifier"),
            "default.sdqp_fixture_employees"
        );
        assert!(sanitize_qualified_identifier("default.employee-rows").is_err());
    }

    #[test]
    fn hive_cli_invocation_replaces_placeholders_for_docker_beeline() {
        let config = DataSourceConfig {
            data_source_id: "datasource-hive".into(),
            source_type: SourceType::Hive,
            connection_uri: "jdbc:hive2://127.0.0.1:10000/default".into(),
            adapter_config: json!({
                "provider": "beeline",
                "command": "docker",
                "username": "hive",
                "command_args": [
                    "compose",
                    "-f",
                    "docker-compose.hive.yml",
                    "exec",
                    "-T",
                    "hive-server",
                    "beeline",
                    "-u",
                    "{jdbc_url}",
                    "-n",
                    "{username}",
                    "-e",
                    "{sql}"
                ]
            }),
        };

        let invocation =
            hive_cli_invocation(&config, "SELECT employee_id FROM sdqp_fixture_employees")
                .expect("invocation");

        assert_eq!(invocation.command, "docker");
        assert!(
            invocation
                .args
                .contains(&"jdbc:hive2://127.0.0.1:10000/default".to_string())
        );
        assert!(
            invocation
                .args
                .contains(&"SELECT employee_id FROM sdqp_fixture_employees".to_string())
        );
    }

    #[test]
    fn hive_csv2_parser_maps_rows_to_requested_fields() {
        let rows = parse_hive_csv_rows(
            "H-100,warehouse\n\"H-200\",\"ops\"\n",
            &["employee_id".into(), "department".into()],
        )
        .expect("rows");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0].field, "employee_id");
        assert_eq!(rows[0][0].value, "H-100");
        assert_eq!(rows[1][1].value, "ops");
    }

    #[tokio::test]
    async fn registry_enforces_filter_closure_for_non_projected_fields() {
        let registry = AdapterRegistry::development();
        let mut query = UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]);
        query.conditions = vec![FilterCondition {
            field: "department".into(),
            operator: FilterOperator::Neq,
            value: "risk".into(),
        }];

        let result = registry
            .execute_query("datasource-rest", &SourceType::Rest, query)
            .await
            .expect("query");

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0].field, "employee_id");
        assert_eq!(result.rows[0][0].value, "E-100");
    }

    #[tokio::test]
    async fn registry_applies_pagination_after_filter_closure() {
        let registry = AdapterRegistry::development();
        let mut query = UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]);
        query.conditions = vec![FilterCondition {
            field: "department".into(),
            operator: FilterOperator::Like,
            value: "%".into(),
        }];
        query.pagination = Some(Pagination::bounded(1, Some("1".into())).expect("pagination"));

        let result = registry
            .execute_query("datasource-rest", &SourceType::Rest, query)
            .await
            .expect("query");

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0].value, "E-200");
    }

    #[tokio::test]
    async fn registry_supports_disjunctive_condition_groups() {
        let registry = AdapterRegistry::development();
        let mut query = UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]);
        query.condition_groups = vec![
            FilterConditionGroup::new(vec![FilterCondition {
                field: "department".into(),
                operator: FilterOperator::Eq,
                value: "fraud".into(),
            }]),
            FilterConditionGroup::new(vec![FilterCondition {
                field: "employee_id".into(),
                operator: FilterOperator::Eq,
                value: "E-200".into(),
            }]),
        ];

        let result = registry
            .execute_query("datasource-rest", &SourceType::Rest, query)
            .await
            .expect("query");

        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0][0].value, "E-100");
        assert_eq!(result.rows[1][0].value, "E-200");
    }
}
