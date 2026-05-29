use axum::{
    Json, Router,
    routing::{get, post},
};
use sdqp_core::{FieldSelector, FilterCondition, FilterOperator, Pagination};
use sdqp_datasource_adapter::{AdapterRegistry, DataSourceConfig, SourceType, UnifiedQuery};
use serde_json::json;
use sqlx::Executor;
use sqlx_postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::oneshot};

fn stage6_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE6_TESTS").ok().as_deref() == Some("1")
}

fn admin_dsn() -> String {
    std::env::var("SDQP_STAGE3_ADMIN_DSN")
        .unwrap_or_else(|_| "postgres://sdqp:sdqp@127.0.0.1:15432/postgres".into())
}

async fn create_database(database_name: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_dsn())
        .await
        .expect("admin postgres");
    admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{database_name}""#).as_str())
        .await
        .expect("drop database if exists");
    admin
        .execute(format!(r#"CREATE DATABASE "{database_name}""#).as_str())
        .await
        .expect("create database");
}

async fn drop_database(database_name: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_dsn())
        .await
        .expect("admin postgres");
    admin
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = '{database_name}' AND pid <> pg_backend_pid()
                "#,
            )
            .as_str(),
        )
        .await
        .expect("terminate sessions");
    admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{database_name}""#).as_str())
        .await
        .expect("drop database");
}

async fn spawn_json_server(router: Router) -> (String, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server");
    });
    (format!("http://{address}"), shutdown_tx)
}

#[tokio::test]
async fn uat_stage6_adapters_execute_against_http_and_sql_backends() {
    if !stage6_enabled() {
        return;
    }

    let rest_router = Router::new().route(
        "/rows",
        get(|| async move {
            Json(json!({
                "rows": [
                    {"employee_id": "REST-100", "department": "fraud"},
                    {"employee_id": "REST-200", "department": "ops"},
                    {"employee_id": "REST-300", "department": "fraud"}
                ]
            }))
        }),
    );
    let rpc_router = Router::new().route(
        "/rpc",
        post(|| async move {
            Json(json!({
                "rows": [
                    {"employee_id": "RPC-100", "department": "rpc"},
                    {"employee_id": "RPC-200", "department": "ops"},
                    {"employee_id": "RPC-300", "department": "rpc"}
                ]
            }))
        }),
    );
    let (rest_base, rest_shutdown) = spawn_json_server(rest_router).await;
    let (rpc_base, rpc_shutdown) = spawn_json_server(rpc_router).await;

    let database_name = format!("sdqp_stage6_adapter_{}", ulid::Ulid::new());
    create_database(&database_name).await;
    let dsn = format!("postgres://sdqp:sdqp@127.0.0.1:15432/{database_name}");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&dsn)
        .await
        .expect("postgres");
    pool.execute(
        r#"
        CREATE TABLE stage6_employee_rows (
            employee_id TEXT NOT NULL,
            department TEXT NOT NULL
        )
        "#,
    )
    .await
    .expect("create table");
    pool.execute(
        r#"
        INSERT INTO stage6_employee_rows (employee_id, department)
        VALUES ('SQL-100', 'warehouse'), ('SQL-200', 'ops'), ('SQL-300', 'warehouse')
        "#,
    )
    .await
    .expect("insert rows");

    let registry = AdapterRegistry::from_configs([
        DataSourceConfig {
            data_source_id: "datasource-rest".into(),
            source_type: SourceType::Rest,
            connection_uri: format!("{rest_base}/rows"),
            adapter_config: json!({}),
        },
        DataSourceConfig {
            data_source_id: "datasource-rpc".into(),
            source_type: SourceType::Rpc,
            connection_uri: format!("{rpc_base}/rpc"),
            adapter_config: json!({}),
        },
        DataSourceConfig {
            data_source_id: "datasource-rdbms".into(),
            source_type: SourceType::Rdbms,
            connection_uri: dsn.clone(),
            adapter_config: json!({"table": "stage6_employee_rows"}),
        },
    ]);

    let mut query = UnifiedQuery::new(vec![FieldSelector::new("employee_id").expect("field")]);
    query.conditions = vec![FilterCondition {
        field: "department".into(),
        operator: FilterOperator::Neq,
        value: "ops".into(),
    }];
    query.pagination = Some(Pagination::bounded(1, Some("1".into())).expect("pagination"));
    let rest_result = registry
        .execute_query("datasource-rest", &SourceType::Rest, query.clone())
        .await
        .expect("rest query");
    let rpc_result = registry
        .execute_query("datasource-rpc", &SourceType::Rpc, query.clone())
        .await
        .expect("rpc query");

    let sql_query = query;
    let sql_result = registry
        .execute_query("datasource-rdbms", &SourceType::Rdbms, sql_query)
        .await
        .expect("sql query");

    assert_eq!(rest_result.rows.len(), 1);
    assert_eq!(rpc_result.rows.len(), 1);
    assert_eq!(sql_result.rows.len(), 1);
    assert_eq!(rest_result.rows[0][0].field, "employee_id");
    assert_eq!(rpc_result.rows[0][0].field, "employee_id");
    assert_eq!(sql_result.rows[0][0].field, "employee_id");
    assert_eq!(rest_result.rows[0][0].value, "REST-300");
    assert_eq!(rpc_result.rows[0][0].value, "RPC-300");
    assert_eq!(sql_result.rows[0][0].value, "SQL-300");

    let _ = rest_shutdown.send(());
    let _ = rpc_shutdown.send(());
    drop(pool);
    drop_database(&database_name).await;
}
