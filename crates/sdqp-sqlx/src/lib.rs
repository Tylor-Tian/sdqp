pub use sqlx_core::{
    Error, Result, executor::Executor, query::query, query_as::query_as,
    query_scalar::query_scalar, row::Row, types,
};
pub use sqlx_postgres::{PgPool, PgPoolOptions, PgQueryResult, PgRow, Postgres};

pub mod migrate {
    pub use sqlx_core::migrate::*;
}

pub mod postgres {
    pub use sqlx_postgres::{PgPool, PgPoolOptions, PgQueryResult, PgRow, Postgres};
}
