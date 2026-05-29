#![recursion_limit = "1024"]

pub mod health;
pub mod openapi;
pub mod proto;
pub mod service;

pub use health::{HealthStatus, ServiceHealth};
pub use openapi::{build_openapi_document, build_proto_contract_index};
pub use service::{API_SERVICE_NAME, PHASE0_MILESTONE, WORKER_SERVICE_NAME, phase0_services};
