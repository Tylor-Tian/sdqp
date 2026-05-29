use sdqp_contracts::{
    API_SERVICE_NAME, PHASE0_MILESTONE, ServiceHealth, phase0_services,
    proto::common::HealthResponse,
};

#[test]
fn phase0_contracts_expose_ready_api_service() {
    let health = ServiceHealth::ready(API_SERVICE_NAME, PHASE0_MILESTONE);

    assert!(phase0_services().contains(&API_SERVICE_NAME));
    assert_eq!(health.service, API_SERVICE_NAME);
    assert_eq!(health.phase, PHASE0_MILESTONE);

    let response = HealthResponse {
        service: API_SERVICE_NAME.to_string(),
        status: "ready".into(),
        phase: PHASE0_MILESTONE.to_string(),
        details: Default::default(),
    };
    assert_eq!(response.service, API_SERVICE_NAME);
}
