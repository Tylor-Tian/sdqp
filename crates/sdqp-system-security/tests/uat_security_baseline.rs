use sdqp_system_security::{AdaptiveResponse, Role, SecurityError, enforce_separation_of_duties};

#[test]
fn uat_security_baseline_blocks_admin_data_access_overlap() {
    assert_eq!(
        enforce_separation_of_duties(&[Role::SystemAdmin, Role::Analyst]),
        Err(SecurityError::SeparationOfDutiesViolation)
    );
    assert_eq!(
        AdaptiveResponse::for_score(75.0),
        AdaptiveResponse::TerminateSession
    );
}
