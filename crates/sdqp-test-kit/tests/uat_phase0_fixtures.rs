use sdqp_test_kit::{sample_request_context, sample_settings};

#[test]
fn phase0_test_kit_provides_stable_fixtures() {
    let context = sample_request_context();
    let settings = sample_settings();

    assert_eq!(
        context.project_scope_key(),
        "tenant-test/project-test/user-test"
    );
    assert_eq!(settings.api.port, 8080);
}
