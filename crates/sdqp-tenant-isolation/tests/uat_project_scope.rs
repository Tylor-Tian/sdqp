use sdqp_core::{ProjectId, RequestContext, TenantId, UserId};
use sdqp_tenant_isolation::{ProjectContext, ProjectState, TenantIsolationGuard};

#[test]
fn uat_project_scope_allows_matching_request() {
    let project = ProjectContext::new(
        TenantId::new("tenant-uat").expect("tenant"),
        ProjectId::new("project-uat").expect("project"),
        ProjectState::Active,
    );
    let request = RequestContext::new(
        TenantId::new("tenant-uat").expect("tenant"),
        UserId::new("user-uat").expect("user"),
    )
    .with_project(ProjectId::new("project-uat").expect("project"));

    assert!(TenantIsolationGuard::assert_request_in_project(&request, &project).is_ok());
}
