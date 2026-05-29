use sdqp_core::{Pagination, ProjectId, RequestContext, TenantId, UserId};

#[test]
fn phase0_context_builds_project_scoped_request() {
    let context = RequestContext::new(
        TenantId::new("tenant-uat").expect("tenant"),
        UserId::new("user-uat").expect("user"),
    )
    .with_project(ProjectId::new("project-uat").expect("project"));

    let pagination = Pagination::bounded(50, None).expect("pagination");

    assert_eq!(
        context.project_scope_key(),
        "tenant-uat/project-uat/user-uat"
    );
    assert_eq!(pagination.page_size, 50);
}
