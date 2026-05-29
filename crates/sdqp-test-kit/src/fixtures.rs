use sdqp_config::AppSettings;
use sdqp_core::{ProjectId, RequestContext, TenantId, UserId};

pub fn sample_request_context() -> RequestContext {
    RequestContext::new(
        TenantId::new("tenant-test").expect("valid tenant"),
        UserId::new("user-test").expect("valid user"),
    )
    .with_project(ProjectId::new("project-test").expect("valid project"))
}

pub fn sample_settings() -> AppSettings {
    AppSettings::local_dev()
}

#[cfg(test)]
mod tests {
    use super::{sample_request_context, sample_settings};

    #[test]
    fn fixture_context_has_project_scope() {
        let context = sample_request_context();
        assert_eq!(
            context.project_scope_key(),
            "tenant-test/project-test/user-test"
        );
    }

    #[test]
    fn fixture_settings_are_dev_defaults() {
        let settings = sample_settings();
        assert_eq!(settings.api.port, 8080);
        assert_eq!(settings.worker.port, 8081);
    }
}
