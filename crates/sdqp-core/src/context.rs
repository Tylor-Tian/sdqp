use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{ProjectId, TenantId, UserId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub tenant_id: TenantId,
    pub project_id: Option<ProjectId>,
    pub user_id: UserId,
    pub issued_at: DateTime<Utc>,
}

impl RequestContext {
    pub fn new(tenant_id: TenantId, user_id: UserId) -> Self {
        Self {
            request_id: Ulid::new().to_string(),
            tenant_id,
            project_id: None,
            user_id,
            issued_at: Utc::now(),
        }
    }

    pub fn with_project(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    pub fn project_scope_key(&self) -> String {
        match &self.project_id {
            Some(project_id) => format!(
                "{}/{}/{}",
                self.tenant_id.as_str(),
                project_id.as_str(),
                self.user_id.as_str()
            ),
            None => format!("{}/-/{}", self.tenant_id.as_str(), self.user_id.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestContext;
    use crate::{ProjectId, TenantId, UserId};

    #[test]
    fn request_context_generates_request_id() {
        let context = RequestContext::new(
            TenantId::new("tenant-a").expect("valid tenant"),
            UserId::new("user-a").expect("valid user"),
        );

        assert!(!context.request_id.is_empty());
        assert!(context.project_id.is_none());
    }

    #[test]
    fn request_context_can_attach_project() {
        let context = RequestContext::new(
            TenantId::new("tenant-a").expect("valid tenant"),
            UserId::new("user-a").expect("valid user"),
        )
        .with_project(ProjectId::new("project-a").expect("valid project"));

        assert_eq!(context.project_scope_key(), "tenant-a/project-a/user-a");
    }

    #[test]
    fn request_context_without_project_uses_dash_scope() {
        let context = RequestContext::new(
            TenantId::new("tenant-a").expect("valid tenant"),
            UserId::new("user-a").expect("valid user"),
        );

        assert_eq!(context.project_scope_key(), "tenant-a/-/user-a");
    }
}
