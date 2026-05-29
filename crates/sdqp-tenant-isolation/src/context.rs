use sdqp_core::{ProjectId, RequestContext, TenantId};
use serde::{Deserialize, Serialize};

use crate::ProjectState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: TenantId,
}

impl TenantContext {
    pub fn new(tenant_id: TenantId) -> Self {
        Self { tenant_id }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectObjectNamespace {
    pub object_bucket: String,
    pub key_prefix: String,
}

impl ProjectObjectNamespace {
    pub fn for_project(
        object_bucket: impl Into<String>,
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) -> Self {
        Self {
            object_bucket: object_bucket.into(),
            key_prefix: format!("snapshots/{}/{}/", tenant_id.as_str(), project_id.as_str()),
        }
    }

    pub fn contains_key(&self, bucket: &str, key: &str) -> bool {
        self.object_bucket == bucket && key.starts_with(&self.key_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectContext {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub state: ProjectState,
    pub object_namespace: ProjectObjectNamespace,
    pub created_by_user_id: Option<String>,
    pub deletion_reason: Option<String>,
}

impl ProjectContext {
    pub fn new(tenant_id: TenantId, project_id: ProjectId, state: ProjectState) -> Self {
        let object_namespace =
            ProjectObjectNamespace::for_project("sdqp-snapshots", &tenant_id, &project_id);
        Self::new_with_namespace(tenant_id, project_id, state, object_namespace)
    }

    pub fn new_with_namespace(
        tenant_id: TenantId,
        project_id: ProjectId,
        state: ProjectState,
        object_namespace: ProjectObjectNamespace,
    ) -> Self {
        Self {
            tenant_id,
            project_id,
            state,
            object_namespace,
            created_by_user_id: None,
            deletion_reason: None,
        }
    }

    pub fn with_object_bucket(mut self, object_bucket: impl Into<String>) -> Self {
        self.object_namespace =
            ProjectObjectNamespace::for_project(object_bucket, &self.tenant_id, &self.project_id);
        self
    }

    pub fn with_created_by(mut self, user_id: impl Into<String>) -> Self {
        self.created_by_user_id = Some(user_id.into());
        self
    }

    pub fn mark_deleted(&mut self, reason: impl Into<String>) {
        self.state = ProjectState::Deleted;
        self.deletion_reason = Some(reason.into());
    }

    pub fn owns_object_key(&self, bucket: &str, key: &str) -> bool {
        self.object_namespace.contains_key(bucket, key)
    }

    pub fn matches_request(&self, request: &RequestContext) -> bool {
        request.tenant_id == self.tenant_id
            && request
                .project_id
                .as_ref()
                .map(|project_id| project_id == &self.project_id)
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::ProjectContext;
    use crate::ProjectState;
    use sdqp_core::{ProjectId, RequestContext, TenantId, UserId};

    #[test]
    fn project_context_matches_request_scope() {
        let tenant_id = TenantId::new("tenant-a").expect("tenant");
        let project_id = ProjectId::new("project-a").expect("project");
        let project =
            ProjectContext::new(tenant_id.clone(), project_id.clone(), ProjectState::Active);
        let request = RequestContext::new(tenant_id, UserId::new("user-a").expect("user"))
            .with_project(project_id);

        assert!(project.matches_request(&request));
    }
}
