use thiserror::Error;

use sdqp_core::RequestContext;

use crate::{ProjectContext, ProjectState};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IsolationError {
    #[error("project is not visible in this tenant")]
    ProjectInvisible,
    #[error("request scope does not match project scope")]
    ScopeMismatch,
    #[error("project is archived or deleted")]
    ProjectUnavailable,
}

pub struct TenantIsolationGuard;

impl TenantIsolationGuard {
    pub fn assert_request_in_project(
        request: &RequestContext,
        project: &ProjectContext,
    ) -> Result<(), IsolationError> {
        if request.tenant_id != project.tenant_id {
            return Err(IsolationError::ProjectInvisible);
        }

        if request
            .project_id
            .as_ref()
            .map(|project_id| project_id != &project.project_id)
            .unwrap_or(true)
        {
            return Err(IsolationError::ScopeMismatch);
        }

        if matches!(
            project.state,
            ProjectState::Archived | ProjectState::Deleted
        ) {
            return Err(IsolationError::ProjectUnavailable);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{IsolationError, TenantIsolationGuard};
    use crate::{ProjectContext, ProjectState};
    use sdqp_core::{ProjectId, RequestContext, TenantId, UserId};

    #[test]
    fn guard_rejects_scope_mismatch() {
        let project = ProjectContext::new(
            TenantId::new("tenant-a").expect("tenant"),
            ProjectId::new("project-a").expect("project"),
            ProjectState::Active,
        );
        let request = RequestContext::new(
            TenantId::new("tenant-a").expect("tenant"),
            UserId::new("user-a").expect("user"),
        )
        .with_project(ProjectId::new("project-b").expect("project"));

        assert_eq!(
            TenantIsolationGuard::assert_request_in_project(&request, &project),
            Err(IsolationError::ScopeMismatch)
        );
    }

    #[test]
    fn guard_hides_cross_tenant_projects() {
        let project = ProjectContext::new(
            TenantId::new("tenant-a").expect("tenant"),
            ProjectId::new("project-a").expect("project"),
            ProjectState::Active,
        );
        let request = RequestContext::new(
            TenantId::new("tenant-b").expect("tenant"),
            UserId::new("user-a").expect("user"),
        )
        .with_project(ProjectId::new("project-a").expect("project"));

        assert_eq!(
            TenantIsolationGuard::assert_request_in_project(&request, &project),
            Err(IsolationError::ProjectInvisible)
        );
    }
}
