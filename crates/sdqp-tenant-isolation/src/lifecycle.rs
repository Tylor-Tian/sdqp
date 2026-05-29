use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectState {
    Created,
    Active,
    Frozen,
    Archived,
    Deleted,
}

impl ProjectState {
    pub fn can_accept_new_permissions(&self) -> bool {
        matches!(self, Self::Created | Self::Active)
    }

    pub fn can_export(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::Frozen)
    }

    pub fn is_externally_visible(&self) -> bool {
        !matches!(self, Self::Deleted)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("invalid project transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: ProjectState,
        to: ProjectState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectLifecycle {
    state: ProjectState,
}

impl ProjectLifecycle {
    pub fn new(state: ProjectState) -> Self {
        Self { state }
    }

    pub fn state(&self) -> ProjectState {
        self.state
    }

    pub fn transition_to(&mut self, next: ProjectState) -> Result<(), LifecycleError> {
        let allowed = match (self.state, next) {
            (ProjectState::Created, ProjectState::Active)
            | (ProjectState::Created, ProjectState::Deleted)
            | (ProjectState::Active, ProjectState::Frozen)
            | (ProjectState::Active, ProjectState::Archived)
            | (ProjectState::Active, ProjectState::Deleted)
            | (ProjectState::Frozen, ProjectState::Active)
            | (ProjectState::Frozen, ProjectState::Archived)
            | (ProjectState::Frozen, ProjectState::Deleted)
            | (ProjectState::Archived, ProjectState::Deleted) => true,
            (current, target) if current == target => true,
            _ => false,
        };

        if !allowed {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }

        self.state = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{LifecycleError, ProjectLifecycle, ProjectState};

    #[test]
    fn active_projects_allow_export() {
        assert!(ProjectState::Active.can_export());
        assert!(!ProjectState::Frozen.can_export());
    }

    #[test]
    fn lifecycle_rejects_invalid_transition() {
        let mut lifecycle = ProjectLifecycle::new(ProjectState::Created);
        assert_eq!(
            lifecycle.transition_to(ProjectState::Archived),
            Err(LifecycleError::InvalidTransition {
                from: ProjectState::Created,
                to: ProjectState::Archived,
            })
        );
    }

    #[test]
    fn lifecycle_allows_direct_delete_for_runtime_closure() {
        let mut lifecycle = ProjectLifecycle::new(ProjectState::Active);
        lifecycle
            .transition_to(ProjectState::Deleted)
            .expect("active project can be deleted");
        assert_eq!(lifecycle.state(), ProjectState::Deleted);
    }
}
