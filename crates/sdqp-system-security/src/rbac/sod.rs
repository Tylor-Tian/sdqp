use thiserror::Error;

use super::Role;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecurityError {
    #[error("role combination violates separation of duties")]
    SeparationOfDutiesViolation,
}

pub fn enforce_separation_of_duties(roles: &[Role]) -> Result<(), SecurityError> {
    let has_system_admin = roles.iter().any(|role| role == &Role::SystemAdmin);
    let has_data_access = roles.iter().any(Role::has_data_access);

    if has_system_admin && has_data_access {
        return Err(SecurityError::SeparationOfDutiesViolation);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Role, SecurityError, enforce_separation_of_duties};

    #[test]
    fn denies_system_admin_plus_analyst() {
        assert_eq!(
            enforce_separation_of_duties(&[Role::SystemAdmin, Role::Analyst]),
            Err(SecurityError::SeparationOfDutiesViolation)
        );
    }

    #[test]
    fn allows_project_admin_plus_approver() {
        assert!(enforce_separation_of_duties(&[Role::ProjectAdmin, Role::Approver]).is_ok());
    }
}
