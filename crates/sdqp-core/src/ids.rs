use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

macro_rules! impl_id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> CoreResult<Self> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(CoreError::EmptyIdentifier);
                }

                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

impl_id_type!(TenantId);
impl_id_type!(ProjectId);
impl_id_type!(UserId);

#[cfg(test)]
mod tests {
    use super::{ProjectId, TenantId, UserId};
    use crate::CoreError;

    #[test]
    fn tenant_id_rejects_empty_value() {
        assert_eq!(TenantId::new("  "), Err(CoreError::EmptyIdentifier));
    }

    #[test]
    fn project_id_returns_inner_string() {
        let project_id = ProjectId::new("project-alpha").expect("valid project id");
        assert_eq!(project_id.as_str(), "project-alpha");
    }

    #[test]
    fn user_id_accepts_non_empty_value() {
        let user_id = UserId::new("user-001").expect("valid user id");
        assert_eq!(user_id.as_str(), "user-001");
    }
}
