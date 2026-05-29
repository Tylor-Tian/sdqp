use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    SystemAdmin,
    ProjectAdmin,
    DataOwner,
    Analyst,
    Auditor,
    Approver,
}

impl Role {
    pub fn has_data_access(&self) -> bool {
        matches!(self, Self::Analyst)
    }
}
