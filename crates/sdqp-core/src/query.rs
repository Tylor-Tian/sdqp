use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSelector(String);

impl FieldSelector {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(CoreError::EmptyFieldSelector);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterOperator {
    Eq,
    Neq,
    Gt,
    Lt,
    Like,
    In,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterCondition {
    pub field: String,
    pub operator: FilterOperator,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FilterConditionGroup {
    #[serde(default)]
    pub conditions: Vec<FilterCondition>,
}

impl FilterConditionGroup {
    pub fn new(conditions: Vec<FilterCondition>) -> Self {
        Self { conditions }
    }

    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pagination {
    pub page_size: usize,
    pub cursor: Option<String>,
}

impl Pagination {
    pub const MAX_PAGE_SIZE: usize = 500;

    pub fn bounded(page_size: usize, cursor: Option<String>) -> CoreResult<Self> {
        if !(1..=Self::MAX_PAGE_SIZE).contains(&page_size) {
            return Err(CoreError::InvalidPageSize {
                max: Self::MAX_PAGE_SIZE,
            });
        }

        Ok(Self { page_size, cursor })
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldSelector, FilterCondition, FilterConditionGroup, FilterOperator, Pagination};
    use crate::CoreError;

    #[test]
    fn field_selector_requires_non_empty_value() {
        assert_eq!(FieldSelector::new(""), Err(CoreError::EmptyFieldSelector));
    }

    #[test]
    fn field_selector_returns_inner_value() {
        let field = FieldSelector::new("employee_email").expect("valid field");
        assert_eq!(field.as_str(), "employee_email");
    }

    #[test]
    fn pagination_rejects_oversized_page() {
        assert_eq!(
            Pagination::bounded(501, None),
            Err(CoreError::InvalidPageSize { max: 500 })
        );
    }

    #[test]
    fn pagination_accepts_valid_page() {
        let pagination = Pagination::bounded(100, Some("cursor-1".into())).expect("valid page");
        assert_eq!(pagination.page_size, 100);
        assert_eq!(pagination.cursor.as_deref(), Some("cursor-1"));
    }

    #[test]
    fn filter_condition_group_tracks_empty_state() {
        let empty = FilterConditionGroup::default();
        let populated = FilterConditionGroup::new(vec![FilterCondition {
            field: "employee_id".into(),
            operator: FilterOperator::Eq,
            value: "E-100".into(),
        }]);

        assert!(empty.is_empty());
        assert!(!populated.is_empty());
    }
}
