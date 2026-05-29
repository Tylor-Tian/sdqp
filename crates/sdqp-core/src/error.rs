use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("identifier cannot be empty")]
    EmptyIdentifier,
    #[error("field selector cannot be empty")]
    EmptyFieldSelector,
    #[error("page size must be between 1 and {max}")]
    InvalidPageSize { max: usize },
}

pub type CoreResult<T> = Result<T, CoreError>;
