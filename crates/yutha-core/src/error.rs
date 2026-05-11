//! Error types shared across the Yutha workspace.
//!
//! Crate-specific errors typically wrap [`CoreError`]; the receipt store, the
//! transport layer, the constitution evaluator each ship their own thiserror
//! enum and convert into / from `CoreError` at boundaries.

use thiserror::Error;

/// Result alias bound to [`CoreError`]. Most public APIs in `yutha-core`
/// return this.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors that can be raised by primitive operations on shared types.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A fixed-length byte sequence had the wrong length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    /// An unknown enum value was encountered (e.g., a future-version
    /// hash algorithm). Per spec versioning policy, receivers default to
    /// the conservative interpretation and surface — never silently coerce.
    #[error("unknown enum value: {context}")]
    UnknownEnumValue {
        /// Where the unknown value was encountered.
        context: &'static str,
    },

    /// Validation failed for a structured value.
    #[error("validation failed: {0}")]
    Validation(String),

    /// A timestamp could not be parsed or formatted.
    #[error("timestamp error: {0}")]
    Timestamp(String),

    /// A version string could not be parsed.
    #[error("version error: {0}")]
    Version(String),

    /// Wrapper for upstream errors at boundaries.
    #[error("internal: {0}")]
    Internal(String),
}

impl CoreError {
    /// Construct a validation error from any displayable message.
    pub fn validation(msg: impl std::fmt::Display) -> Self {
        Self::Validation(msg.to_string())
    }

    /// Construct an internal error from any displayable message.
    pub fn internal(msg: impl std::fmt::Display) -> Self {
        Self::Internal(msg.to_string())
    }
}
