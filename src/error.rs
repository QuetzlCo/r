//! Typed domain errors for the entire crate.
//! thiserror generates Display + Error impls automatically.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NormalizerError {
    /// All std::io::Error surfaces through here — file ops, mmap, flush.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    #[error("Regex compile error: {0}")]
    Regex(#[from] regex::Error),

    #[error("UTF-8 decode error on line {line}: {source}")]
    Utf8 {
        line: usize,
        #[source]
        source: std::str::Utf8Error,
    },

    #[error("Malformed record — cannot identify required fields: `{raw}`")]
    MalformedRecord { raw: String },

    #[error("Validation failed [{field}]: `{value}` — {reason}")]
    ValidationFailure {
        field:  String,
        value:  String,
        reason: String,
    },
}

/// Soft result type used throughout parsing pipeline.
pub type ParseResult<T> = Result<T, NormalizerError>;
