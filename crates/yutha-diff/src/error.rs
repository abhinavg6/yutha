//! Error type for `yutha-diff`.
//!
//! Narrow surface: the structural diff is pure compute over already-
//! constructed [`yutha_cedar_plus::Constitution`] values; the only
//! failure modes are (1) Cedar source that doesn't parse, (2)
//! engine-config items whose serde-canonical bytes don't compute
//! (effectively impossible — both sides derive `Serialize`), (3)
//! render-side I/O when writing to a `Write` sink.

use thiserror::Error;

/// Errors that can occur during a diff or render call.
#[derive(Debug, Error)]
pub enum DiffError {
    /// One of the Cedar sources failed to parse as a `PolicySet`. The
    /// diff can't compare un-parsed policies — render-side fallback
    /// would silently miss rule-level deltas.
    #[error("Cedar parse failed for the {side} constitution: {source}")]
    CedarParse {
        /// Which constitution failed — `"left"` or `"right"`.
        side: &'static str,
        /// Underlying error.
        #[source]
        source: cedar_policy::ParseErrors,
    },

    /// An engine-config item's canonical-bytes computation failed.
    /// Mostly here to surface a clear error if a future engine-config
    /// type loses its `Serialize` derive — should not fire in
    /// practice.
    #[error("canonical-bytes computation failed for {context}: {source}")]
    CanonicalBytes {
        /// Free-form context — typically the section + item name.
        context: String,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// JSON renderer failed to serialize the diff.
    #[error("JSON render failed: {0}")]
    JsonRender(#[from] serde_json::Error),

    /// I/O failed when writing rendered output to a `Write` sink.
    #[error("output write failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Crate-level `Result` alias.
pub type Result<T> = std::result::Result<T, DiffError>;
