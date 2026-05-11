//! [`CostAnnotation`] — per-receipt cost transparency.
//!
//! Mirrors `CostAnnotation` from
//! [`/spec/common.proto`](../../../spec/common.proto). PRD §13.2 makes cost
//! transparency a first-class commitment; the `model_*` fields additionally
//! support A2 (compromised model) attribution.

/// Per-receipt cost annotation.
///
/// All fields optional; an implementation records what it can measure. The
/// `usd_cents_estimate` field is a decimal string to avoid float drift in
/// aggregated cost dashboards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CostAnnotation {
    /// LLM input tokens consumed.
    pub input_tokens: u64,
    /// LLM output tokens produced.
    pub output_tokens: u64,
    /// Number of tool calls invoked.
    pub tool_call_count: u64,
    /// Wall-clock duration of the action, in milliseconds.
    pub wall_time_ms: u64,
    /// USD cost estimate, decimal string (e.g. `"1.23"` = 1.23 cents).
    pub usd_cents_estimate: String,
    /// Model provider (e.g. `"anthropic"`, `"openai"`, `"google"`). Used for
    /// A2 attribution and for cross-agent correlation in observability.
    pub model_provider: String,
    /// Model name.
    pub model_name: String,
    /// Model version string.
    pub model_version: String,
}

impl CostAnnotation {
    /// Whether this annotation has any non-default field set.
    pub fn is_empty(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.tool_call_count == 0
            && self.wall_time_ms == 0
            && self.usd_cents_estimate.is_empty()
            && self.model_provider.is_empty()
            && self.model_name.is_empty()
            && self.model_version.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let c = CostAnnotation::default();
        assert!(c.is_empty());
    }

    #[test]
    fn populated_is_not_empty() {
        let c = CostAnnotation {
            input_tokens: 100,
            ..Default::default()
        };
        assert!(!c.is_empty());
    }
}
