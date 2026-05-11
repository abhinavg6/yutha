//! [`Caveat`] — additional conditions that further constrain a capability.
//!
//! Closed vocabulary at v1.0: six types. Each caveat is evaluated by the
//! control plane at check time. Constitution-defined arbitrary conditions
//! live in the Cedar+ layer, not as caveats.

/// Caveats that constrain a capability beyond its scope.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Caveat {
    /// "Only between HH:MM and HH:MM UTC."
    TimeOfDay(TimeOfDay),
    /// "Only under constitution version in [min, max]."
    ConstitutionVersion {
        /// Inclusive minimum semver.
        min_version: String,
        /// Inclusive maximum semver, or None for no upper bound.
        max_version: Option<String>,
    },
    /// "Requires a supervisor with this role to countersign the receipt."
    SupervisorRequired {
        /// Role string the supervisor must have (e.g. `"production-approver"`).
        supervisor_role: String,
    },
    /// "At most N actions per window seconds."
    RateLimit(RateLimit),
    /// "Only on resources tagged with ALL of these."
    OnlyIfTagged {
        /// All tags must be present in the action descriptor.
        required_tags: Vec<String>,
    },
    /// "Never on resources tagged with ANY of these."
    NeverIfTagged {
        /// Any of these tags being present denies the action.
        forbidden_tags: Vec<String>,
    },
}

/// Time-of-day caveat (UTC).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeOfDay {
    /// Format `"HH:MM"` (24-hour, UTC).
    pub from_utc: String,
    /// Format `"HH:MM"` (24-hour, UTC).
    pub to_utc: String,
}

/// Rate-limit caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RateLimit {
    /// Maximum permitted actions in `window_seconds`.
    pub max_actions: u32,
    /// Window length in seconds.
    pub window_seconds: u64,
}

impl Caveat {
    /// Evaluate this caveat against an action descriptor. Returns true if
    /// the caveat permits the action.
    ///
    /// Some caveats (rate limit, time of day) need additional runtime
    /// context (current wall time, action history). At this scaffolding
    /// level only the tag-based caveats can be fully evaluated from the
    /// descriptor alone; the others always return Ok (deferred to the
    /// control plane's rate-limiter and clock-aware evaluator).
    pub fn permits(&self, descriptor: &crate::check::ActionDescriptor) -> bool {
        match self {
            Caveat::OnlyIfTagged { required_tags } => required_tags
                .iter()
                .all(|t| descriptor.resource_tags.contains(t)),
            Caveat::NeverIfTagged { forbidden_tags } => !forbidden_tags
                .iter()
                .any(|t| descriptor.resource_tags.contains(t)),
            // The three caveats below require external context that the
            // scaffolding doesn't have; they are evaluated higher up the
            // stack. At this layer they pass.
            Caveat::TimeOfDay(_) => true,
            Caveat::RateLimit(_) => true,
            // Constitution-version evaluation lives at the Cedar+ layer.
            Caveat::ConstitutionVersion { .. } => true,
            // Supervisor-required is a receipt-shape requirement, not an
            // action-time decision; the enforcement loop checks it when the
            // receipt is produced.
            Caveat::SupervisorRequired { .. } => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::ActionDescriptor;

    #[test]
    fn only_if_tagged_requires_all_tags() {
        let c = Caveat::OnlyIfTagged {
            required_tags: vec!["pii".into(), "external".into()],
        };
        let with_all = ActionDescriptor {
            action_kind: "x".into(),
            resource_tags: vec!["pii".into(), "external".into()],
            ..Default::default()
        };
        assert!(c.permits(&with_all));

        let with_one = ActionDescriptor {
            action_kind: "x".into(),
            resource_tags: vec!["pii".into()],
            ..Default::default()
        };
        assert!(!c.permits(&with_one));
    }

    #[test]
    fn never_if_tagged_blocks_on_any() {
        let c = Caveat::NeverIfTagged {
            forbidden_tags: vec!["external".into()],
        };
        let without = ActionDescriptor {
            action_kind: "x".into(),
            resource_tags: vec!["internal".into()],
            ..Default::default()
        };
        assert!(c.permits(&without));

        let with = ActionDescriptor {
            action_kind: "x".into(),
            resource_tags: vec!["external".into()],
            ..Default::default()
        };
        assert!(!c.permits(&with));
    }
}
