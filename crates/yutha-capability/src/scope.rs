//! [`Scope`] — what actions / resources / bounds a capability authorizes.
//!
//! Multi-dimensional: action kinds, resource tags, numeric bounds,
//! recipients, memory scopes. Attenuation intersects each dimension.
//! Empty list on a dimension means "all" — but operators are strongly
//! discouraged from leaving any dimension unbounded (every empty list is a
//! deny-by-default escape hatch).

use std::collections::BTreeMap;

/// Capability scope. All five dimensions must satisfy the action descriptor
/// for a check to pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Scope {
    /// Action kinds this capability permits. Empty = all kinds (discouraged).
    pub permitted_actions: Vec<String>,
    /// Resource tags this capability applies to. Empty = all resources.
    pub resource_tags: Vec<String>,
    /// Numeric bounds (decimal-string-encoded). Examples: `usd_max`,
    /// `count_max`.
    pub bounds: BTreeMap<String, String>,
    /// Recipient constraint for envelope-send actions: agent ids, role
    /// names, or wildcards. Empty = unconstrained.
    pub permitted_recipients: Vec<String>,
    /// Memory-scope constraint (Phase 2). Empty = unconstrained.
    pub memory_scopes: Vec<String>,
}

impl Scope {
    /// Empty (and thus maximally permissive) scope. Use sparingly; almost
    /// always wrong outside of root capabilities.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct a scope permitting a single action kind. Convenient for
    /// the common "this capability lets the holder do X" case.
    pub fn for_action(kind: impl Into<String>) -> Self {
        Self {
            permitted_actions: vec![kind.into()],
            ..Self::default()
        }
    }

    /// Builder: add a resource tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.resource_tags.push(tag.into());
        self
    }

    /// Builder: set a numeric bound.
    pub fn with_bound(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.bounds.insert(key.into(), value.into());
        self
    }

    /// Builder: permit sending to a specific recipient.
    pub fn with_recipient(mut self, recipient: impl Into<String>) -> Self {
        self.permitted_recipients.push(recipient.into());
        self
    }

    /// Intersect this scope with another, producing a scope at most as
    /// permissive as the more restrictive of the two on each dimension.
    ///
    /// Semantics per dimension:
    /// - **Action kinds**: intersection of the two sets, unless one is empty
    ///   (empty = "all" in spec semantics, so empty ∩ X = X).
    /// - **Resource tags**: same.
    /// - **Recipients / memory scopes**: same.
    /// - **Bounds**: for each key present in either, take the smaller value
    ///   (lexicographic on the decimal string — works for unsigned numerics
    ///   when the strings are normalized; documented gotcha).
    pub fn intersect(&self, other: &Scope) -> Scope {
        Scope {
            permitted_actions: intersect_or_take_one(
                &self.permitted_actions,
                &other.permitted_actions,
            ),
            resource_tags: intersect_or_take_one(&self.resource_tags, &other.resource_tags),
            bounds: intersect_bounds(&self.bounds, &other.bounds),
            permitted_recipients: intersect_or_take_one(
                &self.permitted_recipients,
                &other.permitted_recipients,
            ),
            memory_scopes: intersect_or_take_one(&self.memory_scopes, &other.memory_scopes),
        }
    }

    /// Whether `descriptor` is permitted by this scope. Strict: every
    /// dimension must match.
    pub fn permits(&self, descriptor: &crate::check::ActionDescriptor) -> bool {
        // Action.
        if !empty_or_contains(&self.permitted_actions, &descriptor.action_kind) {
            return false;
        }
        // Resource tags: every required tag must be permitted (or the
        // permitted set is "all").
        if !self.resource_tags.is_empty() {
            for tag in &descriptor.resource_tags {
                if !self.resource_tags.contains(tag) {
                    return false;
                }
            }
        }
        // Bounds: every numeric in descriptor must be ≤ the scope's bound.
        for (key, val) in &descriptor.numeric_values {
            if let Some(scope_bound) = self.bounds.get(key) {
                if !decimal_le(val, scope_bound) {
                    return false;
                }
            }
        }
        // Recipient.
        if let Some(recipient) = &descriptor.recipient {
            if !empty_or_contains(&self.permitted_recipients, recipient) {
                return false;
            }
        }
        // Memory scope.
        if let Some(mscope) = &descriptor.memory_scope {
            if !empty_or_contains(&self.memory_scopes, mscope) {
                return false;
            }
        }
        true
    }
}

/// `lhs ∩ rhs`, with "empty = all" semantics: if either side is empty, the
/// other side wins. If both non-empty, set intersection.
fn intersect_or_take_one(lhs: &[String], rhs: &[String]) -> Vec<String> {
    if lhs.is_empty() {
        return rhs.to_vec();
    }
    if rhs.is_empty() {
        return lhs.to_vec();
    }
    lhs.iter().filter(|x| rhs.contains(x)).cloned().collect()
}

fn empty_or_contains(scope_dim: &[String], needle: &str) -> bool {
    scope_dim.is_empty() || scope_dim.iter().any(|s| s == needle)
}

/// Intersect numeric bounds: for each key, take the smaller bound.
/// Decimal-string comparison via `decimal_le`.
fn intersect_bounds(
    lhs: &BTreeMap<String, String>,
    rhs: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in lhs {
        match rhs.get(k) {
            Some(rhs_v) => {
                // Smaller bound wins.
                if decimal_le(rhs_v, v) {
                    out.insert(k.clone(), rhs_v.clone());
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            None => {
                // rhs doesn't constrain this dimension; lhs's value holds.
                out.insert(k.clone(), v.clone());
            }
        }
    }
    for (k, v) in rhs {
        out.entry(k.clone()).or_insert_with(|| v.clone());
    }
    out
}

/// Compare two decimal strings (e.g. "500" vs "500.00"). Returns true if
/// `a <= b`. Parses to f64 internally; for the v1.0 alpha this is sufficient
/// (and adequate for budgets in cents-precision), but a future ADR may
/// switch to a real decimal type.
fn decimal_le(a: &str, b: &str) -> bool {
    let av: f64 = a.parse().unwrap_or(f64::INFINITY);
    let bv: f64 = b.parse().unwrap_or(f64::NEG_INFINITY);
    av <= bv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::ActionDescriptor;

    #[test]
    fn intersect_empty_takes_other() {
        let a = Scope::empty();
        let b = Scope::for_action("send_message");
        let i = a.intersect(&b);
        assert_eq!(i.permitted_actions, vec!["send_message"]);
    }

    #[test]
    fn intersect_two_sets_keeps_common() {
        let a = Scope {
            permitted_actions: vec!["x".into(), "y".into()],
            ..Default::default()
        };
        let b = Scope {
            permitted_actions: vec!["y".into(), "z".into()],
            ..Default::default()
        };
        let i = a.intersect(&b);
        assert_eq!(i.permitted_actions, vec!["y"]);
    }

    #[test]
    fn intersect_bounds_takes_smaller() {
        let a = Scope::empty().with_bound("usd_max", "500");
        let b = Scope::empty().with_bound("usd_max", "100");
        let i = a.intersect(&b);
        assert_eq!(i.bounds.get("usd_max"), Some(&"100".to_string()));
    }

    #[test]
    fn permits_action_only_if_listed() {
        let scope = Scope::for_action("issue_refund");
        let descriptor = ActionDescriptor {
            action_kind: "issue_refund".into(),
            ..Default::default()
        };
        assert!(scope.permits(&descriptor));

        let descriptor = ActionDescriptor {
            action_kind: "exfiltrate".into(),
            ..Default::default()
        };
        assert!(!scope.permits(&descriptor));
    }

    #[test]
    fn permits_respects_numeric_bound() {
        let scope = Scope::for_action("issue_refund").with_bound("usd", "500");

        let within = ActionDescriptor {
            action_kind: "issue_refund".into(),
            numeric_values: [("usd".to_string(), "100".to_string())].into(),
            ..Default::default()
        };
        assert!(scope.permits(&within));

        let exceeding = ActionDescriptor {
            action_kind: "issue_refund".into(),
            numeric_values: [("usd".to_string(), "501".to_string())].into(),
            ..Default::default()
        };
        assert!(!scope.permits(&exceeding));
    }
}
