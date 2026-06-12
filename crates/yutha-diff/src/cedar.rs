//! Cedar policy diff substrate.
//!
//! Cedar policies don't fit the engine-config "named items with
//! `.name`" shape — they're text + parse tree, and may or may not
//! carry an explicit `@id("...")` annotation. This module:
//!
//! - Parses each side's `cedar_source` into a [`cedar_policy::PolicySet`].
//! - Lifts every policy into a [`CedarPolicyEntry`] carrying a `name`
//!   that's either the operator-supplied `@id` OR a stable
//!   structural fingerprint when `@id` was omitted.
//! - Returns the lifted lists, sorted by name, ready for the
//!   `diff_named_items` matcher in [`crate::diff`].
//!
//! ## Match strategy (locked at 3d-A)
//!
//! - **Annotated policies** (carry `@id("name")`) match by id alone.
//!   Two annotated policies with the same id are "the same policy"
//!   even if their bodies differ — the body delta becomes a
//!   `modified` entry.
//! - **Un-annotated policies** match by a structural fingerprint:
//!   `effect:scope_shape:body_hash`. Two un-annotated policies with
//!   identical effect + scope shape + body collapse into the same
//!   entry on each side; reorderings of un-annotated policies are
//!   therefore stable across diffs.
//!
//! Operators SHOULD `@id` every policy by Yutha convention; this
//! fallback exists so legacy un-annotated policies don't break the
//! tool. Renderers surface a soft "consider annotating with `@id`"
//! hint when any un-annotated entry is encountered.

use std::str::FromStr;

use cedar_policy::PolicySet;
use serde::{Deserialize, Serialize};

use crate::error::{DiffError, Result};

/// Cedar effect: Permit or Forbid. Serde-friendly mirror of
/// [`cedar_policy::Effect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CedarPolicyEffect {
    /// `permit (...) when {...};`
    Permit,
    /// `forbid (...) when {...};`
    Forbid,
}

impl std::fmt::Display for CedarPolicyEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CedarPolicyEffect::Permit => f.write_str("permit"),
            CedarPolicyEffect::Forbid => f.write_str("forbid"),
        }
    }
}

impl From<cedar_policy::Effect> for CedarPolicyEffect {
    fn from(e: cedar_policy::Effect) -> Self {
        match e {
            cedar_policy::Effect::Permit => Self::Permit,
            cedar_policy::Effect::Forbid => Self::Forbid,
        }
    }
}

/// One Cedar policy lifted from a `PolicySet` for diffing.
///
/// `name` is either the operator-supplied `@id` annotation OR a
/// stable structural fingerprint when `@id` was omitted (see module
/// doc-comment). `source` is the policy's rendered Cedar text — used
/// by renderers for inline display + canonical-bytes equality check
/// for modified detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarPolicyEntry {
    /// Matching key. Either the operator's `@id("...")` value or
    /// `<effect>:<scope_shape>:<body_hash>` for un-annotated
    /// policies.
    pub name: String,
    /// `true` when the source carried an explicit `@id`; `false`
    /// when `name` is the synthetic fingerprint. Renderers surface
    /// the "consider annotating" hint when ANY lifted entry is
    /// un-annotated.
    pub annotated: bool,
    /// Cedar effect: Permit or Forbid.
    pub effect: CedarPolicyEffect,
    /// Rendered Cedar source text for this single policy. Equal to
    /// `policy.to_string()` from the `Display` impl.
    pub source: String,
}

impl CedarPolicyEntry {
    /// Construct an entry directly. Public so render-only tests can
    /// populate fixtures without going through `lift_policies`.
    pub fn new(
        name: impl Into<String>,
        annotated: bool,
        effect: CedarPolicyEffect,
        source: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            annotated,
            effect,
            source: source.into(),
        }
    }
}

/// Lift every policy out of `cedar_source` (after parsing) into a
/// sorted-by-name list of [`CedarPolicyEntry`].
///
/// Parse failures bubble up as [`DiffError::CedarParse`] tagged with
/// `side` (`"left"` or `"right"`) so renderers can surface which
/// constitution was at fault.
pub fn lift_policies(side: &'static str, cedar_source: &str) -> Result<Vec<CedarPolicyEntry>> {
    let policy_set = PolicySet::from_str(cedar_source)
        .map_err(|source| DiffError::CedarParse { side, source })?;

    let mut out = Vec::new();
    for policy in policy_set.policies() {
        let effect: CedarPolicyEffect = policy.effect().into();
        let source_text = policy.to_string();

        // `@id("...")` is a regular Cedar annotation in 3.x — NOT
        // the same as `policy.id()`, which always returns an
        // auto-generated string (`policy0`, `policy1`, ...). The
        // operator-supplied id lives under the "id" annotation key.
        let annotated_id = policy.annotation("id").map(|s| s.to_string());

        let (name, annotated) = match annotated_id {
            Some(id) => (id, true),
            None => {
                // Un-annotated → stable structural fingerprint so
                // source-order reorderings don't flip rows between
                // sides.
                let scope = scope_shape(policy);
                let body = stable_hash(source_text.as_bytes());
                (format!("{effect}:{scope}:{body}"), false)
            }
        };

        out.push(CedarPolicyEntry {
            name,
            annotated,
            effect,
            source: source_text,
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// `true` when ANY entry in the list lacks an `@id`. Renderers use
/// this to decide whether to surface the "consider annotating" hint.
pub fn has_unannotated_policies(entries: &[CedarPolicyEntry]) -> bool {
    entries.iter().any(|e| !e.annotated)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Rough shape of the policy's scope (principal / action / resource).
/// Used as part of the structural fingerprint for un-annotated
/// policies. Stable across runs via the Debug impl on each
/// constraint variant.
fn scope_shape(policy: &cedar_policy::Policy) -> String {
    let p = format!("{:?}", policy.principal_constraint());
    let a = format!("{:?}", policy.action_constraint());
    let r = format!("{:?}", policy.resource_constraint());
    format!("{p}|{a}|{r}")
}

/// Short, deterministic non-cryptographic hash of `bytes` for the
/// structural fingerprint. We can't add a `blake3` dep just for
/// this; std's hasher gives us the determinism + low collision rate
/// we actually need (the fingerprint isn't security-sensitive).
fn stable_hash(bytes: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotated_policy_uses_id() {
        let src = r#"
            @id("no-forbidden-payloads")
            forbid (principal, action, resource)
            when { context.tag == "bad" };

            permit (principal, action, resource);
        "#;
        let entries = lift_policies("left", src).expect("parses");
        // Annotated policy by @id, un-annotated permit policy as
        // structural fingerprint.
        assert_eq!(entries.len(), 2);
        let annotated: Vec<_> = entries.iter().filter(|e| e.annotated).collect();
        assert_eq!(annotated.len(), 1);
        assert_eq!(annotated[0].name, "no-forbidden-payloads");
        assert_eq!(annotated[0].effect, CedarPolicyEffect::Forbid);
        // The unannotated permit's name is the structural fingerprint
        // — starts with the effect prefix.
        let unannotated: Vec<_> = entries.iter().filter(|e| !e.annotated).collect();
        assert_eq!(unannotated.len(), 1);
        assert!(unannotated[0].name.starts_with("permit:"));
    }

    #[test]
    fn unannotated_policies_stable_under_reorder() {
        // Two un-annotated permit policies with different bodies.
        // Reordering source MUST yield the same set of fingerprints.
        let src_a = r#"
            permit (principal, action, resource) when { principal == User::"alice" };
            permit (principal, action, resource) when { principal == User::"bob" };
        "#;
        let src_b = r#"
            permit (principal, action, resource) when { principal == User::"bob" };
            permit (principal, action, resource) when { principal == User::"alice" };
        "#;
        let entries_a = lift_policies("left", src_a).expect("parses a");
        let entries_b = lift_policies("right", src_b).expect("parses b");
        let names_a: Vec<_> = entries_a.iter().map(|e| &e.name).collect();
        let names_b: Vec<_> = entries_b.iter().map(|e| &e.name).collect();
        assert_eq!(names_a, names_b, "reordering must not change fingerprints");
        assert!(entries_a.iter().all(|e| !e.annotated));
        assert!(has_unannotated_policies(&entries_a));
    }

    #[test]
    fn parse_failure_tags_side() {
        let err = lift_policies("right", "this is not cedar").unwrap_err();
        match err {
            DiffError::CedarParse { side, .. } => assert_eq!(side, "right"),
            other => panic!("expected CedarParse, got {other:?}"),
        }
    }
}
