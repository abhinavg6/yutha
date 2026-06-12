//! JSON renderer.
//!
//! Emits the full [`ConstitutionDiff`] as pretty-printed JSON
//! (`serde_json::to_writer_pretty`). The shape is the
//! Serialize-derived layout of the type — field order matches the
//! struct declaration order in [`crate::model`] for stable git
//! diffs. The schema marker `"yutha-diff/v1"` rides on every output
//! under the top-level `diff_schema_version` key.
//!
//! ## Output shape
//!
//! ```json
//! {
//!   "diff_schema_version": "yutha-diff/v1",
//!   "left_constitution_version": "...",
//!   "right_constitution_version": "...",
//!   "schema_version_change": null,
//!   "cedar_policies":     { "added": [...], "removed": [...], "modified": [...] },
//!   "named_predicates":   { "added": [...], "removed": [...], "modified": [...] },
//!   "scoring_rules":      { "added": [...], "removed": [...], "modified": [...] },
//!   "procedures":         { "added": [...], "removed": [...], "modified": [...] },
//!   "enforcement_rules":  { "added": [...], "removed": [...], "modified": [...] },
//!   "behavioural": null
//! }
//! ```
//!
//! Empty sections render as `{"added": [], "removed": [],
//! "modified": []}` — they're never elided so consumers can rely on
//! shape stability. `schema_version_change` is `null` when the two
//! constitutions pin the same Cedar+ schema version; `behavioural`
//! is `null` when the diff was static-only.
//!
//! Per-entry `annotated` bool on each cedar-policy entry surfaces
//! whether the operator's source used an `@id("...")` annotation;
//! consumers can derive an "any un-annotated" summary from that
//! field if they want a CI gate on it.

use std::io::Write;

use crate::error::Result;
use crate::model::ConstitutionDiff;

/// Render `diff` as pretty-printed JSON to `out`. Trailing newline
/// included so output is line-tool-friendly (`| jq .`, `| diff`).
pub(crate) fn render(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    serde_json::to_writer_pretty(&mut *out, diff)?;
    out.write_all(b"\n")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::{CedarPolicyEffect, CedarPolicyEntry};
    use crate::diff::DIFF_SCHEMA_VERSION;
    use crate::model::NamedItemsDiff;

    fn empty_diff() -> ConstitutionDiff {
        ConstitutionDiff {
            diff_schema_version: DIFF_SCHEMA_VERSION.to_string(),
            left_constitution_version: "1.0.0".into(),
            right_constitution_version: "1.0.0".into(),
            schema_version_change: None,
            cedar_policies: NamedItemsDiff::default(),
            named_predicates: NamedItemsDiff::default(),
            scoring_rules: NamedItemsDiff::default(),
            procedures: NamedItemsDiff::default(),
            enforcement_rules: NamedItemsDiff::default(),
            behavioural: None,
        }
    }

    #[test]
    fn empty_diff_renders_full_shape() {
        let diff = empty_diff();
        let mut buf = Vec::new();
        render(&diff, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf8");

        // Schema marker present.
        assert!(s.contains(r#""diff_schema_version": "yutha-diff/v1""#));
        // Every section key present so consumers see shape stability
        // even on no-change diffs.
        for key in [
            "left_constitution_version",
            "right_constitution_version",
            "schema_version_change",
            "cedar_policies",
            "named_predicates",
            "scoring_rules",
            "procedures",
            "enforcement_rules",
            "behavioural",
        ] {
            assert!(s.contains(key), "missing key {key:?}:\n{s}");
        }
        // Trailing newline.
        assert!(s.ends_with("\n"));
    }

    #[test]
    fn output_round_trips_through_deserialize() {
        let mut diff = empty_diff();
        diff.cedar_policies.added.push(CedarPolicyEntry::new(
            "no-x",
            true,
            CedarPolicyEffect::Forbid,
            "forbid (principal, action, resource);",
        ));
        diff.schema_version_change = Some(("1.1.0".into(), "1.2.0".into()));

        let mut buf = Vec::new();
        render(&diff, &mut buf).expect("render");
        let reparsed: ConstitutionDiff = serde_json::from_slice(&buf).expect("deserialize");

        assert_eq!(reparsed.diff_schema_version, DIFF_SCHEMA_VERSION);
        assert_eq!(reparsed.cedar_policies.added.len(), 1);
        assert_eq!(reparsed.cedar_policies.added[0].name, "no-x");
        assert!(reparsed.cedar_policies.added[0].annotated);
        assert_eq!(
            reparsed.cedar_policies.added[0].effect,
            CedarPolicyEffect::Forbid
        );
        assert_eq!(
            reparsed.schema_version_change,
            Some(("1.1.0".to_string(), "1.2.0".to_string()))
        );
    }

    #[test]
    fn unannotated_bit_surfaces_in_output() {
        let mut diff = empty_diff();
        diff.cedar_policies.added.push(CedarPolicyEntry::new(
            "forbid:Any|Any|Any:abc123",
            false, // unannotated
            CedarPolicyEffect::Forbid,
            "forbid (principal, action, resource);",
        ));

        let mut buf = Vec::new();
        render(&diff, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf8");

        // `annotated: false` is visible per-entry so a CI gate can
        // walk the added/removed/modified arrays and derive a
        // policy-hygiene summary.
        assert!(s.contains(r#""annotated": false"#));
    }
}
