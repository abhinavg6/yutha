//! The structural-diff entry point: [`diff_constitutions`].
//!
//! Pure compute over two [`yutha_cedar_plus::Constitution`] values
//! plus a generic `diff_named_items` helper that handles the
//! add/remove/modify partition. The helper is reused across all five
//! sections (cedar policies + the four engine-config item families).
//!
//! Modified detection: two items with the same `name` are
//! "modified" iff their serde-canonical JSON bytes differ. We use
//! `serde_json::to_value` + a stable comparator rather than
//! `serde_json::to_string` because serde_json's default writer
//! preserves field order in struct serialization (no need for a
//! `BTreeMap` round-trip).

use yutha_cedar_plus::engine_config::{EnforcementRule, NamedPredicate, Procedure, ScoringRule};
use yutha_cedar_plus::Constitution;

use crate::cedar::{lift_policies, CedarPolicyEntry};
use crate::error::Result;
use crate::model::{ConstitutionDiff, NamedItemChange, NamedItemsDiff};

/// Stable schema marker baked into every emitted [`ConstitutionDiff`].
pub const DIFF_SCHEMA_VERSION: &str = "yutha-diff/v1";

/// Compute the structural diff between two constitutions.
///
/// Pure. No I/O. The returned [`ConstitutionDiff`] carries the
/// [`ConstitutionDiff::behavioural`] field as `None` — populating
/// that is the caller's responsibility (see `yutha-ops diff
/// --against-window`, 3d-G).
///
/// ## Errors
///
/// Returns [`DiffError::CedarParse`] if either side's `cedar_source`
/// fails to parse. The structural diff cannot meaningfully run
/// against an un-parseable Cedar source — a text-diff fallback would
/// silently miss policy-level deltas the operator actually cares
/// about.
pub fn diff_constitutions(left: &Constitution, right: &Constitution) -> Result<ConstitutionDiff> {
    // Schema version delta. None when the two pins match.
    let schema_version_change = if left.schema_version != right.schema_version {
        Some((left.schema_version.clone(), right.schema_version.clone()))
    } else {
        None
    };

    // Cedar policies — lifted to entries first, then diffed by
    // (name, source) just like the engine-config sections.
    let left_policies = lift_policies("left", &left.cedar_source)?;
    let right_policies = lift_policies("right", &right.cedar_source)?;
    let cedar_policies = diff_named_items(left_policies, right_policies, |e: &CedarPolicyEntry| {
        e.name.clone()
    });

    // Engine-config sections: same diff_named_items applied four
    // times with `|x| x.name.clone()` as the key extractor.
    let named_predicates = diff_named_items(
        left.engine_config.predicates.clone(),
        right.engine_config.predicates.clone(),
        |p: &NamedPredicate| p.name.clone(),
    );
    let scoring_rules = diff_named_items(
        left.engine_config.scoring_rules.clone(),
        right.engine_config.scoring_rules.clone(),
        |r: &ScoringRule| r.name.clone(),
    );
    let procedures = diff_named_items(
        left.engine_config.procedures.clone(),
        right.engine_config.procedures.clone(),
        |p: &Procedure| p.name.clone(),
    );
    let enforcement_rules = diff_named_items(
        left.engine_config.enforcement_rules.clone(),
        right.engine_config.enforcement_rules.clone(),
        |r: &EnforcementRule| r.name.clone(),
    );

    Ok(ConstitutionDiff {
        diff_schema_version: DIFF_SCHEMA_VERSION.to_string(),
        left_constitution_version: left.constitution_version.clone(),
        right_constitution_version: right.constitution_version.clone(),
        schema_version_change,
        cedar_policies,
        named_predicates,
        scoring_rules,
        procedures,
        enforcement_rules,
        behavioural: None,
    })
}

/// Partition two vectors of items into add / remove / modify by a
/// shared name key.
///
/// Modified detection uses `serde_json::to_value` equality —
/// canonical at the JSON-value level (object field order is
/// preserved by serde_json's default writer for struct
/// serialization, so two items with the same `T` produce the same
/// `serde_json::Value`).
pub(crate) fn diff_named_items<T, K>(left: Vec<T>, right: Vec<T>, key_of: K) -> NamedItemsDiff<T>
where
    T: serde::Serialize + Clone,
    K: Fn(&T) -> String,
{
    use std::collections::BTreeMap;

    let mut left_map: BTreeMap<String, T> = left.into_iter().map(|v| (key_of(&v), v)).collect();
    let mut right_map: BTreeMap<String, T> = right.into_iter().map(|v| (key_of(&v), v)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    // Take ownership of right_map's keys first; for each, either
    // pair with the matching left entry (modified-or-equal check) or
    // declare it "added".
    let right_keys: Vec<String> = right_map.keys().cloned().collect();
    for key in right_keys {
        let right_value = right_map.remove(&key).expect("key just iterated");
        match left_map.remove(&key) {
            None => added.push(right_value),
            Some(left_value) => {
                // Canonical-byte equality via serde_json::to_value.
                // Cheap to fall back on serialize_err → treat as
                // modified (callers see the difference one way or
                // another).
                let same = match (
                    serde_json::to_value(&left_value),
                    serde_json::to_value(&right_value),
                ) {
                    (Ok(l), Ok(r)) => l == r,
                    _ => false,
                };
                if !same {
                    modified.push(NamedItemChange {
                        name: key,
                        left: left_value,
                        right: right_value,
                    });
                }
                // Equal → both sides have it identically; not
                // recorded in any of the three buckets.
            }
        }
    }

    // Everything left in left_map after the right-side walk is
    // "removed".
    for (_key, value) in left_map {
        removed.push(value);
    }

    // Stable output order: each bucket sorted by name.
    added.sort_by_cached_key(|v| serde_json::to_value(v).ok().map(|j| j.to_string()));
    removed.sort_by_cached_key(|v| serde_json::to_value(v).ok().map(|j| j.to_string()));
    modified.sort_by(|a, b| a.name.cmp(&b.name));

    NamedItemsDiff {
        added,
        removed,
        modified,
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_cedar_plus::engine_config::EngineConfig;
    use yutha_core::{Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};

    fn constitution(
        cedar_source: &str,
        engine_config: EngineConfig,
        version: &str,
    ) -> Constitution {
        Constitution {
            constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            schema_version: "1.1.0".into(),
            constitution_version: version.into(),
            parent_version: None,
            swarm_id: SwarmId::new(),
            cedar_source: cedar_source.into(),
            engine_config,
            issued_at: Timestamp::now(),
        }
    }

    #[test]
    fn no_changes_yields_empty_diff() {
        let cedar = r#"permit (principal, action, resource);"#;
        let left = constitution(cedar, EngineConfig::default(), "1.0.0");
        let right = constitution(cedar, EngineConfig::default(), "1.0.0");
        let d = diff_constitutions(&left, &right).expect("ok");
        assert!(d.is_empty_structurally());
        assert!(d.cedar_policies.is_empty());
        assert!(d.behavioural.is_none());
    }

    #[test]
    fn added_cedar_rule_detected_by_id() {
        let left_src = r#"permit (principal, action, resource);"#;
        let right_src = r#"
            @id("no-x")
            forbid (principal, action, resource) when { context.x };

            permit (principal, action, resource);
        "#;
        let left = constitution(left_src, EngineConfig::default(), "1.0.0");
        let right = constitution(right_src, EngineConfig::default(), "1.1.0");
        let d = diff_constitutions(&left, &right).expect("ok");
        assert_eq!(d.cedar_policies.added.len(), 1);
        assert_eq!(d.cedar_policies.added[0].name, "no-x");
        assert_eq!(d.cedar_policies.removed.len(), 0);
    }

    #[test]
    fn schema_version_change_surfaced() {
        let mut left = constitution(
            "permit (principal, action, resource);",
            EngineConfig::default(),
            "1.0.0",
        );
        let mut right = constitution(
            "permit (principal, action, resource);",
            EngineConfig::default(),
            "1.0.0",
        );
        left.schema_version = "1.1.0".into();
        right.schema_version = "1.2.0".into();
        let d = diff_constitutions(&left, &right).expect("ok");
        assert_eq!(
            d.schema_version_change,
            Some(("1.1.0".to_string(), "1.2.0".to_string()))
        );
    }

    #[test]
    fn modified_engine_config_item_detected() {
        let cedar = r#"permit (principal, action, resource);"#;
        let mut left_cfg = EngineConfig::default();
        left_cfg.predicates.push(NamedPredicate {
            name: "is_supervisor".into(),
            expr: "principal.role == \"supervisor\"".into(),
        });
        let mut right_cfg = EngineConfig::default();
        right_cfg.predicates.push(NamedPredicate {
            name: "is_supervisor".into(),
            expr: "principal.role == \"admin\"".into(),
        });
        let left = constitution(cedar, left_cfg, "1.0.0");
        let right = constitution(cedar, right_cfg, "1.0.0");
        let d = diff_constitutions(&left, &right).expect("ok");
        assert_eq!(d.named_predicates.modified.len(), 1);
        assert_eq!(d.named_predicates.modified[0].name, "is_supervisor");
        assert_eq!(d.named_predicates.added.len(), 0);
        assert_eq!(d.named_predicates.removed.len(), 0);
    }
}
