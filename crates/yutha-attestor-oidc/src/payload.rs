//! Claim projection from a verified ID-token payload into the
//! [`AttestedIdentity::attributes`] map.
//!
//! Implements [spec §8](../../../../spec/identity-keys/attestor-oidc.md#8-claims--attributes-projection):
//!
//! - String claims project verbatim: `attributes.<key>: <string>`.
//! - Array-of-string claims comma-join into a single string:
//!   `attributes.groups: "admin,auditor"`.
//! - Numeric / boolean / null / object / mixed-array values are
//!   SKIPPED with a `tracing::warn!` log; the verify still succeeds.
//! - Total projection is capped at **64 entries** and **4 KiB** total
//!   bytes of key+value (spec §8.2). Beyond either cap the projection
//!   truncates with a `tracing::warn!` log naming the dropped claims.
//!
//! Non-allowlisted claims (`iss`, `sub`, `aud`, `iat`, `exp`, `nbf`,
//! `nonce`, `azp`, `auth_time`, `acr`, `amr`, `jti`, IdP-extension
//! claims) are NEVER projected — only claims the operator explicitly
//! lists in `OidcConfig::project_claims` (spec §8.3).
//!
//! [`AttestedIdentity::attributes`]: yutha_attestor::AttestedIdentity::attributes

use std::collections::BTreeMap;

use serde_json::Value;
use tracing::warn;

/// Spec §8.2 cap: maximum number of `attributes.<key>` entries the
/// receipt evidence will carry from a single registration.
const PROJECT_MAX_ENTRIES: usize = 64;

/// Spec §8.2 cap: maximum total bytes of `key + value` across the
/// projection. Prevents an unbounded `groups` array from ballooning
/// the per-receipt size.
const PROJECT_MAX_BYTES: usize = 4 * 1024;

/// Project the operator-allowlisted claims from the verified ID-token
/// payload into a `BTreeMap<String, String>` ready for assignment to
/// [`AttestedIdentity::attributes`].
///
/// The `payload` parameter is the full ID-token payload deserialised
/// as `serde_json::Value` by the verify body. `allowlist` is the
/// operator-configured `OidcConfig::project_claims`.
///
/// Returns an empty map if `allowlist` is empty (the common case;
/// operators opt in to projection explicitly).
///
/// [`AttestedIdentity::attributes`]: yutha_attestor::AttestedIdentity::attributes
pub(crate) fn project_allowlisted_claims(
    payload: &Value,
    allowlist: &[String],
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut bytes_used = 0usize;

    for claim_name in allowlist {
        if out.len() >= PROJECT_MAX_ENTRIES {
            warn!(
                claim = %claim_name,
                cap = PROJECT_MAX_ENTRIES,
                "OIDC claim projection: entry-count cap reached; \
                 dropping remaining claims"
            );
            break;
        }

        let Some(raw) = payload.get(claim_name) else {
            // Allowlisted claim isn't present in this particular
            // token. Quietly skip — operators commonly allowlist a
            // claim set that's a superset of any one token's actual
            // claims (e.g., `email` is in some tokens, `groups` in
            // others). Not a warn-worthy condition.
            continue;
        };

        let Some(rendered) = render_claim_value(raw) else {
            warn!(
                claim = %claim_name,
                value_shape = ?value_shape(raw),
                "OIDC claim projection: claim is not string-or-array-of-string; \
                 skipping (spec §8.1)"
            );
            continue;
        };

        let entry_bytes = claim_name.len() + rendered.len();
        if bytes_used + entry_bytes > PROJECT_MAX_BYTES {
            warn!(
                claim = %claim_name,
                cap_bytes = PROJECT_MAX_BYTES,
                used_bytes = bytes_used,
                entry_bytes,
                "OIDC claim projection: byte-cap reached; \
                 dropping this claim and any remaining"
            );
            break;
        }
        bytes_used += entry_bytes;
        out.insert(claim_name.clone(), rendered);
    }

    out
}

/// Render a single JSON value per spec §8.1's rules:
///
/// - String → `Some(string)` verbatim.
/// - Array of strings → `Some("v1,v2,v3")` comma-joined (no
///   whitespace). Empty array → `Some(String::new())`.
/// - Anything else → `None` (caller skips with a warn log).
///
/// Mixed-shape arrays (some strings, some numbers) skip entirely —
/// the spec doesn't define a "best-effort partial render" mode and
/// silently dropping non-string elements would produce a misleading
/// receipt.
fn render_claim_value(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let mut strings: Vec<&str> = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => strings.push(s.as_str()),
                    _ => return None, // mixed array → skip
                }
            }
            Some(strings.join(","))
        }
        _ => None,
    }
}

/// Tag a JSON value's shape for the warning-log when we skip it.
/// Returns a short debug-printable static string so the log line
/// doesn't leak the actual value.
fn value_shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_allowlist_returns_empty_map() {
        let payload = json!({ "groups": ["a", "b"], "email": "x@y.com" });
        let out = project_allowlisted_claims(&payload, &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn string_claim_projects_verbatim() {
        let payload = json!({ "email": "ops@example.com" });
        let out = project_allowlisted_claims(&payload, &["email".to_string()]);
        assert_eq!(out.get("email"), Some(&"ops@example.com".to_string()));
    }

    #[test]
    fn array_claim_comma_joins() {
        let payload = json!({ "groups": ["admin", "auditor", "ops"] });
        let out = project_allowlisted_claims(&payload, &["groups".to_string()]);
        assert_eq!(out.get("groups"), Some(&"admin,auditor,ops".to_string()));
    }

    #[test]
    fn empty_array_projects_as_empty_string() {
        let payload = json!({ "groups": [] });
        let out = project_allowlisted_claims(&payload, &["groups".to_string()]);
        assert_eq!(out.get("groups"), Some(&String::new()));
    }

    #[test]
    fn missing_claim_silently_skipped() {
        let payload = json!({ "email": "x@y.com" });
        let out =
            project_allowlisted_claims(&payload, &["email".to_string(), "groups".to_string()]);
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("email"));
        assert!(!out.contains_key("groups"));
    }

    #[test]
    fn numeric_claim_skipped() {
        let payload = json!({ "age": 30 });
        let out = project_allowlisted_claims(&payload, &["age".to_string()]);
        assert!(out.is_empty());
    }

    #[test]
    fn bool_claim_skipped() {
        let payload = json!({ "email_verified": true });
        let out = project_allowlisted_claims(&payload, &["email_verified".to_string()]);
        assert!(out.is_empty());
    }

    #[test]
    fn null_claim_skipped() {
        let payload = json!({ "department": null });
        let out = project_allowlisted_claims(&payload, &["department".to_string()]);
        assert!(out.is_empty());
    }

    #[test]
    fn object_claim_skipped() {
        let payload = json!({ "profile": { "tier": "gold" } });
        let out = project_allowlisted_claims(&payload, &["profile".to_string()]);
        assert!(out.is_empty());
    }

    #[test]
    fn mixed_array_skipped() {
        let payload = json!({ "tags": ["admin", 42, "ops"] });
        let out = project_allowlisted_claims(&payload, &["tags".to_string()]);
        assert!(out.is_empty());
    }

    #[test]
    fn entry_count_cap_enforced() {
        // Build a payload with 100 string claims and an allowlist
        // that names them all.
        let mut payload = serde_json::Map::new();
        let mut allowlist = Vec::new();
        for i in 0..100 {
            let k = format!("claim_{i:03}");
            payload.insert(k.clone(), Value::String(format!("v{i}")));
            allowlist.push(k);
        }
        let payload = Value::Object(payload);
        let out = project_allowlisted_claims(&payload, &allowlist);
        assert_eq!(out.len(), PROJECT_MAX_ENTRIES);
    }

    #[test]
    fn byte_cap_enforced() {
        // One big string claim exceeds the byte cap by itself.
        let big = "X".repeat(PROJECT_MAX_BYTES + 1);
        let payload = json!({ "huge": big });
        let out = project_allowlisted_claims(&payload, &["huge".to_string()]);
        assert!(out.is_empty(), "single oversize claim must be dropped");
    }

    #[test]
    fn byte_cap_drops_subsequent_claims() {
        // First claim fills most of the budget; second pushes over.
        let big = "X".repeat(PROJECT_MAX_BYTES - 100);
        let payload = json!({
            "first": big,
            "second": "Y".repeat(200),
        });
        let out =
            project_allowlisted_claims(&payload, &["first".to_string(), "second".to_string()]);
        assert!(out.contains_key("first"));
        assert!(!out.contains_key("second"));
    }
}
