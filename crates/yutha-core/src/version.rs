//! [`SpecVersion`] — semver string for spec versioning.
//!
//! Mirrors `Version` from
//! [`/spec/common.proto`](../../../spec/common.proto). Per
//! [`/spec/README.md`](../../../spec/README.md) §3, every spec has its own
//! semver-style version that evolves independently.

use crate::error::{CoreError, Result};

/// A spec version. Light wrapper around a semver string.
///
/// Parsing is intentionally permissive at v1.0; comparison is via the parsed
/// (major, minor, patch) tuple. Pre-release and build-metadata extensions are
/// preserved on the wire but not used for ordering.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpecVersion(pub String);

impl SpecVersion {
    /// Parse a version string and validate the major.minor.patch shape.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        let parts: Vec<_> = s.split('.').collect();
        if parts.len() < 3 {
            return Err(CoreError::Version(format!(
                "expected major.minor.patch, got {s}"
            )));
        }
        for p in &parts[..3] {
            // Strip pre-release / build metadata before number parse.
            let num_part = p.split(['-', '+']).next().unwrap_or("");
            num_part
                .parse::<u32>()
                .map_err(|e| CoreError::Version(format!("non-numeric version part `{p}`: {e}")))?;
        }
        Ok(Self(s))
    }

    /// Parse the (major, minor, patch) tuple.
    pub fn major_minor_patch(&self) -> Result<(u32, u32, u32)> {
        let parts: Vec<_> = self.0.split('.').collect();
        let parse_part = |p: &str| -> Result<u32> {
            let num = p.split(['-', '+']).next().unwrap_or("");
            num.parse::<u32>()
                .map_err(|e| CoreError::Version(format!("invalid version component {p}: {e}")))
        };
        Ok((
            parse_part(parts[0])?,
            parse_part(parts.get(1).copied().unwrap_or("0"))?,
            parse_part(parts.get(2).copied().unwrap_or("0"))?,
        ))
    }
}

impl std::fmt::Display for SpecVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_semver() {
        let v = SpecVersion::parse("1.0.0").unwrap();
        assert_eq!(v.major_minor_patch().unwrap(), (1, 0, 0));
    }

    #[test]
    fn parses_pre_release() {
        let v = SpecVersion::parse("1.2.3-alpha.1").unwrap();
        assert_eq!(v.major_minor_patch().unwrap(), (1, 2, 3));
    }

    #[test]
    fn rejects_non_semver_shapes() {
        assert!(SpecVersion::parse("1.0").is_err());
        assert!(SpecVersion::parse("v1.0.0").is_err());
        assert!(SpecVersion::parse("not.a.version").is_err());
    }
}
