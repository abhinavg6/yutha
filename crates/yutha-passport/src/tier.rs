//! [`PassportTier`] — conformance-tier mirror.
//!
//! Mirrors `PassportTier` in
//! [`/spec/passport/passport-v1.proto`](../../../spec/passport/passport-v1.proto).
//! The tier the agent registers at; open swarms typically require STANDARD
//! or higher.

use crate::error::PassportError;

/// Passport tier. Mirrors conformance tiers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PassportTier {
    /// Self-attested only. Default for closed swarms.
    #[default]
    Minimal,
    /// Operator-vetted. Default for open and hybrid swarms.
    Standard,
    /// Cryptographic attestation required. For verifiable-tier backends.
    Verifiable,
}

impl PassportTier {
    /// Parse from the proto wire-tag integer.
    pub fn from_wire(value: i32) -> Result<Self, PassportError> {
        match value {
            1 => Ok(Self::Minimal),
            2 => Ok(Self::Standard),
            3 => Ok(Self::Verifiable),
            other => Err(PassportError::Backend(format!(
                "unknown PassportTier wire value: {other}"
            ))),
        }
    }

    /// Return the proto wire-tag integer.
    pub const fn to_wire(self) -> i32 {
        match self {
            Self::Minimal => 1,
            Self::Standard => 2,
            Self::Verifiable => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trip() {
        for tier in [
            PassportTier::Minimal,
            PassportTier::Standard,
            PassportTier::Verifiable,
        ] {
            assert_eq!(PassportTier::from_wire(tier.to_wire()).unwrap(), tier);
        }
    }

    #[test]
    fn unknown_wire_is_error() {
        assert!(PassportTier::from_wire(0).is_err());
        assert!(PassportTier::from_wire(99).is_err());
    }

    #[test]
    fn tier_ordering_is_minimal_to_verifiable() {
        assert!(PassportTier::Minimal < PassportTier::Standard);
        assert!(PassportTier::Standard < PassportTier::Verifiable);
    }
}
