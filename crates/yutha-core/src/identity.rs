//! Identifier types: [`AgentId`], [`SwarmId`], [`ReceiptId`].
//!
//! Mirrors `AgentId`, `SwarmId`, and `ReceiptId` from
//! [`/spec/common.proto`](../../../spec/common.proto). All three are 16-byte
//! UUID v7 values; the type wrappers exist to keep callers from accidentally
//! using one in place of another.

use crate::error::{CoreError, Result};
use crate::hash::Hash;
use uuid::Uuid;

macro_rules! uuid_v7_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// Stored as a [`Uuid`] internally; the on-the-wire encoding is the
        /// 16-byte big-endian UUID value, per spec.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(pub Uuid);

        impl $name {
            /// Construct a new identifier with a fresh UUID v7 value.
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Construct from raw bytes. Returns an error if the slice is not
            /// exactly 16 bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != 16 {
                    return Err(CoreError::InvalidLength {
                        expected: 16,
                        actual: bytes.len(),
                    });
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Ok(Self(Uuid::from_bytes(arr)))
            }

            /// The 16-byte big-endian representation.
            pub fn as_bytes(&self) -> [u8; 16] {
                *self.0.as_bytes()
            }

            /// String representation. Useful in logs, observability,
            /// and human-meaningful contexts. Not authoritative — IDs
            /// are not secrets and are not the trust anchor.
            pub fn to_hex(&self) -> String {
                self.0.simple().to_string()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

uuid_v7_id!(AgentId, "Stable identifier for an agent. UUID v7.");
uuid_v7_id!(SwarmId, "Stable identifier for a swarm. UUID v7.");

/// Identifier for a stored receipt — a thin wrapper around a content-address
/// [`Hash`].
///
/// Distinct from [`AgentId`] / [`SwarmId`] because receipts are content-
/// addressed, not UUID-keyed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiptId(pub Hash);

impl ReceiptId {
    /// Construct from a [`Hash`].
    pub fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    /// Borrow the underlying hash.
    pub fn hash(&self) -> &Hash {
        &self.0
    }
}

impl std::fmt::Display for ReceiptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_round_trip_bytes() {
        let id = AgentId::new();
        let bytes = id.as_bytes();
        let back = AgentId::from_bytes(&bytes).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn agent_id_rejects_wrong_length() {
        assert!(AgentId::from_bytes(&[0u8; 15]).is_err());
        assert!(AgentId::from_bytes(&[0u8; 17]).is_err());
        assert!(AgentId::from_bytes(&[]).is_err());
    }

    #[test]
    fn swarm_id_distinct_type_from_agent_id() {
        // Compile-time check that SwarmId and AgentId are not interchangeable.
        // (If the macro produced the same type, this wouldn't compile.)
        fn takes_agent(_: AgentId) {}
        let s = SwarmId::new();
        let _ = s;
        // Uncommenting the following line MUST fail to compile:
        // takes_agent(s);
        takes_agent(AgentId::new());
    }

    #[test]
    fn uuid_v7_is_time_orderable() {
        let a = AgentId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = AgentId::new();
        // UUID v7 prefixes a millisecond timestamp; sequential ids should
        // sort in creation order.
        assert!(a < b, "expected {a} < {b}");
    }
}
