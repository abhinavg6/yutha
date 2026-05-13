//! Macaroon-style attenuable authority tokens. Mirrors
//! [`/spec/capability/capability-v1.proto`](../../../spec/capability/capability-v1.proto).
//!
//! No ambient authority: every action requires an explicit capability check.
//! Default-deny on any ambiguity. The check evaluation walks the
//! attenuation chain (bounded depth), intersects scopes, evaluates caveats,
//! and returns a typed pass/deny outcome.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod capability;
pub mod caveat;
pub mod check;
pub mod error;
pub mod issuer;
pub mod memory;
pub mod proto_conv;
pub mod scope;
pub mod store;

pub use capability::{Capability, CapabilityBuilder};
pub use caveat::{Caveat, RateLimit, TimeOfDay};
pub use check::{ActionDescriptor, CheckOutcome};
pub use error::{CapabilityError, Result};
pub use issuer::{ControlPlaneIssuer, Issuer};
pub use memory::MemoryCapabilityStore;
pub use scope::Scope;
pub use store::{CapabilityStore, CheckEvaluation, IssuanceOutcome};

/// Default maximum attenuation chain depth, per topology defaults.
pub const DEFAULT_MAX_CHAIN_DEPTH: u32 = 8;

/// Default maximum capability lifetime, per topology defaults.
pub const DEFAULT_MAX_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;
