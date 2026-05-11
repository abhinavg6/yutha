//! Agent identity for Yutha — the [`Passport`] and [`PassportStore`].
//!
//! Mirrors [`/spec/passport/passport-v1.proto`](../../../spec/passport/passport-v1.proto).
//! The Passport is what an agent presents to a registry to join a swarm.
//! Authority comes from cryptographic signature, not from declarations in
//! the passport — see the capability spec for the actual authority layer.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod control_plane;
pub mod declarations;
pub mod error;
pub mod memory;
pub mod passport;
pub mod proto_conv;
pub mod registration;
pub mod resolver;
pub mod store;
pub mod tier;

pub use control_plane::ControlPlaneIdentity;
pub use declarations::{CapabilityDeclaration, ResourceDeclaration};
pub use error::{PassportError, Result};
pub use memory::MemoryPassportStore;
pub use passport::{Passport, PassportBuilder};
pub use registration::{RegistrationOutcome, RegistrationStatus};
pub use resolver::PassportResolverAdapter;
pub use store::PassportStore;
pub use tier::PassportTier;
