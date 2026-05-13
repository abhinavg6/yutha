//! Membership controller for Yutha.
//!
//! Mirrors [`/spec/topology/topology-v1.proto`](../../../spec/topology/topology-v1.proto).
//! Topology + admission policy + sybil-resistance configuration.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod admission;
pub mod error;
pub mod identity;
pub mod memory;
pub mod proto_conv;
pub mod registry;
pub mod sybil;
pub mod topology;

pub use admission::{AdmissionPolicy, ClosedPolicy, HybridPolicy, OpenPolicy};
pub use error::{RegistryError, Result};
pub use identity::ControlPlaneIdentity;
pub use memory::MemoryRegistry;
pub use registry::Registry;
pub use sybil::{
    HardwareAttestationKind, HardwareAttestationRequirement, IdpAttestationRequirement,
    InviteRequirement, ProofOfWorkRequirement, StakeRequirement, SybilResistanceRequirement,
};
pub use topology::{Topology, TopologyMode};
