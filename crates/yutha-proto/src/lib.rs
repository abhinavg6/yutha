//! Prost-generated Rust types from the Yutha protobuf specs.
//!
//! This crate is the single source of truth for the on-the-wire encoding
//! of every Yutha artifact. Consumers (`yutha-receipt`, `yutha-passport`,
//! `yutha-envelope`, `yutha-capability`, `yutha-topology`) import the
//! generated types and convert between their ergonomic Rust shapes and the
//! protobuf representation for content-addressing and signing.
//!
//! The generated modules mirror the proto packages: a `yutha.common.v1`
//! package becomes `yutha_proto::common::v1::*`.

#![forbid(unsafe_code)]
// Generated code; suppress style lints that the protobuf compiler can't
// satisfy by construction.
#![allow(missing_docs)]
#![allow(clippy::all)]

/// `yutha.common.v1` — shared types (Hash, Signature, Timestamp, etc.).
pub mod common {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/yutha.common.v1.rs"));
    }
}

/// `yutha.passport.v1` — Passport, CapabilityDeclaration, ResourceDeclaration.
pub mod passport {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/yutha.passport.v1.rs"));
    }
}

/// `yutha.envelope.v1` — Envelope, Performative, Recipient.
pub mod envelope {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/yutha.envelope.v1.rs"));
    }
}

/// `yutha.receipt.v1` — Receipt, Evidence, SignedBy, SealStatus.
pub mod receipt {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/yutha.receipt.v1.rs"));
    }
}

/// `yutha.capability.v1` — Capability, Scope, Caveat, Issuer.
pub mod capability {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/yutha.capability.v1.rs"));
    }
}

/// `yutha.topology.v1` — Topology, AdmissionPolicy, sybil-resistance types.
pub mod topology {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/yutha.topology.v1.rs"));
    }
}

/// Re-export `prost::Message` so consumers don't need a separate `prost`
/// dependency just to call `.encode_to_vec()` on generated types.
pub use prost::Message;
