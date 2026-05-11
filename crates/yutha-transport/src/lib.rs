//! Typed envelope transport for Yutha. Mirrors
//! [`/spec/envelope/envelope-v1.proto`](../../../spec/envelope/envelope-v1.proto).
//!
//! Untrusted payload bytes are signed-but-opaque; envelope fields
//! (performative, recipient, swarm, causal, nonce, epoch, signature, tags)
//! are typed and authoritative. The split is the structural defense against
//! A3 (prompt injection).

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod envelope;
pub mod error;
pub mod memory;
pub mod performative;
pub mod proto_conv;
pub mod recipient;
pub mod replay;
pub mod transport;

pub use envelope::{Envelope, EnvelopeBuilder};
pub use error::{EnvelopeError, Result, TransportError};
pub use memory::MemoryTransport;
pub use performative::Performative;
pub use recipient::{ExternalEndpoint, Recipient, SwarmBroadcast};
pub use replay::ReplayProtection;
pub use transport::Transport;
