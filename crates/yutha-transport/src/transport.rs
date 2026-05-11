//! [`Transport`] — the trait every wire backend implements.

use crate::envelope::Envelope;
use crate::error::Result;
use async_trait::async_trait;
use yutha_core::AgentId;

/// Transport: how envelopes get from a sender to a recipient.
///
/// Implementations MUST:
/// - Preserve the envelope bytewise (no field rewriting).
/// - Preserve causal metadata end-to-end.
/// - Run the envelope through [`crate::ReplayProtection`] before delivery.
/// - Surface backpressure rather than silently drop.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send an envelope. May block on backpressure; returns
    /// [`crate::TransportError::Backpressure`] if the receiver queue is
    /// full and `send` is non-blocking.
    async fn send(&self, envelope: Envelope) -> Result<()>;

    /// Receive the next envelope addressed to `recipient`. Blocks until
    /// one is available or the receive timeout fires.
    async fn receive(&self, recipient: &AgentId) -> Result<Envelope>;
}
