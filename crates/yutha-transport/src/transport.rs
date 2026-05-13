//! [`Transport`] — the trait every wire backend implements.

use crate::envelope::Envelope;
use crate::error::Result;
use async_trait::async_trait;
use futures::stream::BoxStream;
use yutha_core::{AgentId, Hash};

/// A streaming subscription returned by [`Transport::subscribe`]. Yields
/// `(Envelope, deliver_receipt_id)` pairs as envelopes arrive for the
/// subscribed agent, or an error if the subscription terminates abnormally.
pub type EnvelopeStream = BoxStream<'static, Result<(Envelope, Hash)>>;

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
    ///
    /// Returns the content-address of the `envelope.send` receipt produced
    /// by this operation so callers (the gRPC handler in particular) can
    /// echo it back to the sender without re-querying the receipt store.
    async fn send(&self, envelope: Envelope) -> Result<Hash>;

    /// Receive the next envelope addressed to `recipient`. Blocks until
    /// one is available or the receive timeout fires. Single-shot —
    /// callers that want a long-lived stream should use
    /// [`Transport::subscribe`] instead.
    async fn receive(&self, recipient: &AgentId) -> Result<Envelope>;

    /// Open a long-lived subscription for `recipient`. Returns a stream
    /// that yields `(envelope, deliver_receipt_id)` pairs as envelopes
    /// arrive.
    ///
    /// Semantics:
    /// - Cancelling the stream (dropping it) ends the subscription. The
    ///   backend MAY drop in-flight envelopes after cancel; production
    ///   backends typically continue buffering per the topology's
    ///   delivery policy.
    /// - Only one subscription per recipient at a time. Concurrent
    ///   subscriptions for the same agent serialize on the underlying
    ///   inbox lock.
    /// - Every delivery yields an `envelope.deliver` receipt (same
    ///   semantics as [`Transport::receive`]); the stream surfaces its
    ///   content-address alongside the envelope.
    async fn subscribe(&self, recipient: AgentId) -> Result<EnvelopeStream>;
}
