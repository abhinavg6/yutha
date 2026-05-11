//! [`ReplayProtection`] — per-sender replay defense.
//!
//! Maintains a bounded window of recent (nonce, epoch) pairs per sender.
//! Rejects:
//! - Same nonce seen within the recent window.
//! - Epoch significantly older than the last-seen for that sender (per
//!   `max_epoch_skew`).
//! - Expired envelopes (TTL past).

use crate::envelope::Envelope;
use crate::error::{EnvelopeError, TransportError};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use yutha_core::{AgentId, Timestamp};

/// Per-sender replay-prevention state.
///
/// Tracks recent nonces in a bounded ring buffer and the highest epoch seen.
/// Cheap to clone — internal state is `Arc<RwLock<_>>`.
#[derive(Debug, Clone, Default)]
pub struct ReplayProtection {
    inner: Arc<RwLock<Inner>>,
    /// Maximum nonces retained per sender. Older nonces age out.
    window_size: usize,
    /// Maximum allowed epoch skew below the highest-seen.
    max_epoch_skew: u32,
}

#[derive(Debug, Default)]
struct Inner {
    per_sender: HashMap<AgentId, SenderState>,
}

#[derive(Debug, Default)]
struct SenderState {
    /// FIFO of recent nonces; both the queue and the set are maintained.
    nonces_queue: VecDeque<Vec<u8>>,
    nonces_set: HashSet<Vec<u8>>,
    /// Highest epoch seen from this sender.
    max_epoch: u64,
}

impl ReplayProtection {
    /// New replay-protection with default knobs (window 1024, skew 256).
    pub fn new() -> Self {
        Self::with_params(1024, 256)
    }

    /// New replay-protection with custom knobs.
    pub fn with_params(window_size: usize, max_epoch_skew: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            window_size,
            max_epoch_skew,
        }
    }

    /// Check an envelope against replay protection. Returns Ok if accepted
    /// (and records the nonce / updates max_epoch); Err with the rejection
    /// reason otherwise.
    pub async fn admit(&self, envelope: &Envelope, now: &Timestamp) -> Result<(), TransportError> {
        // TTL.
        if envelope.is_expired_at(now) {
            return Err(TransportError::EnvelopeRejected(EnvelopeError::Expired));
        }

        let mut guard = self.inner.write().await;
        let state = guard.per_sender.entry(envelope.from_agent).or_default();

        // Epoch skew.
        if envelope.epoch + (self.max_epoch_skew as u64) < state.max_epoch {
            return Err(TransportError::EnvelopeRejected(
                EnvelopeError::ReplayDetected,
            ));
        }

        // Duplicate nonce.
        if state.nonces_set.contains(&envelope.nonce) {
            return Err(TransportError::EnvelopeRejected(
                EnvelopeError::ReplayDetected,
            ));
        }

        // Record.
        state.nonces_set.insert(envelope.nonce.clone());
        state.nonces_queue.push_back(envelope.nonce.clone());
        while state.nonces_queue.len() > self.window_size {
            if let Some(oldest) = state.nonces_queue.pop_front() {
                state.nonces_set.remove(&oldest);
            }
        }
        if envelope.epoch > state.max_epoch {
            state.max_epoch = envelope.epoch;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;
    use crate::performative::Performative;
    use crate::recipient::Recipient;
    use yutha_core::{CausalRef, SpecVersion, SwarmId};
    use yutha_crypto::sign::generate_keypair;

    fn make_envelope(
        key: &yutha_crypto::SigningKey,
        nonce: Vec<u8>,
        epoch: u64,
        expires_at: Option<Timestamp>,
    ) -> Envelope {
        let mut b = Envelope::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .envelope_id(vec![0u8; 16])
            .from_agent(AgentId::new())
            .recipient(Recipient::Agent(AgentId::new()))
            .performative(Performative::Inform)
            .causal(CausalRef::empty())
            .nonce(nonce)
            .epoch(epoch)
            .sent_at(Timestamp::now());
        if let Some(e) = expires_at {
            b = b.expires_at(e);
        }
        b.sign(key).unwrap()
    }

    #[tokio::test]
    async fn first_envelope_accepted() {
        let rp = ReplayProtection::new();
        let key = generate_keypair();
        let e = make_envelope(&key, vec![1u8; 16], 1, None);
        assert!(rp.admit(&e, &Timestamp::now()).await.is_ok());
    }

    #[tokio::test]
    async fn duplicate_nonce_rejected() {
        let rp = ReplayProtection::new();
        let key = generate_keypair();
        let mut e1 = make_envelope(&key, vec![1u8; 16], 1, None);
        let mut e2 = make_envelope(&key, vec![1u8; 16], 2, None);
        // Pin both to the same sender for the replay check to bite.
        let same_sender = AgentId::new();
        e1.from_agent = same_sender;
        e2.from_agent = same_sender;

        assert!(rp.admit(&e1, &Timestamp::now()).await.is_ok());
        let result = rp.admit(&e2, &Timestamp::now()).await;
        assert!(matches!(
            result,
            Err(TransportError::EnvelopeRejected(
                EnvelopeError::ReplayDetected
            ))
        ));
    }

    #[tokio::test]
    async fn expired_envelope_rejected() {
        let rp = ReplayProtection::new();
        let key = generate_keypair();
        let expired = Timestamp::new("2020-01-01T00:00:00Z".into(), 1).unwrap();
        let e = make_envelope(&key, vec![1u8; 16], 1, Some(expired));
        // "now" with monotonic_ns > 1 makes expired_at <= now true.
        let now = Timestamp::new("2030-01-01T00:00:00Z".into(), 2).unwrap();
        let result = rp.admit(&e, &now).await;
        assert!(matches!(
            result,
            Err(TransportError::EnvelopeRejected(EnvelopeError::Expired))
        ));
    }

    #[tokio::test]
    async fn stale_epoch_rejected() {
        let rp = ReplayProtection::with_params(1024, 5);
        let key = generate_keypair();
        let sender = AgentId::new();

        let mut e_high = make_envelope(&key, vec![1u8; 16], 100, None);
        e_high.from_agent = sender;
        rp.admit(&e_high, &Timestamp::now()).await.unwrap();

        // Now send something more than skew below.
        let mut e_old = make_envelope(&key, vec![2u8; 16], 50, None);
        e_old.from_agent = sender;
        let result = rp.admit(&e_old, &Timestamp::now()).await;
        assert!(matches!(
            result,
            Err(TransportError::EnvelopeRejected(
                EnvelopeError::ReplayDetected
            ))
        ));
    }
}
