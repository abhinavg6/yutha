//! [`MemoryTransport`] — channel-based in-memory transport for tests and
//! the embedded quickstart.
//!
//! Produces `envelope.send` and `envelope.deliver` receipts as substrate
//! observations. Actor on these receipts is the control plane (the platform
//! recording the observation); the sender / recipient are recorded as
//! evidence. See [`/spec/receipt/canonical-actions.md`](../../../spec/receipt/canonical-actions.md).

use crate::envelope::Envelope;
use crate::error::{Result, TransportError};
use crate::recipient::Recipient;
use crate::replay::ReplayProtection;
use crate::transport::{EnvelopeStream, Transport};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use yutha_core::{AgentId, Hash, SpecVersion, Timestamp};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_passport::ControlPlaneIdentity;
use yutha_receipt::{
    AppendOptions, Evidence, PassportResolver, Receipt, ReceiptStore, SignatureRole, SignedBy,
};

/// In-memory transport with receipt emission.
///
/// Routes by `recipient.Agent(_)` unicast at this scaffolding level; role,
/// swarm, and external recipients return errors until full implementations
/// land. Every successful send produces an `envelope.send` receipt; every
/// successful receive produces an `envelope.deliver` receipt.
#[derive(Clone)]
pub struct MemoryTransport {
    inner: Arc<Inner>,
    replay: ReplayProtection,
    receipts: Arc<dyn ReceiptStore>,
    resolver: Arc<dyn PassportResolver>,
    control_plane: Arc<ControlPlaneIdentity>,
}

struct Inner {
    /// Per-recipient inbox.
    inboxes: RwLock<HashMap<AgentId, Arc<Mutex<mpsc::Receiver<Envelope>>>>>,
    /// Per-recipient sender handle.
    senders: RwLock<HashMap<AgentId, mpsc::Sender<Envelope>>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").finish()
    }
}

impl std::fmt::Debug for MemoryTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTransport")
            .field("control_plane", &self.control_plane)
            .finish()
    }
}

impl MemoryTransport {
    /// Build a new transport wired to a receipt store, resolver, and
    /// control-plane identity. Precondition: the cp's passport is already
    /// registered in the passport store backing `resolver`, so receipts
    /// signed by the cp will verify on append.
    pub fn new(
        receipts: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        control_plane: Arc<ControlPlaneIdentity>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                inboxes: RwLock::new(HashMap::new()),
                senders: RwLock::new(HashMap::new()),
            }),
            replay: ReplayProtection::new(),
            receipts,
            resolver,
            control_plane,
        }
    }

    /// Register a recipient agent so it can receive envelopes.
    pub async fn register_recipient(&self, recipient: AgentId) {
        let (tx, rx) = mpsc::channel::<Envelope>(64);
        let mut senders = self.inner.senders.write().await;
        let mut inboxes = self.inner.inboxes.write().await;
        senders.insert(recipient, tx);
        inboxes.insert(recipient, Arc::new(Mutex::new(rx)));
    }

    /// Construct and append an envelope-related receipt, signed by the cp.
    /// Used internally by send/receive on success. Returns the appended
    /// receipt's content-address so callers can echo it on the wire.
    async fn record(
        &self,
        action_kind: &str,
        envelope: &Envelope,
        extra_evidence: Vec<Evidence>,
    ) -> Result<Hash> {
        let envelope_hash = content_address(envelope)?;
        let mut evidence = vec![
            Evidence::new(
                "envelope_id",
                "type.yutha.dev/v1/Bytes",
                envelope.envelope_id.clone(),
            ),
            Evidence::new(
                "envelope_hash",
                "type.yutha.dev/v1/Hash",
                envelope_hash.digest.clone(),
            ),
            Evidence::new(
                "from_agent",
                "type.yutha.dev/v1/AgentId",
                envelope.from_agent.as_bytes().to_vec(),
            ),
        ];
        evidence.extend(extra_evidence);

        let mut receipt = Receipt::builder()
            .spec_version(
                SpecVersion::parse("1.0.0")
                    .map_err(|e| TransportError::Backend(format!("spec version parse: {e}")))?,
            )
            .swarm_id(envelope.swarm_id)
            .actor(self.control_plane.agent_id)
            .action_kind(action_kind)
            // No constitution context inside transport; this is a substrate
            // observation. The constitution-version is the genesis the
            // envelope's swarm started with, but we don't have a reference
            // to topology here. Use an empty string; this is the documented
            // sentinel for "substrate observation, constitution-agnostic."
            .constitution_version("")
            .occurred_at(Timestamp::now())
            .evidence(evidence.remove(0));

        // Add the remaining evidence one at a time (builder API takes one).
        for e in evidence {
            receipt = receipt.evidence(e);
        }
        let mut receipt = receipt
            .build()
            .map_err(|e| TransportError::Backend(format!("build receipt: {e}")))?;

        let bytes = receipt.canonical_bytes()?;
        let sig = self.control_plane.sign(&bytes);
        receipt
            .signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

        let outcome = self
            .receipts
            .append(receipt, AppendOptions::default(), self.resolver.as_ref())
            .await?;
        Ok(outcome.receipt_id)
    }

    fn recipient_kind(recipient: &Recipient) -> &'static str {
        match recipient {
            Recipient::Agent(_) => "agent",
            Recipient::Role(_) => "role",
            Recipient::Swarm(_) => "swarm",
            Recipient::External(_) => "external",
        }
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    async fn send(&self, envelope: Envelope) -> Result<Hash> {
        // Replay protection (substrate-side; receipts not produced for
        // rejected sends since they didn't happen).
        self.replay.admit(&envelope, &Timestamp::now()).await?;

        let recipient_agent = match &envelope.recipient {
            Recipient::Agent(id) => *id,
            Recipient::Role(_) => {
                return Err(TransportError::Backend(
                    "Role broadcast not implemented in MemoryTransport yet".into(),
                ))
            }
            Recipient::Swarm(_) => {
                return Err(TransportError::Backend(
                    "Swarm broadcast not implemented in MemoryTransport yet".into(),
                ))
            }
            Recipient::External(_) => {
                return Err(TransportError::Backend(
                    "External endpoints not implemented in MemoryTransport".into(),
                ))
            }
        };

        let senders = self.inner.senders.read().await;
        let tx = senders.get(&recipient_agent).cloned().ok_or_else(|| {
            TransportError::Delivery(format!("recipient not registered: {recipient_agent}"))
        })?;
        drop(senders);

        let recipient_kind = Self::recipient_kind(&envelope.recipient);
        let to_evidence = Evidence::new(
            "to_agent",
            "type.yutha.dev/v1/AgentId",
            recipient_agent.as_bytes().to_vec(),
        );
        let kind_evidence = Evidence::new(
            "recipient_kind",
            "type.yutha.dev/v1/String",
            recipient_kind.as_bytes().to_vec(),
        );
        let envelope_for_receipt = envelope.clone();

        tx.try_send(envelope).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TransportError::Backpressure,
            mpsc::error::TrySendError::Closed(_) => {
                TransportError::Delivery("recipient channel closed".into())
            }
        })?;

        // Produce envelope.send receipt now that delivery to the inbox
        // succeeded. Return its content-address so the gRPC handler can
        // echo it on the wire as `SendEnvelopeResponse.send_receipt`.
        let send_receipt_id = self
            .record(
                "envelope.send",
                &envelope_for_receipt,
                vec![to_evidence, kind_evidence],
            )
            .await?;
        Ok(send_receipt_id)
    }

    async fn receive(&self, recipient: &AgentId) -> Result<Envelope> {
        let inboxes = self.inner.inboxes.read().await;
        let rx = inboxes.get(recipient).cloned().ok_or_else(|| {
            TransportError::Delivery(format!("recipient not registered: {recipient}"))
        })?;
        drop(inboxes);

        let mut guard = rx.lock().await;
        let envelope = guard
            .recv()
            .await
            .ok_or_else(|| TransportError::Delivery("inbox closed".into()))?;
        drop(guard);

        let to_evidence = Evidence::new(
            "to_agent",
            "type.yutha.dev/v1/AgentId",
            recipient.as_bytes().to_vec(),
        );
        let _ = self
            .record("envelope.deliver", &envelope, vec![to_evidence])
            .await?;
        Ok(envelope)
    }

    async fn subscribe(&self, recipient: AgentId) -> Result<EnvelopeStream> {
        // Idempotent inbox setup: the gRPC `Subscribe` RPC IS the
        // pre-registration step for receiving, so subscribe creates the
        // inbox if absent. Send still requires the inbox to exist (a
        // sender who tries to deliver before the recipient has
        // subscribed gets `recipient not registered`), which is the
        // correct "deliver only to opt-in subscribers" semantics.
        let already_registered = {
            let inboxes = self.inner.inboxes.read().await;
            inboxes.contains_key(&recipient)
        };
        if !already_registered {
            self.register_recipient(recipient).await;
        }

        let inboxes = self.inner.inboxes.read().await;
        let inbox = inboxes
            .get(&recipient)
            .cloned()
            .expect("inbox was just registered or already present");
        drop(inboxes);

        // Bridge: a forwarder task pulls from the inbox, emits a deliver
        // receipt, and pushes the (envelope, receipt_id) pair into a
        // channel whose receiver we return as the stream.
        //
        // Channel depth 8 — small buffer; the upstream inbox is the real
        // backpressure point.
        let (tx, rx) = mpsc::channel::<Result<(Envelope, Hash)>>(8);
        let transport = self.clone();

        // The forwarder must exit promptly when the subscriber drops
        // the gRPC stream — otherwise it stays parked on
        // `inbox.lock().await` -> `recv().await` *while holding the
        // mutex on the shared inbox*, and the next envelope addressed
        // to this agent gets eaten by the zombie forwarder before any
        // live subscriber can see it. We race the recv against
        // `tx.closed()` so a closed downstream tears the forwarder
        // down before it consumes another envelope.
        tokio::spawn(async move {
            loop {
                let envelope = {
                    let mut guard = inbox.lock().await;
                    tokio::select! {
                        biased;
                        _ = tx.closed() => break,
                        recv = guard.recv() => match recv {
                            Some(e) => e,
                            None => break, // inbox closed
                        },
                    }
                };

                let to_evidence = Evidence::new(
                    "to_agent",
                    "type.yutha.dev/v1/AgentId",
                    recipient.as_bytes().to_vec(),
                );
                let item = match transport
                    .record("envelope.deliver", &envelope, vec![to_evidence])
                    .await
                {
                    Ok(receipt_id) => Ok((envelope, receipt_id)),
                    Err(e) => Err(e),
                };

                if tx.send(item).await.is_err() {
                    // Subscriber dropped the stream between recv and
                    // send. Same root cause; same exit.
                    break;
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::performative::Performative;
    use yutha_core::{CausalRef, SpecVersion, SwarmId};
    use yutha_crypto::sign::generate_keypair;
    use yutha_passport::{
        MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
    };

    /// Build a test harness: receipt store, passport store with cp passport
    /// pre-registered, resolver, transport.
    async fn harness() -> (MemoryTransport, Arc<dyn ReceiptStore>, SwarmId) {
        let swarm_id = SwarmId::new();
        let receipts: Arc<dyn ReceiptStore> = Arc::new(yutha_receipt::MemoryStore::new());
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

        let cp_key = generate_keypair();
        let cp_agent_id = AgentId::new();
        let cp_passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(cp_agent_id)
            .swarm_id(swarm_id)
            .agent_public_key(cp_key.public())
            .owner("control plane")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&cp_key)
            .unwrap();
        passports.register(cp_passport).await.unwrap();
        let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_key));

        let transport = MemoryTransport::new(Arc::clone(&receipts), resolver, cp);
        (transport, receipts, swarm_id)
    }

    use std::sync::atomic::{AtomicU8, Ordering};
    static COUNTER: AtomicU8 = AtomicU8::new(1);
    fn rand_nonce() -> u8 {
        COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    async fn send_round_trip(
        transport: &MemoryTransport,
        swarm_id: SwarmId,
        from: AgentId,
        to: AgentId,
    ) -> Envelope {
        transport.register_recipient(to).await;
        let key = generate_keypair();
        let envelope = Envelope::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(swarm_id)
            .envelope_id(vec![rand_nonce(); 16])
            .from_agent(from)
            .recipient(Recipient::Agent(to))
            .performative(Performative::Inform)
            .payload(b"hello".to_vec())
            .causal(CausalRef::empty())
            .nonce(vec![rand_nonce(); 16])
            .epoch(1)
            .sent_at(Timestamp::now())
            .sign(&key)
            .unwrap();
        transport.send(envelope.clone()).await.unwrap();
        transport.receive(&to).await.unwrap()
    }

    #[tokio::test]
    async fn unicast_round_trip_emits_two_receipts() {
        let (transport, receipts, swarm_id) = harness().await;
        let alice = AgentId::new();
        let bob = AgentId::new();
        let delivered = send_round_trip(&transport, swarm_id, alice, bob).await;
        assert_eq!(delivered.from_agent, alice);

        // One envelope.send + one envelope.deliver.
        let send_page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "envelope.send".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(send_page.receipts.len(), 1);

        let deliver_page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "envelope.deliver".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(deliver_page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn send_to_unregistered_recipient_errors_and_emits_no_receipt() {
        let (transport, receipts, swarm_id) = harness().await;
        let key = generate_keypair();
        let alice = AgentId::new();
        let bob = AgentId::new();
        let envelope = Envelope::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(swarm_id)
            .envelope_id(vec![rand_nonce(); 16])
            .from_agent(alice)
            .recipient(Recipient::Agent(bob))
            .performative(Performative::Inform)
            .causal(CausalRef::empty())
            .nonce(vec![rand_nonce(); 16])
            .epoch(1)
            .sent_at(Timestamp::now())
            .sign(&key)
            .unwrap();
        let result = transport.send(envelope).await;
        assert!(matches!(result, Err(TransportError::Delivery(_))));
        assert_eq!(receipts.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn replay_attempt_rejected_and_emits_no_receipt_on_replay() {
        let (transport, receipts, swarm_id) = harness().await;
        let alice = AgentId::new();
        let bob = AgentId::new();
        transport.register_recipient(bob).await;
        let key = generate_keypair();

        let nonce = vec![rand_nonce(); 16];
        let envelope = Envelope::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(swarm_id)
            .envelope_id(vec![rand_nonce(); 16])
            .from_agent(alice)
            .recipient(Recipient::Agent(bob))
            .performative(Performative::Inform)
            .causal(CausalRef::empty())
            .nonce(nonce)
            .epoch(1)
            .sent_at(Timestamp::now())
            .sign(&key)
            .unwrap();

        transport.send(envelope.clone()).await.unwrap();
        let _ = transport.receive(&bob).await.unwrap();
        let count_after_first = receipts.count().await.unwrap();

        let result = transport.send(envelope).await;
        assert!(matches!(result, Err(TransportError::EnvelopeRejected(_))));
        // No additional receipts produced on rejected replay.
        assert_eq!(receipts.count().await.unwrap(), count_after_first);
    }
}
