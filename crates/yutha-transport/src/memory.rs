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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tracing::debug;
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
    /// Role-membership map. `Role` recipients fan out to every agent
    /// listed here. Operators opt agents in via
    /// [`MemoryTransport::register_role_member`]; the transport
    /// itself imposes no role schema beyond "free-form string."
    roles: RwLock<HashMap<String, HashSet<AgentId>>>,
    /// Per-agent tag set. `Swarm` recipients with non-empty
    /// `filter_tags` fan out only to agents whose tag set is a
    /// SUPERSET of `filter_tags` (i.e. the agent carries every
    /// requested tag). With empty `filter_tags`, the broadcast
    /// fans out to every subscribed agent in the swarm regardless
    /// of tags.
    tags: RwLock<HashMap<AgentId, HashSet<String>>>,
    /// Per-agent "supersede" notify. Calling `subscribe(agent)` fires
    /// `notify_waiters()` to evict any prior subscribe-forwarders for
    /// the same agent. Without this, gRPC-stream teardown can lag
    /// 5+ seconds behind the client's intent, leaving zombie
    /// forwarders that race the new subscriber for the next inbox
    /// item under back-to-back test patterns. We enforce a
    /// one-active-forwarder-per-inbox invariant explicitly.
    subscribe_supersede: RwLock<HashMap<AgentId, Arc<Notify>>>,
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
                roles: RwLock::new(HashMap::new()),
                tags: RwLock::new(HashMap::new()),
                subscribe_supersede: RwLock::new(HashMap::new()),
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

    /// Opt `agent` into membership for `role`. Subsequent
    /// [`Recipient::Role`] sends fan out to every agent currently
    /// registered for that role. Idempotent.
    pub async fn register_role_member(&self, role: impl Into<String>, agent: AgentId) {
        let role = role.into();
        let mut roles = self.inner.roles.write().await;
        roles.entry(role).or_default().insert(agent);
    }

    /// Set `agent`'s tag set. Replaces any prior assignment.
    /// [`Recipient::Swarm`] sends with `filter_tags` deliver to every
    /// agent whose tag set is a superset of the filter (i.e. carries
    /// every requested tag).
    pub async fn set_agent_tags(&self, agent: AgentId, tags: impl IntoIterator<Item = String>) {
        let mut t = self.inner.tags.write().await;
        t.insert(agent, tags.into_iter().collect());
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
        let sig = self
            .control_plane
            .sign(&bytes)
            .await
            .map_err(|e| TransportError::Backend(format!("signer: {e}")))?;
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

    /// Snapshot the members of `role`. Returns the empty vec when the
    /// role has no registered members — broadcasts to empty roles
    /// succeed at the substrate level (the send happened; nothing got
    /// delivered) per the standard broadcast semantics.
    async fn role_members(&self, role: &str) -> Vec<AgentId> {
        let roles = self.inner.roles.read().await;
        roles
            .get(role)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Snapshot the swarm-broadcast targets given a (possibly empty)
    /// `filter_tags`. With empty filter, returns every subscribed
    /// agent. With non-empty filter, returns agents whose tag set is
    /// a superset of the filter (carries every requested tag).
    async fn swarm_targets(&self, filter_tags: &[String]) -> Vec<AgentId> {
        let senders = self.inner.senders.read().await;
        if filter_tags.is_empty() {
            return senders.keys().copied().collect();
        }
        let tags = self.inner.tags.read().await;
        senders
            .keys()
            .filter(|agent| {
                let agent_tags = tags.get(agent);
                let Some(agent_tags) = agent_tags else {
                    return false;
                };
                filter_tags.iter().all(|t| agent_tags.contains(t))
            })
            .copied()
            .collect()
    }

    /// Common fanout body for role/swarm broadcasts. Returns the
    /// number of recipients we successfully delivered to.
    ///
    /// Failure semantics: missing inboxes are silently skipped
    /// (broadcasts tolerate stale role memberships and unsubscribed
    /// agents); `Backpressure` and `Closed` errors are surfaced
    /// because they indicate a real local problem operators care to
    /// see.
    async fn fanout_to(
        &self,
        targets: &[AgentId],
        envelope: Envelope,
        label: &'static str,
    ) -> Result<u64> {
        let senders = self.inner.senders.read().await;
        let mut delivered = 0u64;
        for agent in targets {
            let Some(tx) = senders.get(agent).cloned() else {
                continue; // skip stale role memberships / unsubscribed agents
            };
            tx.try_send(envelope.clone()).map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => TransportError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => TransportError::Delivery(format!(
                    "{label} fanout: recipient {agent} channel closed",
                )),
            })?;
            delivered += 1;
        }
        Ok(delivered)
    }
}

/// Evidence shape for a broadcast `envelope.send` receipt — drops the
/// per-recipient `to_agent` (there's no single recipient) and adds
/// `recipient_value` (the role name or swarm filter) + `fanout_count`.
fn broadcast_evidence(
    recipient_kind: &str,
    recipient_value: &str,
    fanout_count: u64,
) -> Vec<Evidence> {
    vec![
        Evidence::new(
            "recipient_kind",
            "type.yutha.dev/v1/String",
            recipient_kind.as_bytes().to_vec(),
        ),
        Evidence::new(
            "recipient_value",
            "type.yutha.dev/v1/String",
            recipient_value.as_bytes().to_vec(),
        ),
        Evidence::new(
            "fanout_count",
            "type.yutha.dev/v1/Long",
            fanout_count.to_string().into_bytes(),
        ),
    ]
}

#[async_trait]
impl Transport for MemoryTransport {
    async fn send(&self, envelope: Envelope) -> Result<Hash> {
        // Replay protection (substrate-side; receipts not produced for
        // rejected sends since they didn't happen).
        self.replay.admit(&envelope, &Timestamp::now()).await?;

        let recipient_kind = Self::recipient_kind(&envelope.recipient);
        let envelope_for_receipt = envelope.clone();
        // Clone the recipient into an owned value so the match's
        // destructured patterns (`role`, `b.filter_tags`) don't hold
        // a borrow on `envelope`, which the broadcast arms move into
        // `fanout_to`. Recipient is small (4 variants, mostly Strings).
        let recipient = envelope.recipient.clone();

        match recipient {
            // Direct unicast — original path. One known recipient.
            // Delivery failure is an error (caller likely expects the
            // recipient to be subscribed).
            Recipient::Agent(id) => {
                let recipient_agent = id;
                let senders = self.inner.senders.read().await;
                let tx = senders.get(&recipient_agent).cloned().ok_or_else(|| {
                    TransportError::Delivery(format!("recipient not registered: {recipient_agent}"))
                })?;
                drop(senders);
                tx.try_send(envelope).map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => TransportError::Backpressure,
                    mpsc::error::TrySendError::Closed(_) => {
                        TransportError::Delivery("recipient channel closed".into())
                    }
                })?;
                let send_receipt_id = self
                    .record(
                        "envelope.send",
                        &envelope_for_receipt,
                        vec![
                            Evidence::new(
                                "to_agent",
                                "type.yutha.dev/v1/AgentId",
                                recipient_agent.as_bytes().to_vec(),
                            ),
                            Evidence::new(
                                "recipient_kind",
                                "type.yutha.dev/v1/String",
                                recipient_kind.as_bytes().to_vec(),
                            ),
                        ],
                    )
                    .await?;
                Ok(send_receipt_id)
            }

            // Role broadcast — fan out to every agent currently
            // registered as a member of the role.
            Recipient::Role(role) => {
                let targets = self.role_members(&role).await;
                let fanout_count = self.fanout_to(&targets, envelope, "Role").await?;
                self.record(
                    "envelope.send",
                    &envelope_for_receipt,
                    broadcast_evidence(recipient_kind, &role, fanout_count),
                )
                .await
            }

            // Swarm broadcast — fan out to every subscribed agent
            // matching the filter_tags. Empty filter_tags means
            // "every subscribed agent."
            Recipient::Swarm(b) => {
                let scope = if b.filter_tags.is_empty() {
                    "*".to_string()
                } else {
                    b.filter_tags.join(",")
                };
                let targets = self.swarm_targets(&b.filter_tags).await;
                let fanout_count = self.fanout_to(&targets, envelope, "Swarm").await?;
                self.record(
                    "envelope.send",
                    &envelope_for_receipt,
                    broadcast_evidence(recipient_kind, &scope, fanout_count),
                )
                .await
            }

            // External endpoints are network egress — out of scope for
            // an in-memory transport. A real implementation (HTTP/gRPC
            // out-of-band) lives elsewhere.
            Recipient::External(_) => Err(TransportError::Backend(
                "External endpoints not implemented in MemoryTransport".into(),
            )),
        }
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

        // Evict any prior subscribe-forwarders for this agent. The
        // gRPC-aio stream teardown lag on the client side (5+ seconds
        // observed under load) leaves zombie forwarders that compete
        // with this new subscriber for the inbox lock. We enforce a
        // one-active-forwarder-per-inbox invariant explicitly:
        // (1) get-or-create the per-agent supersede Notify;
        // (2) fire `notify_waiters()` BEFORE spawning the new forwarder
        //     — this wakes any existing waiters (old forwarders parked
        //     in their select!) so they exit;
        // (3) the new forwarder, spawned below, registers its own
        //     `.notified()` future AFTER step 2, so it is NOT woken
        //     by the same fire — it'll be woken only when a FUTURE
        //     subscribe arrives.
        let supersede = {
            let mut map = self.inner.subscribe_supersede.write().await;
            map.entry(recipient)
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };
        supersede.notify_waiters();
        debug!(
            target: "yutha::transport::trace",
            recipient = %recipient,
            "MemoryTransport::subscribe: superseded any prior subscribers"
        );

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
        let recipient_for_log = recipient;
        let supersede_for_task = supersede.clone();
        tokio::spawn(async move {
            let mut items: u64 = 0;
            loop {
                let envelope = {
                    let mut guard = inbox.lock().await;
                    tokio::select! {
                        biased;
                        _ = tx.closed() => {
                            debug!(
                                target: "yutha::transport::trace",
                                recipient = %recipient_for_log,
                                items_forwarded = items,
                                "MemoryTransport: inner forwarder exit via tx.closed"
                            );
                            break;
                        }
                        _ = supersede_for_task.notified() => {
                            // A newer subscribe call evicted us. Exit
                            // without consuming the next inbox item so
                            // the new forwarder gets it.
                            debug!(
                                target: "yutha::transport::trace",
                                recipient = %recipient_for_log,
                                items_forwarded = items,
                                "MemoryTransport: inner forwarder exit via supersede"
                            );
                            break;
                        }
                        recv = guard.recv() => match recv {
                            Some(e) => e,
                            None => {
                                debug!(
                                    target: "yutha::transport::trace",
                                    recipient = %recipient_for_log,
                                    items_forwarded = items,
                                    "MemoryTransport: inner forwarder exit via inbox closed"
                                );
                                break;
                            }
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
                    debug!(
                        target: "yutha::transport::trace",
                        recipient = %recipient_for_log,
                        items_forwarded = items,
                        "MemoryTransport: inner forwarder exit via tx.send error (envelope dropped after consume)"
                    );
                    break;
                }
                items += 1;
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
    use yutha_passport::{
        MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
    };
    use yutha_signer::InProcessSigner;

    /// Build a test harness: receipt store, passport store with cp passport
    /// pre-registered, resolver, transport.
    async fn harness() -> (MemoryTransport, Arc<dyn ReceiptStore>, SwarmId) {
        let swarm_id = SwarmId::new();
        let receipts: Arc<dyn ReceiptStore> = Arc::new(yutha_receipt::MemoryStore::new());
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

        // Construct as concrete `InProcessSigner` first so we can use its
        // inherent `public_key()` accessor without `use yutha_signer::Signer;`
        // in scope; then wrap in `Arc<dyn Signer>` for handoff to
        // `ControlPlaneIdentity::new`.
        let cp_signer = InProcessSigner::generate();
        let cp_public_key = cp_signer.public_key();
        let cp_signer: Arc<dyn yutha_signer::Signer> = Arc::new(cp_signer);
        let cp_agent_id = AgentId::new();
        let cp_passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(cp_agent_id)
            .swarm_id(swarm_id)
            .agent_public_key(cp_public_key)
            .owner("control plane")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(cp_signer.as_ref())
            .await
            .unwrap();
        passports.register(cp_passport).await.unwrap();
        let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_signer));

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
        let signer = InProcessSigner::generate();
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
            .sign(&signer)
            .await
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
        let signer = InProcessSigner::generate();
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
            .sign(&signer)
            .await
            .unwrap();
        let result = transport.send(envelope).await;
        assert!(matches!(result, Err(TransportError::Delivery(_))));
        assert_eq!(receipts.count().await.unwrap(), 0);
    }

    async fn broadcast_envelope(
        swarm_id: SwarmId,
        from: AgentId,
        recipient: Recipient,
    ) -> Envelope {
        let signer = InProcessSigner::generate();
        Envelope::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(swarm_id)
            .envelope_id(vec![rand_nonce(); 16])
            .from_agent(from)
            .recipient(recipient)
            .performative(Performative::Inform)
            .payload(b"broadcast".to_vec())
            .causal(CausalRef::empty())
            .nonce(vec![rand_nonce(); 16])
            .epoch(1)
            .sent_at(Timestamp::now())
            .sign(&signer)
            .await
            .unwrap()
    }

    fn fanout_count_from(receipt: &yutha_receipt::Receipt) -> u64 {
        let v = receipt
            .evidence
            .iter()
            .find(|e| e.key == "fanout_count")
            .expect("fanout_count evidence");
        std::str::from_utf8(&v.value)
            .unwrap()
            .parse::<u64>()
            .unwrap()
    }

    #[tokio::test]
    async fn role_broadcast_fans_out_to_all_members() {
        // Two members opt into role "billing"; one agent opts in to a
        // different role. Send to "billing" reaches both members and
        // skips the outsider.
        let (transport, receipts, swarm_id) = harness().await;
        let alice = AgentId::new();
        let bob = AgentId::new();
        let carol = AgentId::new();
        for a in [alice, bob, carol] {
            transport.register_recipient(a).await;
        }
        transport.register_role_member("billing", alice).await;
        transport.register_role_member("billing", bob).await;
        transport.register_role_member("shipping", carol).await;

        let sender = AgentId::new();
        let envelope =
            broadcast_envelope(swarm_id, sender, Recipient::Role("billing".to_string())).await;
        transport.send(envelope).await.unwrap();

        // Both billing members got an envelope; carol's inbox stays empty.
        transport.receive(&alice).await.unwrap();
        transport.receive(&bob).await.unwrap();

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
        assert_eq!(fanout_count_from(&send_page.receipts[0]), 2);

        // Two deliver receipts — one per member who drained their inbox.
        let deliver_page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "envelope.deliver".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(deliver_page.receipts.len(), 2);
    }

    #[tokio::test]
    async fn role_broadcast_with_zero_members_succeeds_with_fanout_zero() {
        // Broadcast semantics: no members = nothing gets delivered,
        // but the send is well-defined. Receipt records fanout_count = 0.
        let (transport, receipts, swarm_id) = harness().await;
        let sender = AgentId::new();
        transport
            .send(broadcast_envelope(swarm_id, sender, Recipient::Role("nobody".to_string())).await)
            .await
            .unwrap();

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
        assert_eq!(fanout_count_from(&send_page.receipts[0]), 0);
    }

    #[tokio::test]
    async fn swarm_broadcast_empty_filter_reaches_all_subscribers() {
        let (transport, _receipts, swarm_id) = harness().await;
        let alice = AgentId::new();
        let bob = AgentId::new();
        for a in [alice, bob] {
            transport.register_recipient(a).await;
        }
        let sender = AgentId::new();
        transport
            .send(
                broadcast_envelope(
                    swarm_id,
                    sender,
                    Recipient::Swarm(crate::SwarmBroadcast {
                        filter_tags: vec![],
                    }),
                )
                .await,
            )
            .await
            .unwrap();
        // Both subscribed agents got it.
        transport.receive(&alice).await.unwrap();
        transport.receive(&bob).await.unwrap();
    }

    #[tokio::test]
    async fn swarm_broadcast_filter_tags_select_only_matching_agents() {
        // Three agents; only the ones tagged with EVERY filter tag
        // receive the envelope.
        let (transport, receipts, swarm_id) = harness().await;
        let alice = AgentId::new();
        let bob = AgentId::new();
        let carol = AgentId::new();
        for a in [alice, bob, carol] {
            transport.register_recipient(a).await;
        }
        transport
            .set_agent_tags(alice, ["finance".to_string(), "pii".to_string()])
            .await;
        transport.set_agent_tags(bob, ["finance".to_string()]).await;
        transport.set_agent_tags(carol, ["pii".to_string()]).await;

        let sender = AgentId::new();
        transport
            .send(
                broadcast_envelope(
                    swarm_id,
                    sender,
                    Recipient::Swarm(crate::SwarmBroadcast {
                        filter_tags: vec!["finance".to_string(), "pii".to_string()],
                    }),
                )
                .await,
            )
            .await
            .unwrap();

        // Only alice carries both tags. Bob and carol are skipped.
        transport.receive(&alice).await.unwrap();

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
        assert_eq!(fanout_count_from(&send_page.receipts[0]), 1);
    }

    #[tokio::test]
    async fn replay_attempt_rejected_and_emits_no_receipt_on_replay() {
        let (transport, receipts, swarm_id) = harness().await;
        let alice = AgentId::new();
        let bob = AgentId::new();
        transport.register_recipient(bob).await;
        let signer = InProcessSigner::generate();

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
            .sign(&signer)
            .await
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
