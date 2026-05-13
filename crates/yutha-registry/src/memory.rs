//! [`MemoryRegistry`] — in-memory reference [`Registry`].

use crate::admission::{AdmissionPolicy, ClosedPolicy, HybridPolicy, OpenPolicy};
use crate::error::{RegistryError, Result};
use crate::identity::ControlPlaneIdentity;
use crate::registry::Registry;
use crate::sybil;
use crate::topology::Topology;
use async_trait::async_trait;
use std::sync::Arc;
use yutha_core::{AgentId, SpecVersion, Timestamp};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_passport::{Passport, PassportStore, RegistrationOutcome};
use yutha_receipt::{
    AppendOptions, Evidence, PassportResolver, Receipt, ReceiptStore, SignatureRole, SignedBy,
};

/// Reference registry implementation.
///
/// Pairs a [`Topology`] with a `PassportStore`, a `ReceiptStore`, a
/// `PassportResolver`, and a [`ControlPlaneIdentity`]. Successful
/// registration produces an `agent.register` receipt signed by the control
/// plane and appended via the resolver-verified path.
///
/// Precondition: the control plane's own passport MUST be registered in
/// `passports` before the first call to [`Self::register`]. The
/// resolver-verified append flow requires the resolver to find the control
/// plane's public key when verifying the receipt's actor signature. The
/// control-plane binary handles this at startup.
#[derive(Clone)]
pub struct MemoryRegistry {
    topology: Topology,
    passports: Arc<dyn PassportStore>,
    receipts: Arc<dyn ReceiptStore>,
    resolver: Arc<dyn PassportResolver>,
    control_plane: Arc<ControlPlaneIdentity>,
}

impl std::fmt::Debug for MemoryRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryRegistry")
            .field("topology", &self.topology)
            .field("passports", &"<store>")
            .field("receipts", &"<store>")
            .field("resolver", &"<resolver>")
            .field("control_plane", &self.control_plane)
            .finish()
    }
}

impl MemoryRegistry {
    /// Construct a registry. Refuses if the topology is internally
    /// inconsistent (mode / admission policy disagree).
    pub fn new(
        topology: Topology,
        passports: Arc<dyn PassportStore>,
        receipts: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        control_plane: Arc<ControlPlaneIdentity>,
    ) -> Result<Self> {
        if !topology.is_consistent() {
            return Err(RegistryError::TopologyInconsistent);
        }
        Ok(Self {
            topology,
            passports,
            receipts,
            resolver,
            control_plane,
        })
    }

    /// Build a registry-produced receipt of the given action_kind, signed
    /// by the control plane. Used for `agent.register`, `agent.revoke`, and
    /// `agent.rotate_key`. Evidence is passed in by the caller; this helper
    /// handles the framing + signing.
    fn build_signed_receipt(&self, action_kind: &str, evidence: Vec<Evidence>) -> Result<Receipt> {
        let mut iter = evidence.into_iter();
        let first = iter.next().ok_or_else(|| {
            RegistryError::Backend("registry receipts require at least one evidence entry".into())
        })?;

        let mut builder = Receipt::builder()
            .spec_version(
                SpecVersion::parse("1.0.0").map_err(|e| RegistryError::Backend(format!("{e}")))?,
            )
            .swarm_id(self.topology.swarm_id)
            .actor(self.control_plane.agent_id)
            .action_kind(action_kind)
            .constitution_version(self.topology.initial_constitution_version.clone())
            .occurred_at(Timestamp::now())
            .evidence(first);
        for e in iter {
            builder = builder.evidence(e);
        }
        let mut receipt = builder
            .build()
            .map_err(|e| RegistryError::Backend(format!("build receipt: {e}")))?;

        let bytes = receipt
            .canonical_bytes()
            .map_err(yutha_receipt::ReceiptError::from)?;
        let sig = self.control_plane.sign(&bytes);
        receipt
            .signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

        Ok(receipt)
    }

    /// Build the registration receipt.
    fn build_registration_receipt(&self, passport: &Passport) -> Result<Receipt> {
        let passport_hash = content_address(passport).map_err(yutha_receipt::ReceiptError::from)?;
        self.build_signed_receipt(
            "agent.register",
            vec![
                Evidence::new(
                    "passport_agent_id",
                    "type.yutha.dev/v1/AgentId",
                    passport.agent_id.as_bytes().to_vec(),
                ),
                Evidence::new(
                    "passport_hash",
                    "type.yutha.dev/v1/Hash",
                    passport_hash.digest.clone(),
                ),
            ],
        )
    }
}

#[async_trait]
impl Registry for MemoryRegistry {
    async fn register(&self, passport: Passport) -> Result<RegistrationOutcome> {
        // Substrate-layer checks.
        passport.verify_self_signature()?;
        if passport.swarm_id != self.topology.swarm_id {
            return Err(RegistryError::SwarmMismatch {
                expected: self.topology.swarm_id,
                actual: passport.swarm_id,
            });
        }

        // Admission policy.
        match &self.topology.admission {
            AdmissionPolicy::Closed(policy) => check_closed(policy, &passport)?,
            AdmissionPolicy::Open(policy) => check_open(policy, &passport)?,
            AdmissionPolicy::Hybrid(policy) => check_hybrid(policy, &passport)?,
        }

        // Persist the passport BEFORE producing the receipt — the resolver
        // needs to find the agent's key, and (more importantly for this
        // moment) the control plane's key must already be present so the
        // receipt's actor signature verifies on append.
        let mut outcome = self.passports.register(passport.clone()).await?;

        // Build the registration receipt, signed by the control plane.
        let receipt = self.build_registration_receipt(&passport)?;
        let append_out = self
            .receipts
            .append(receipt, AppendOptions::default(), self.resolver.as_ref())
            .await?;

        outcome.registration_receipt = Some(append_out.receipt_id);
        Ok(outcome)
    }

    async fn revoke(&self, agent_id: &AgentId, reason: &str) -> Result<yutha_core::Hash> {
        // Revoke in the passport store first, then record the receipt. If
        // the passport doesn't exist, the revoke errors and no receipt is
        // produced.
        self.passports.revoke(agent_id, reason).await?;

        let receipt = self.build_signed_receipt(
            "agent.revoke",
            vec![
                Evidence::new(
                    "agent_id",
                    "type.yutha.dev/v1/AgentId",
                    agent_id.as_bytes().to_vec(),
                ),
                Evidence::new(
                    "reason",
                    "type.yutha.dev/v1/String",
                    reason.as_bytes().to_vec(),
                ),
            ],
        )?;
        let outcome = self
            .receipts
            .append(receipt, AppendOptions::default(), self.resolver.as_ref())
            .await?;
        Ok(outcome.receipt_id)
    }

    fn topology(&self) -> &Topology {
        &self.topology
    }

    async fn rotate_key(&self, new_passport: Passport) -> Result<RegistrationOutcome> {
        new_passport.verify_self_signature()?;
        if new_passport.swarm_id != self.topology.swarm_id {
            return Err(RegistryError::SwarmMismatch {
                expected: self.topology.swarm_id,
                actual: new_passport.swarm_id,
            });
        }

        // Capture the old public-key fingerprint before mutation — needed
        // for evidence on the rotation receipt. Look up the existing
        // passport via the store.
        let old_fingerprint = match self.passports.lookup(&new_passport.agent_id).await? {
            Some(existing) => {
                yutha_crypto::fingerprint_public_key(&existing.agent_public_key.value)
            }
            None => {
                return Err(RegistryError::Passport(
                    yutha_passport::PassportError::NotFound(new_passport.agent_id),
                ))
            }
        };
        let new_fingerprint =
            yutha_crypto::fingerprint_public_key(&new_passport.agent_public_key.value);

        let mut outcome = self.passports.rotate_key(new_passport.clone()).await?;

        let receipt = self.build_signed_receipt(
            "agent.rotate_key",
            vec![
                Evidence::new(
                    "agent_id",
                    "type.yutha.dev/v1/AgentId",
                    new_passport.agent_id.as_bytes().to_vec(),
                ),
                Evidence::new(
                    "old_key_fingerprint",
                    "type.yutha.dev/v1/Hash",
                    old_fingerprint,
                ),
                Evidence::new(
                    "new_key_fingerprint",
                    "type.yutha.dev/v1/Hash",
                    new_fingerprint,
                ),
            ],
        )?;
        let append_out = self
            .receipts
            .append(receipt, AppendOptions::default(), self.resolver.as_ref())
            .await?;
        outcome.registration_receipt = Some(append_out.receipt_id);
        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------
// Per-policy admission checks
// ---------------------------------------------------------------------------

fn check_closed(policy: &ClosedPolicy, passport: &Passport) -> Result<()> {
    let by_agent_id = policy.allowlisted_agents.contains(&passport.agent_id);
    // Owner-key fingerprint matching: scaffolding-level; production would
    // resolve the owner's key from the passport context.
    let by_owner = !policy.allowlisted_owner_key_fingerprints.is_empty();
    if by_agent_id || by_owner {
        Ok(())
    } else if policy.pending_review_on_unknown {
        Err(RegistryError::AdmissionDenied(
            "pending operator review (scaffolding: not queued)".into(),
        ))
    } else {
        Err(RegistryError::AdmissionDenied(
            "agent not in closed allowlist".into(),
        ))
    }
}

fn check_open(policy: &OpenPolicy, passport: &Passport) -> Result<()> {
    if passport.tier < policy.min_passport_tier {
        return Err(RegistryError::AdmissionDenied(format!(
            "min tier required: {:?}, got {:?}",
            policy.min_passport_tier, passport.tier
        )));
    }
    let _ = policy.max_passport_lifetime_seconds; // scaffolding: lifetime enforcement deferred to real impl
    if passport.expires_at.is_none() {
        return Err(RegistryError::AdmissionDenied(
            "open swarm requires expires_at".into(),
        ));
    }
    sybil::check_all(&policy.requirements, passport)?;
    Ok(())
}

fn check_hybrid(policy: &HybridPolicy, passport: &Passport) -> Result<()> {
    if check_closed(&policy.core, passport).is_ok() {
        return Ok(());
    }
    check_open(&policy.periphery, passport)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::{SpecVersion, SwarmId, Timestamp};
    use yutha_crypto::sign::generate_keypair;
    use yutha_passport::{
        MemoryPassportStore, PassportResolverAdapter, PassportTier, RegistrationStatus,
    };

    /// Build a fully-wired test harness: receipt store, passport store with
    /// the control-plane passport pre-registered, resolver adapter, registry.
    async fn harness(
        mode: crate::TopologyMode,
        admission: AdmissionPolicy,
    ) -> (MemoryRegistry, Arc<dyn ReceiptStore>, SwarmId) {
        let swarm_id = SwarmId::new();
        let topology = Topology {
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            swarm_id,
            mode,
            admission,
            max_capability_lifetime_seconds: 0,
            max_capability_chain_depth: 8,
            default_envelope_ttl_seconds: 300,
            max_epoch_skew: 256,
            external_sends_permitted: false,
            initial_constitution_version: "1.0.0".into(),
            operator_key_fingerprint: vec![0u8; 32],
            operator_signature: None,
        };

        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let receipts: Arc<dyn ReceiptStore> = Arc::new(yutha_receipt::MemoryStore::new());
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

        // Bootstrap control plane: fresh identity, passport registered into
        // the passport store so the resolver can later verify the cp's
        // signature on registration receipts.
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

        let registry =
            MemoryRegistry::new(topology, passports, Arc::clone(&receipts), resolver, cp).unwrap();
        (registry, receipts, swarm_id)
    }

    fn signed_passport_for_swarm(
        swarm_id: SwarmId,
        tier: PassportTier,
        with_expiry: bool,
    ) -> Passport {
        let key = generate_keypair();
        let mut b = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(AgentId::new())
            .swarm_id(swarm_id)
            .agent_public_key(key.public())
            .accepted_constitution_version("1.0.0")
            .tier(tier)
            .issued_at(Timestamp::now());
        if with_expiry {
            b = b.expires_at(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap());
        }
        b.sign(&key).unwrap()
    }

    #[tokio::test]
    async fn closed_admits_listed_agent_and_produces_receipt() {
        let agent_id = AgentId::new();
        let mut admission = ClosedPolicy::default();
        admission.allowlisted_agents.push(agent_id);
        let (registry, receipts, swarm) = harness(
            crate::TopologyMode::Closed,
            AdmissionPolicy::Closed(admission),
        )
        .await;

        let key = generate_keypair();
        let p = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(swarm)
            .agent_public_key(key.public())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&key)
            .unwrap();

        let outcome = registry.register(p).await.unwrap();
        assert!(matches!(outcome.status, RegistrationStatus::Accepted));
        assert!(
            outcome.registration_receipt.is_some(),
            "registration receipt should be produced"
        );

        // Query the receipt store: exactly one agent.register receipt.
        let count = receipts.count().await.unwrap();
        assert_eq!(count, 1);
        let page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "agent.register".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn closed_rejects_unlisted_agent_produces_no_receipt() {
        let (registry, receipts, swarm) = harness(
            crate::TopologyMode::Closed,
            AdmissionPolicy::Closed(ClosedPolicy::default()),
        )
        .await;
        let p = signed_passport_for_swarm(swarm, PassportTier::Minimal, false);
        let result = registry.register(p).await;
        assert!(matches!(result, Err(RegistryError::AdmissionDenied(_))));
        assert_eq!(receipts.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn open_rejects_passport_without_expiry() {
        let (registry, _, swarm) = harness(
            crate::TopologyMode::Open,
            AdmissionPolicy::Open(OpenPolicy::default()),
        )
        .await;
        let p = signed_passport_for_swarm(swarm, PassportTier::Standard, false);
        let result = registry.register(p).await;
        assert!(matches!(result, Err(RegistryError::AdmissionDenied(_))));
    }

    #[tokio::test]
    async fn open_rejects_below_min_tier() {
        let (registry, _, swarm) = harness(
            crate::TopologyMode::Open,
            AdmissionPolicy::Open(OpenPolicy::default()),
        )
        .await;
        let p = signed_passport_for_swarm(swarm, PassportTier::Minimal, true);
        let result = registry.register(p).await;
        assert!(matches!(result, Err(RegistryError::AdmissionDenied(_))));
    }

    #[tokio::test]
    async fn open_admits_well_formed_passport() {
        let (registry, receipts, swarm) = harness(
            crate::TopologyMode::Open,
            AdmissionPolicy::Open(OpenPolicy::default()),
        )
        .await;
        let p = signed_passport_for_swarm(swarm, PassportTier::Standard, true);
        let outcome = registry.register(p).await.unwrap();
        assert!(matches!(outcome.status, RegistrationStatus::Accepted));
        assert_eq!(receipts.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn swarm_mismatch_rejected() {
        let (registry, receipts, _swarm) = harness(
            crate::TopologyMode::Closed,
            AdmissionPolicy::Closed(ClosedPolicy::default()),
        )
        .await;

        let other_swarm = SwarmId::new();
        let p = signed_passport_for_swarm(other_swarm, PassportTier::Minimal, false);
        let result = registry.register(p).await;
        assert!(matches!(result, Err(RegistryError::SwarmMismatch { .. })));
        assert_eq!(receipts.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn revoke_produces_receipt() {
        let agent_id = AgentId::new();
        let mut admission = ClosedPolicy::default();
        admission.allowlisted_agents.push(agent_id);
        let (registry, receipts, swarm) = harness(
            crate::TopologyMode::Closed,
            AdmissionPolicy::Closed(admission),
        )
        .await;

        let key = generate_keypair();
        let p = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(swarm)
            .agent_public_key(key.public())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&key)
            .unwrap();
        registry.register(p).await.unwrap();

        registry.revoke(&agent_id, "test").await.unwrap();

        let page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "agent.revoke".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn rotate_key_produces_receipt() {
        let agent_id = AgentId::new();
        let mut admission = ClosedPolicy::default();
        admission.allowlisted_agents.push(agent_id);
        let (registry, receipts, swarm) = harness(
            crate::TopologyMode::Closed,
            AdmissionPolicy::Closed(admission),
        )
        .await;

        // Initial registration.
        let key1 = generate_keypair();
        let p1 = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(swarm)
            .agent_public_key(key1.public())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&key1)
            .unwrap();
        registry.register(p1).await.unwrap();

        // New passport with rotated key.
        let key2 = generate_keypair();
        let p2 = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(swarm)
            .agent_public_key(key2.public())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&key2)
            .unwrap();
        let outcome = registry.rotate_key(p2).await.unwrap();
        assert!(outcome.registration_receipt.is_some());

        let page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "agent.rotate_key".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn registry_rejects_inconsistent_topology() {
        let topology = Topology {
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            swarm_id: SwarmId::new(),
            mode: crate::TopologyMode::Closed,
            admission: AdmissionPolicy::Open(OpenPolicy::default()),
            max_capability_lifetime_seconds: 0,
            max_capability_chain_depth: 8,
            default_envelope_ttl_seconds: 300,
            max_epoch_skew: 256,
            external_sends_permitted: false,
            initial_constitution_version: "1.0.0".into(),
            operator_key_fingerprint: vec![0u8; 32],
            operator_signature: None,
        };
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let receipts: Arc<dyn ReceiptStore> = Arc::new(yutha_receipt::MemoryStore::new());
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));
        let cp = Arc::new(ControlPlaneIdentity::generate());
        let result = MemoryRegistry::new(topology, passports, receipts, resolver, cp);
        assert!(matches!(result, Err(RegistryError::TopologyInconsistent)));
    }
}
