//! [`MemoryCapabilityStore`] — in-memory reference [`CapabilityStore`].
//!
//! Every successful or denied `check` produces a `capability.check.pass` or
//! `capability.check.deny` receipt as a substrate observation, signed by the
//! control plane. See [`/spec/receipt/canonical-actions.md`](../../../spec/receipt/canonical-actions.md).

use crate::capability::Capability;
use crate::check::{ActionDescriptor, CheckOutcome};
use crate::error::{CapabilityError, Result};
use crate::scope::Scope;
use crate::store::CapabilityStore;
use crate::DEFAULT_MAX_CHAIN_DEPTH;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use yutha_core::{Hash, SpecVersion, Timestamp};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_passport::ControlPlaneIdentity;
use yutha_receipt::{
    AppendOptions, Evidence, PassportResolver, Receipt, ReceiptStore, SignatureRole, SignedBy,
};

/// In-memory capability store with bounded-depth chain walks and
/// receipt-emitting checks.
#[derive(Clone)]
pub struct MemoryCapabilityStore {
    inner: Arc<RwLock<Inner>>,
    max_depth: u32,
    receipts: Arc<dyn ReceiptStore>,
    resolver: Arc<dyn PassportResolver>,
    control_plane: Arc<ControlPlaneIdentity>,
}

impl std::fmt::Debug for MemoryCapabilityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCapabilityStore")
            .field("max_depth", &self.max_depth)
            .field("control_plane", &self.control_plane)
            .finish()
    }
}

#[derive(Debug, Default)]
struct Inner {
    /// content-address → capability
    by_id: HashMap<Hash, Capability>,
    /// content-address → revocation reason
    revoked: HashMap<Hash, String>,
}

impl MemoryCapabilityStore {
    /// New store with default max chain depth and receipt emission.
    pub fn new(
        receipts: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        control_plane: Arc<ControlPlaneIdentity>,
    ) -> Self {
        Self::with_max_depth(DEFAULT_MAX_CHAIN_DEPTH, receipts, resolver, control_plane)
    }

    /// New store with a custom max chain depth.
    pub fn with_max_depth(
        max_depth: u32,
        receipts: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        control_plane: Arc<ControlPlaneIdentity>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            max_depth,
            receipts,
            resolver,
            control_plane,
        }
    }

    /// Build and append a capability.check.* receipt for the outcome.
    async fn record_check(
        &self,
        outcome: &CheckOutcome,
        descriptor: &ActionDescriptor,
        swarm_id: yutha_core::SwarmId,
    ) -> Result<()> {
        let action_kind = if outcome.permitted {
            "capability.check.pass"
        } else {
            "capability.check.deny"
        };

        let mut evidence = vec![Evidence::new(
            "action_kind_checked",
            "type.yutha.dev/v1/String",
            descriptor.action_kind.as_bytes().to_vec(),
        )];
        if let Some(cap_id) = &outcome.capability {
            evidence.push(Evidence::new(
                "capability_hash",
                "type.yutha.dev/v1/Hash",
                cap_id.digest.clone(),
            ));
        }
        if !outcome.permitted {
            evidence.push(Evidence::new(
                "deny_reason",
                "type.yutha.dev/v1/String",
                outcome.deny_reason.as_bytes().to_vec(),
            ));
            for caveat in &outcome.unmet_caveats {
                evidence.push(Evidence::new(
                    "unmet_caveat",
                    "type.yutha.dev/v1/String",
                    caveat.as_bytes().to_vec(),
                ));
            }
        }

        let mut receipt = Receipt::builder()
            .spec_version(
                SpecVersion::parse("1.0.0")
                    .map_err(|e| CapabilityError::Backend(format!("spec version: {e}")))?,
            )
            .swarm_id(swarm_id)
            .actor(self.control_plane.agent_id)
            .action_kind(action_kind)
            .constitution_version("")
            .occurred_at(Timestamp::now())
            .evidence(evidence.remove(0));
        for e in evidence {
            receipt = receipt.evidence(e);
        }
        let mut receipt = receipt
            .build()
            .map_err(|e| CapabilityError::Backend(format!("build receipt: {e}")))?;

        let bytes = receipt.canonical_bytes().map_err(CapabilityError::Crypto)?;
        let sig = self.control_plane.sign(&bytes);
        receipt
            .signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

        self.receipts
            .append(receipt, AppendOptions::default(), self.resolver.as_ref())
            .await
            .map_err(|e| CapabilityError::Backend(format!("append: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl CapabilityStore for MemoryCapabilityStore {
    async fn issue(&self, capability: Capability) -> Result<Hash> {
        let id = content_address(&capability).map_err(CapabilityError::Crypto)?;
        let mut guard = self.inner.write().await;
        guard.by_id.insert(id.clone(), capability);
        Ok(id)
    }

    async fn attenuate(&self, child: Capability) -> Result<Hash> {
        let parent_hash = child
            .parent
            .clone()
            .ok_or(CapabilityError::MissingField("parent"))?;

        let guard = self.inner.read().await;
        let parent = guard
            .by_id
            .get(&parent_hash)
            .ok_or_else(|| CapabilityError::ParentNotFound(parent_hash.clone()))?
            .clone();
        drop(guard);

        let intersected = parent.scope.intersect(&child.scope);
        if intersected != child.scope {
            return Err(CapabilityError::AttenuationBroadens {
                detail: "child scope is not a subset of parent's".into(),
            });
        }

        let id = content_address(&child).map_err(CapabilityError::Crypto)?;
        let mut guard = self.inner.write().await;
        guard.by_id.insert(id.clone(), child);
        Ok(id)
    }

    async fn revoke(&self, capability_id: &Hash, reason: &str) -> Result<()> {
        let mut guard = self.inner.write().await;
        if !guard.by_id.contains_key(capability_id) {
            return Err(CapabilityError::Backend(format!(
                "capability not found: {capability_id}"
            )));
        }
        guard
            .revoked
            .insert(capability_id.clone(), reason.to_string());
        Ok(())
    }

    async fn lookup(&self, capability_id: &Hash) -> Result<Option<Capability>> {
        let guard = self.inner.read().await;
        if guard.revoked.contains_key(capability_id) {
            return Ok(None);
        }
        Ok(guard.by_id.get(capability_id).cloned())
    }

    async fn check(
        &self,
        capability_id: &Hash,
        descriptor: &ActionDescriptor,
    ) -> Result<CheckOutcome> {
        let outcome_and_swarm = self.check_inner(capability_id, descriptor).await?;
        self.record_check(&outcome_and_swarm.0, descriptor, outcome_and_swarm.1)
            .await?;
        Ok(outcome_and_swarm.0)
    }
}

impl MemoryCapabilityStore {
    /// Inner check logic. Returns `(CheckOutcome, swarm_id)` so the receipt
    /// emitter can record on the right swarm. swarm_id is taken from the
    /// leaf capability (every capability has one; chain links are all in
    /// the same swarm).
    async fn check_inner(
        &self,
        capability_id: &Hash,
        descriptor: &ActionDescriptor,
    ) -> Result<(CheckOutcome, yutha_core::SwarmId)> {
        let guard = self.inner.read().await;
        let now = Timestamp::now();

        // Walk the chain. Same algorithm as before.
        let mut chain: Vec<Capability> = Vec::new();
        let mut cursor = Some(capability_id.clone());
        let mut depth: u32 = 0;
        while let Some(id) = cursor {
            depth += 1;
            if depth > self.max_depth {
                return Err(CapabilityError::ChainTooDeep {
                    actual: depth,
                    max: self.max_depth,
                });
            }
            if guard.revoked.contains_key(&id) {
                let leaf_swarm = chain.first().map(|c| c.swarm_id).unwrap_or_else(|| {
                    // No links walked yet — capability_id is the leaf and
                    // revoked. Look it up regardless to get swarm_id.
                    guard.by_id.get(&id).map(|c| c.swarm_id).unwrap_or_default()
                });
                return Ok((
                    CheckOutcome::deny(
                        Some(capability_id.clone()),
                        "capability revoked in chain",
                        vec![],
                    ),
                    leaf_swarm,
                ));
            }
            let cap = guard
                .by_id
                .get(&id)
                .cloned()
                .ok_or_else(|| CapabilityError::Backend(format!("missing chain link: {id}")))?;
            if !cap.is_within_window(&now) {
                let leaf_swarm = chain.first().map(|c| c.swarm_id).unwrap_or(cap.swarm_id);
                return Ok((
                    CheckOutcome::deny(
                        Some(capability_id.clone()),
                        "capability outside validity window",
                        vec![],
                    ),
                    leaf_swarm,
                ));
            }
            cursor = cap.parent.clone();
            chain.push(cap);
        }

        let swarm_id = chain.first().map(|c| c.swarm_id).unwrap_or_default();

        chain.reverse();
        let mut effective_scope = Scope::empty();
        let mut first = true;
        for cap in &chain {
            if first {
                effective_scope = cap.scope.clone();
                first = false;
            } else {
                effective_scope = effective_scope.intersect(&cap.scope);
            }
        }

        if !effective_scope.permits(descriptor) {
            return Ok((
                CheckOutcome::deny(
                    Some(capability_id.clone()),
                    "effective scope (after chain intersection) does not permit action",
                    vec![],
                ),
                swarm_id,
            ));
        }

        let mut matched = Vec::new();
        let mut unmet = Vec::new();
        for cap in &chain {
            for caveat in &cap.caveats {
                let label = caveat_label(caveat);
                if caveat.permits(descriptor) {
                    matched.push(label);
                } else {
                    unmet.push(label);
                }
            }
        }
        if !unmet.is_empty() {
            return Ok((
                CheckOutcome::deny(
                    Some(capability_id.clone()),
                    "caveat(s) in chain not met",
                    unmet,
                ),
                swarm_id,
            ));
        }

        Ok((
            CheckOutcome::permit(Some(capability_id.clone()), matched),
            swarm_id,
        ))
    }
}

fn caveat_label(c: &crate::caveat::Caveat) -> String {
    use crate::caveat::Caveat::*;
    match c {
        TimeOfDay(_) => "time_of_day".into(),
        ConstitutionVersion { .. } => "constitution_version".into(),
        SupervisorRequired { .. } => "supervisor_required".into(),
        RateLimit(_) => "rate_limit".into(),
        OnlyIfTagged { .. } => "only_if_tagged".into(),
        NeverIfTagged { .. } => "never_if_tagged".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::issuer::Issuer;
    use crate::scope::Scope;
    use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
    use yutha_crypto::sign::generate_keypair;
    use yutha_passport::{
        MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
    };

    async fn harness() -> (MemoryCapabilityStore, Arc<dyn ReceiptStore>, SwarmId) {
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
            .owner("cp")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&cp_key)
            .unwrap();
        passports.register(cp_passport).await.unwrap();
        let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_key));

        let store = MemoryCapabilityStore::new(Arc::clone(&receipts), resolver, cp);
        (store, receipts, swarm_id)
    }

    fn far_future() -> Timestamp {
        Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap()
    }

    fn root_cap(scope: Scope, swarm_id: SwarmId) -> Capability {
        let key = generate_keypair();
        Capability::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .capability_id(vec![1u8; 16])
            .swarm_id(swarm_id)
            .issuer(Issuer::Operator(vec![0u8; 32]))
            .subject(AgentId::new())
            .scope(scope)
            .valid_from(Timestamp::now())
            .valid_until(far_future())
            .sign(&key)
            .unwrap()
    }

    #[tokio::test]
    async fn issue_then_check_pass_emits_receipt() {
        let (store, receipts, swarm) = harness().await;
        let cap = root_cap(Scope::for_action("send_message"), swarm);
        let id = store.issue(cap).await.unwrap();
        let outcome = store
            .check(
                &id,
                &ActionDescriptor {
                    action_kind: "send_message".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(outcome.permitted);

        let page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "capability.check.pass".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn deny_emits_check_deny_receipt() {
        let (store, receipts, swarm) = harness().await;
        let cap = root_cap(Scope::for_action("send_message"), swarm);
        let id = store.issue(cap).await.unwrap();
        let outcome = store
            .check(
                &id,
                &ActionDescriptor {
                    action_kind: "exfiltrate".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!outcome.permitted);

        let page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "capability.check.deny".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.receipts.len(), 1);
    }
}
