//! [`MemoryCapabilityStore`] — in-memory reference [`CapabilityStore`].
//!
//! Every successful or denied `check` produces a `capability.check.pass` or
//! `capability.check.deny` receipt as a substrate observation, signed by the
//! control plane. See [`/spec/receipt/canonical-actions.md`](../../../spec/receipt/canonical-actions.md).

use crate::capability::Capability;
use crate::check::{ActionDescriptor, CheckOutcome};
use crate::error::{CapabilityError, Result};
use crate::quarantine::QuarantineSource;
use crate::scope::Scope;
use crate::store::{CapabilityStore, CheckEvaluation, IssuanceOutcome};
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
    /// Quarantine state consulted on every check / issue / attenuate
    /// per RFC 0013 §4.2. Backed by the constitution layer's
    /// `EnforcementEngine` in production; by [`crate::AlwaysAllowed`]
    /// in tests and demos.
    quarantine: Arc<dyn QuarantineSource>,
}

impl std::fmt::Debug for MemoryCapabilityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCapabilityStore")
            .field("max_depth", &self.max_depth)
            .field("control_plane", &self.control_plane)
            .field("quarantine", &self.quarantine)
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
    ///
    /// `quarantine` is consulted on every `check`, `issue`, and
    /// `attenuate` call to enforce RFC 0013 §4.2 ("the cap layer
    /// denies quarantined agents"). Pass [`crate::AlwaysAllowed`]
    /// when the constitution layer isn't wired in (tests, demos);
    /// pass an adapter backed by `EnforcementEngine` in production.
    pub fn new(
        receipts: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        control_plane: Arc<ControlPlaneIdentity>,
        quarantine: Arc<dyn QuarantineSource>,
    ) -> Self {
        Self::with_max_depth(
            DEFAULT_MAX_CHAIN_DEPTH,
            receipts,
            resolver,
            control_plane,
            quarantine,
        )
    }

    /// New store with a custom max chain depth.
    pub fn with_max_depth(
        max_depth: u32,
        receipts: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        control_plane: Arc<ControlPlaneIdentity>,
        quarantine: Arc<dyn QuarantineSource>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            max_depth,
            receipts,
            resolver,
            control_plane,
            quarantine,
        }
    }

    /// Build and append a capability.* receipt signed by the control
    /// plane. Returns the receipt's content-address.
    ///
    /// Used by [`Self::record_check`] (capability.check.{pass,deny}),
    /// [`Self::record_issue`] (capability.issue),
    /// [`Self::record_attenuate`] (capability.attenuate), and
    /// [`Self::record_revoke`] (capability.revoke). Centralizes the
    /// boilerplate so each event-kind just supplies action_kind + the
    /// event-specific evidence.
    async fn record_event(
        &self,
        action_kind: &str,
        swarm_id: yutha_core::SwarmId,
        evidence: Vec<Evidence>,
    ) -> Result<Hash> {
        let mut iter = evidence.into_iter();
        let first = iter.next().ok_or_else(|| {
            CapabilityError::Backend(
                "capability receipts require at least one evidence entry".into(),
            )
        })?;

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
            .evidence(first);
        for e in iter {
            receipt = receipt.evidence(e);
        }
        let mut receipt = receipt
            .build()
            .map_err(|e| CapabilityError::Backend(format!("build receipt: {e}")))?;

        let bytes = receipt.canonical_bytes().map_err(CapabilityError::Crypto)?;
        let sig = self
            .control_plane
            .sign(&bytes)
            .await
            .map_err(|e| CapabilityError::Signer(e.to_string()))?;
        receipt
            .signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

        let outcome = self
            .receipts
            .append(receipt, AppendOptions::default(), self.resolver.as_ref())
            .await
            .map_err(|e| CapabilityError::Backend(format!("append: {e}")))?;
        Ok(outcome.receipt_id)
    }

    /// Build and append a `capability.check.{pass,deny}` receipt for the
    /// outcome. Returns the receipt's content-address so the caller can
    /// thread it back up through [`CheckEvaluation`].
    async fn record_check(
        &self,
        outcome: &CheckOutcome,
        descriptor: &ActionDescriptor,
        swarm_id: yutha_core::SwarmId,
    ) -> Result<Hash> {
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

        self.record_event(action_kind, swarm_id, evidence).await
    }

    async fn record_issue(&self, cap_id: &Hash, capability: &Capability) -> Result<Hash> {
        self.record_event(
            "capability.issue",
            capability.swarm_id,
            vec![
                Evidence::new(
                    "capability_hash",
                    "type.yutha.dev/v1/Hash",
                    cap_id.digest.clone(),
                ),
                Evidence::new(
                    "subject",
                    "type.yutha.dev/v1/AgentId",
                    capability.subject.as_bytes().to_vec(),
                ),
            ],
        )
        .await
    }

    async fn record_attenuate(
        &self,
        child_id: &Hash,
        parent_id: &Hash,
        child: &Capability,
    ) -> Result<Hash> {
        self.record_event(
            "capability.attenuate",
            child.swarm_id,
            vec![
                Evidence::new(
                    "child_capability_hash",
                    "type.yutha.dev/v1/Hash",
                    child_id.digest.clone(),
                ),
                Evidence::new(
                    "parent_capability_hash",
                    "type.yutha.dev/v1/Hash",
                    parent_id.digest.clone(),
                ),
                Evidence::new(
                    "subject",
                    "type.yutha.dev/v1/AgentId",
                    child.subject.as_bytes().to_vec(),
                ),
            ],
        )
        .await
    }

    async fn record_revoke(
        &self,
        cap_id: &Hash,
        swarm_id: yutha_core::SwarmId,
        reason: &str,
    ) -> Result<Hash> {
        self.record_event(
            "capability.revoke",
            swarm_id,
            vec![
                Evidence::new(
                    "capability_hash",
                    "type.yutha.dev/v1/Hash",
                    cap_id.digest.clone(),
                ),
                Evidence::new(
                    "reason",
                    "type.yutha.dev/v1/String",
                    reason.as_bytes().to_vec(),
                ),
            ],
        )
        .await
    }
}

#[async_trait]
impl CapabilityStore for MemoryCapabilityStore {
    async fn issue(&self, capability: Capability) -> Result<IssuanceOutcome> {
        // RFC 0013 §4.2: refuse to mint a fresh cap to a quarantined
        // subject. Errors out (vs the check-path's "deny via receipt")
        // because there's no `capability.issue.deny` action-kind in
        // canonical-actions.md — issuance refusal is an exceptional
        // condition, not a substrate observation.
        if self
            .quarantine
            .is_agent_quarantined(&capability.subject)
            .await
        {
            return Err(CapabilityError::SubjectQuarantined(capability.subject));
        }

        let capability_id = content_address(&capability).map_err(CapabilityError::Crypto)?;
        // Persist first so the resolver / lookup path is consistent before
        // the receipt lands. Mirrors `MemoryRegistry::register` ordering.
        {
            let mut guard = self.inner.write().await;
            guard
                .by_id
                .insert(capability_id.clone(), capability.clone());
        }
        let issuance_receipt = self.record_issue(&capability_id, &capability).await?;
        Ok(IssuanceOutcome {
            capability_id,
            issuance_receipt,
        })
    }

    async fn attenuate(&self, child: Capability) -> Result<IssuanceOutcome> {
        // Same quarantine gate as `issue` — attenuation hands a fresh
        // (narrower) cap to a subject. If they're quarantined, deny.
        if self.quarantine.is_agent_quarantined(&child.subject).await {
            return Err(CapabilityError::SubjectQuarantined(child.subject));
        }

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

        let capability_id = content_address(&child).map_err(CapabilityError::Crypto)?;
        {
            let mut guard = self.inner.write().await;
            guard.by_id.insert(capability_id.clone(), child.clone());
        }
        let issuance_receipt = self
            .record_attenuate(&capability_id, &parent_hash, &child)
            .await?;
        Ok(IssuanceOutcome {
            capability_id,
            issuance_receipt,
        })
    }

    async fn revoke(&self, capability_id: &Hash, reason: &str) -> Result<Hash> {
        // Pull swarm_id from the existing capability before mutating; the
        // revocation receipt is recorded against that swarm so observability
        // for a multi-swarm CP is coherent.
        let swarm_id = {
            let guard = self.inner.read().await;
            guard
                .by_id
                .get(capability_id)
                .ok_or_else(|| {
                    CapabilityError::Backend(format!("capability not found: {capability_id}"))
                })?
                .swarm_id
        };

        {
            let mut guard = self.inner.write().await;
            guard
                .revoked
                .insert(capability_id.clone(), reason.to_string());
        }

        self.record_revoke(capability_id, swarm_id, reason).await
    }

    async fn lookup(&self, capability_id: &Hash) -> Result<Option<Capability>> {
        let guard = self.inner.read().await;
        if guard.revoked.contains_key(capability_id) {
            return Ok(None);
        }
        Ok(guard.by_id.get(capability_id).cloned())
    }

    async fn list_for_subject(&self, agent_id: &yutha_core::AgentId) -> Result<Vec<Hash>> {
        let guard = self.inner.read().await;
        // Linear scan over the in-memory cap table; fine for Phase-1
        // memory backend. A Postgres impl would replace this with a
        // `WHERE subject = $1 AND revoked_at IS NULL` query against an
        // indexed column. Skips already-revoked caps so the cascade
        // doesn't re-revoke (idempotent + audit-clean).
        let mut out = Vec::new();
        for (id, cap) in &guard.by_id {
            if &cap.subject == agent_id && !guard.revoked.contains_key(id) {
                out.push(id.clone());
            }
        }
        Ok(out)
    }

    async fn check(
        &self,
        capability_id: &Hash,
        descriptor: &ActionDescriptor,
    ) -> Result<CheckEvaluation> {
        let (outcome, swarm_id) = self.check_inner(capability_id, descriptor).await?;
        let check_receipt = self.record_check(&outcome, descriptor, swarm_id).await?;
        Ok(CheckEvaluation {
            outcome,
            check_receipt,
        })
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
        // RFC 0013 §4.2: quarantine fires *before* scope/caveat eval
        // so a quarantined agent can't squeeze a permitted action
        // through on the merits — the cap layer denies categorically.
        // The leaf cap carries the subject (chains don't change it
        // for v1; if attenuation ever re-delegates to a different
        // subject in v2, the consultation still uses the leaf's
        // subject because that's whoever is actually presenting the
        // token at check time).
        //
        // The lookup is intentionally lenient: an unknown leaf id
        // falls through to the chain walk below, where the
        // "missing chain link" backend error fires with a clearer
        // message. Revoked leaves likewise fall through to the
        // chain-walk's revocation check, so the deny-reason on the
        // resulting receipt stays "capability revoked in chain"
        // rather than getting masked by a quarantine check.
        //
        // We acquire the read-lock once to snapshot the leaf's
        // (subject, swarm_id, is_revoked), then drop it before the
        // async quarantine consultation to avoid holding the inner
        // lock across an await — the quarantine source has its own
        // internal lock and ordering is cleaner this way.
        let leaf_meta: Option<(yutha_core::AgentId, yutha_core::SwarmId)> = {
            let guard = self.inner.read().await;
            match (
                guard.by_id.get(capability_id),
                guard.revoked.contains_key(capability_id),
            ) {
                (Some(leaf), false) => Some((leaf.subject, leaf.swarm_id)),
                _ => None,
            }
        };
        if let Some((subject, swarm_id)) = leaf_meta {
            if self.quarantine.is_agent_quarantined(&subject).await {
                return Ok((
                    CheckOutcome::deny(Some(capability_id.clone()), "subject_quarantined", vec![]),
                    swarm_id,
                ));
            }
        }

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
    use yutha_passport::{
        MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
    };
    use yutha_signer::InProcessSigner;

    async fn harness() -> (MemoryCapabilityStore, Arc<dyn ReceiptStore>, SwarmId) {
        let swarm_id = SwarmId::new();
        let receipts: Arc<dyn ReceiptStore> = Arc::new(yutha_receipt::MemoryStore::new());
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

        let cp_signer = InProcessSigner::generate();
        let cp_public_key = cp_signer.public_key();
        let cp_signer: Arc<dyn yutha_signer::Signer> = Arc::new(cp_signer);
        let cp_agent_id = AgentId::new();
        let cp_passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(cp_agent_id)
            .swarm_id(swarm_id)
            .agent_public_key(cp_public_key)
            .owner("cp")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(cp_signer.as_ref())
            .await
            .unwrap();
        passports.register(cp_passport).await.unwrap();
        let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_signer));

        let store = MemoryCapabilityStore::new(
            Arc::clone(&receipts),
            resolver,
            cp,
            Arc::new(crate::quarantine::AlwaysAllowed),
        );
        (store, receipts, swarm_id)
    }

    fn far_future() -> Timestamp {
        Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap()
    }

    async fn root_cap(scope: Scope, swarm_id: SwarmId) -> Capability {
        root_cap_for(AgentId::new(), scope, swarm_id).await
    }

    /// Variant of [`root_cap`] that lets the caller pin the subject —
    /// needed by tests (e.g. `list_for_subject_*`) that have to issue
    /// multiple caps under the same recipient and assert filter
    /// behaviour. `root_cap` picks a random `AgentId` which is fine for
    /// single-cap flows but useless when the test logic depends on the
    /// subject value.
    async fn root_cap_for(subject: AgentId, scope: Scope, swarm_id: SwarmId) -> Capability {
        let signer = InProcessSigner::generate();
        Capability::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .capability_id(vec![1u8; 16])
            .swarm_id(swarm_id)
            .issuer(Issuer::Operator(vec![0u8; 32]))
            .subject(subject)
            .scope(scope)
            .valid_from(Timestamp::now())
            .valid_until(far_future())
            .sign(&signer)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn issue_then_check_pass_emits_receipt() {
        let (store, receipts, swarm) = harness().await;
        let cap = root_cap(Scope::for_action("send_message"), swarm).await;
        let issued = store.issue(cap).await.unwrap();
        let eval = store
            .check(
                &issued.capability_id,
                &ActionDescriptor {
                    action_kind: "send_message".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(eval.outcome.permitted);

        // Issuance receipt + check receipt both landed.
        let issue_page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "capability.issue".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(issue_page.receipts.len(), 1);

        let check_page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "capability.check.pass".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(check_page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn deny_emits_check_deny_receipt() {
        let (store, receipts, swarm) = harness().await;
        let cap = root_cap(Scope::for_action("send_message"), swarm).await;
        let issued = store.issue(cap).await.unwrap();
        let eval = store
            .check(
                &issued.capability_id,
                &ActionDescriptor {
                    action_kind: "exfiltrate".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!eval.outcome.permitted);

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

    #[tokio::test]
    async fn list_for_subject_empty_store_returns_empty() {
        let (store, _receipts, _swarm) = harness().await;
        let ids = store.list_for_subject(&AgentId::new()).await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_for_subject_filters_by_subject() {
        // Three caps, two distinct subjects. The query must return only
        // the caps whose subject == query target, in any order — the
        // cascade caller doesn't depend on ordering.
        let (store, _receipts, swarm) = harness().await;
        let target = AgentId::new();
        let other = AgentId::new();

        let cap_a = root_cap_for(target, Scope::for_action("send_message"), swarm).await;
        let cap_b = root_cap_for(target, Scope::for_action("envelope.send"), swarm).await;
        let cap_c = root_cap_for(other, Scope::for_action("send_message"), swarm).await;

        let id_a = store.issue(cap_a).await.unwrap().capability_id;
        let id_b = store.issue(cap_b).await.unwrap().capability_id;
        let _id_c = store.issue(cap_c).await.unwrap().capability_id;

        let mut got = store.list_for_subject(&target).await.unwrap();
        got.sort_by(|x, y| x.digest.cmp(&y.digest));
        let mut want = vec![id_a, id_b];
        want.sort_by(|x, y| x.digest.cmp(&y.digest));
        assert_eq!(got, want);

        // Negative: the other subject still resolves to its single cap.
        let other_ids = store.list_for_subject(&other).await.unwrap();
        assert_eq!(other_ids.len(), 1);
    }

    #[tokio::test]
    async fn list_for_subject_excludes_revoked() {
        // RFC 0009 §3.2 cascade is supposed to no-op on already-revoked
        // caps. We enforce that at the source by having
        // `list_for_subject` filter them out — otherwise the cascade
        // loop would try to revoke them again and the receipt store
        // would record duplicate `capability.revoke` entries.
        let (store, _receipts, swarm) = harness().await;
        let target = AgentId::new();

        let cap_live = root_cap_for(target, Scope::for_action("send_message"), swarm).await;
        let cap_dead = root_cap_for(target, Scope::for_action("envelope.send"), swarm).await;
        let id_live = store.issue(cap_live).await.unwrap().capability_id;
        let id_dead = store.issue(cap_dead).await.unwrap().capability_id;

        // Revoke one directly (simulates the agent self-revoking it
        // before the operator gets there).
        store
            .revoke(&id_dead, "pre-cascade self-revoke")
            .await
            .unwrap();

        let ids = store.list_for_subject(&target).await.unwrap();
        assert_eq!(ids, vec![id_live]);
    }

    /// `QuarantineSource` impl used by the F10g tests below. Backed by
    /// a parking-lot-free `RwLock<HashSet<AgentId>>` so the test can
    /// flip an agent's quarantine state mid-test.
    #[derive(Debug, Default)]
    struct TestQuarantine {
        set: tokio::sync::RwLock<std::collections::HashSet<AgentId>>,
    }

    #[async_trait]
    impl crate::quarantine::QuarantineSource for TestQuarantine {
        async fn is_agent_quarantined(&self, agent_id: &AgentId) -> bool {
            self.set.read().await.contains(agent_id)
        }
    }

    impl TestQuarantine {
        async fn quarantine(&self, agent_id: AgentId) {
            self.set.write().await.insert(agent_id);
        }
    }

    /// Variant of [`harness`] that swaps in a controllable quarantine
    /// source so the F10g tests can flip an agent's state mid-test.
    async fn harness_with_quarantine(
        q: Arc<TestQuarantine>,
    ) -> (MemoryCapabilityStore, Arc<dyn ReceiptStore>, SwarmId) {
        let swarm_id = SwarmId::new();
        let receipts: Arc<dyn ReceiptStore> = Arc::new(yutha_receipt::MemoryStore::new());
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

        let cp_signer = InProcessSigner::generate();
        let cp_public_key = cp_signer.public_key();
        let cp_signer: Arc<dyn yutha_signer::Signer> = Arc::new(cp_signer);
        let cp_agent_id = AgentId::new();
        let cp_passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(cp_agent_id)
            .swarm_id(swarm_id)
            .agent_public_key(cp_public_key)
            .owner("cp")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(cp_signer.as_ref())
            .await
            .unwrap();
        passports.register(cp_passport).await.unwrap();
        let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_signer));

        let store = MemoryCapabilityStore::new(Arc::clone(&receipts), resolver, cp, q);
        (store, receipts, swarm_id)
    }

    #[tokio::test]
    async fn check_denies_when_subject_is_quarantined() {
        // Issue a cap to a fresh subject, then flip the subject to
        // quarantined before checking. The check should deny with
        // reason "subject_quarantined" and emit a
        // `capability.check.deny` receipt — never letting the
        // quarantined agent's action through on the merits, per
        // RFC 0013 §4.2.
        let q = Arc::new(TestQuarantine::default());
        let (store, receipts, swarm) = harness_with_quarantine(Arc::clone(&q)).await;
        let target = AgentId::new();
        let cap = root_cap_for(target, Scope::for_action("send_message"), swarm).await;
        let issued = store.issue(cap).await.unwrap();

        // Quarantine the subject *after* issuance — issuance happened
        // when the agent was still in good standing.
        q.quarantine(target).await;

        let eval = store
            .check(
                &issued.capability_id,
                &ActionDescriptor {
                    action_kind: "send_message".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!eval.outcome.permitted, "quarantine must deny");
        assert_eq!(eval.outcome.deny_reason, "subject_quarantined");

        // Deny receipt landed.
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

    #[tokio::test]
    async fn issue_refused_when_subject_is_quarantined() {
        // Quarantine first, then attempt to issue. The store must
        // refuse with `SubjectQuarantined` — issuance is the cap
        // layer's way of handing fresh authority to an agent, and
        // a quarantined agent doesn't get fresh authority.
        let q = Arc::new(TestQuarantine::default());
        let (store, _receipts, swarm) = harness_with_quarantine(Arc::clone(&q)).await;
        let target = AgentId::new();
        q.quarantine(target).await;

        let cap = root_cap_for(target, Scope::for_action("send_message"), swarm).await;
        let err = store.issue(cap).await.unwrap_err();
        assert!(
            matches!(err, CapabilityError::SubjectQuarantined(a) if a == target),
            "expected SubjectQuarantined({target}), got {err:?}"
        );
    }

    #[tokio::test]
    async fn revoke_emits_capability_revoke_receipt() {
        let (store, receipts, swarm) = harness().await;
        let cap = root_cap(Scope::for_action("send_message"), swarm).await;
        let issued = store.issue(cap).await.unwrap();
        let receipt_id = store
            .revoke(&issued.capability_id, "scaffolding test")
            .await
            .unwrap();
        assert_eq!(receipt_id.digest.len(), 32, "sha256 digest");

        let page = receipts
            .query(
                yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                    action_kind: "capability.revoke".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.receipts.len(), 1);
    }
}
