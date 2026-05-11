//! [`Capability`] — the authority token itself.

use crate::caveat::Caveat;
use crate::check::{ActionDescriptor, CheckOutcome};
use crate::error::{CapabilityError, Result};
use crate::issuer::Issuer;
use crate::scope::Scope;
use yutha_core::{AgentId, Hash, Signature, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::Result as CryptoResult;
use yutha_proto::Message;

/// A signed authority token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Capability {
    /// Spec version.
    pub spec_version: SpecVersion,
    /// Stable capability id (UUID v7, 16 bytes).
    pub capability_id: Vec<u8>,
    /// Swarm where this capability is valid.
    pub swarm_id: SwarmId,
    /// Who issued it.
    pub issuer: Issuer,
    /// Who can use it.
    pub subject: AgentId,
    /// What it permits.
    pub scope: Scope,
    /// Content-address of the parent capability (empty for root).
    pub parent: Option<Hash>,
    /// Window: not before.
    pub valid_from: Timestamp,
    /// Window: not after. REQUIRED — no non-expiring capabilities.
    pub valid_until: Timestamp,
    /// Caveats further constraining when the capability is valid.
    pub caveats: Vec<Caveat>,
    /// Optional revocation-check endpoint (CRL-like).
    pub revocation_endpoint: String,
    /// Issuer's signature (canonical bytes with this field cleared).
    pub issuer_signature: Option<Signature>,
}

impl Capability {
    /// Builder.
    pub fn builder() -> CapabilityBuilder {
        CapabilityBuilder::default()
    }

    /// Whether this capability is within its validity window relative to
    /// the given monotonic time.
    pub fn is_within_window(&self, now: &Timestamp) -> bool {
        now.monotonic_ns >= self.valid_from.monotonic_ns
            && now.monotonic_ns <= self.valid_until.monotonic_ns
    }

    /// Evaluate a single capability against an action descriptor, ignoring
    /// any parent chain. Use [`crate::store::CapabilityStore::check`] for
    /// the chain-aware version.
    pub fn check(&self, descriptor: &ActionDescriptor) -> CheckOutcome {
        let cap_id = yutha_crypto::canonical::content_address(self).ok();

        // Scope.
        if !self.scope.permits(descriptor) {
            return CheckOutcome::deny(cap_id, "scope does not permit action", vec![]);
        }

        // Caveats.
        let mut matched = Vec::new();
        let mut unmet = Vec::new();
        for caveat in &self.caveats {
            let label = caveat_label(caveat);
            if caveat.permits(descriptor) {
                matched.push(label);
            } else {
                unmet.push(label);
            }
        }
        if !unmet.is_empty() {
            return CheckOutcome::deny(cap_id, "caveat(s) not met", unmet);
        }

        CheckOutcome::permit(cap_id, matched)
    }
}

/// Label string for observability / receipts. Concise per-caveat tag.
fn caveat_label(c: &Caveat) -> String {
    match c {
        Caveat::TimeOfDay(_) => "time_of_day".into(),
        Caveat::ConstitutionVersion { .. } => "constitution_version".into(),
        Caveat::SupervisorRequired { .. } => "supervisor_required".into(),
        Caveat::RateLimit(_) => "rate_limit".into(),
        Caveat::OnlyIfTagged { .. } => "only_if_tagged".into(),
        Caveat::NeverIfTagged { .. } => "never_if_tagged".into(),
    }
}

impl Canonical for Capability {
    /// Canonical bytes for content-addressing and signature verification.
    ///
    /// Goes through [`Capability::to_canonical_proto`] (which clears
    /// `signatures` and `extensions`) and encodes via prost. With tag-sorted
    /// fields plus `btree_map(["."])` for the scope's `bounds` map, the
    /// result is bytewise deterministic across runs and across
    /// spec-conforming implementations.
    fn canonical_bytes(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.to_canonical_proto().encode_to_vec())
    }
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Builder for [`Capability`].
#[derive(Debug, Default)]
pub struct CapabilityBuilder {
    spec_version: Option<SpecVersion>,
    capability_id: Option<Vec<u8>>,
    swarm_id: Option<SwarmId>,
    issuer: Option<Issuer>,
    subject: Option<AgentId>,
    scope: Scope,
    parent: Option<Hash>,
    valid_from: Option<Timestamp>,
    valid_until: Option<Timestamp>,
    caveats: Vec<Caveat>,
    revocation_endpoint: String,
}

impl CapabilityBuilder {
    /// Required: spec version.
    pub fn spec_version(mut self, v: SpecVersion) -> Self {
        self.spec_version = Some(v);
        self
    }
    /// Required: capability id (16-byte UUID v7).
    pub fn capability_id(mut self, id: Vec<u8>) -> Self {
        self.capability_id = Some(id);
        self
    }
    /// Required: swarm id.
    pub fn swarm_id(mut self, id: SwarmId) -> Self {
        self.swarm_id = Some(id);
        self
    }
    /// Required: issuer.
    pub fn issuer(mut self, issuer: Issuer) -> Self {
        self.issuer = Some(issuer);
        self
    }
    /// Required: subject (agent permitted to use the capability).
    pub fn subject(mut self, id: AgentId) -> Self {
        self.subject = Some(id);
        self
    }
    /// Required: scope.
    pub fn scope(mut self, s: Scope) -> Self {
        self.scope = s;
        self
    }
    /// Optional: parent capability for attenuated children.
    pub fn parent(mut self, hash: Hash) -> Self {
        self.parent = Some(hash);
        self
    }
    /// Required: validity window start.
    pub fn valid_from(mut self, t: Timestamp) -> Self {
        self.valid_from = Some(t);
        self
    }
    /// Required: validity window end. Non-expiring capabilities are rejected
    /// by the spec.
    pub fn valid_until(mut self, t: Timestamp) -> Self {
        self.valid_until = Some(t);
        self
    }
    /// Optional: add a caveat.
    pub fn caveat(mut self, caveat: Caveat) -> Self {
        self.caveats.push(caveat);
        self
    }
    /// Optional: revocation endpoint URL.
    pub fn revocation_endpoint(mut self, url: impl Into<String>) -> Self {
        self.revocation_endpoint = url.into();
        self
    }

    /// Build (unsigned).
    pub fn build(self) -> Result<Capability> {
        Ok(Capability {
            spec_version: self
                .spec_version
                .ok_or(CapabilityError::MissingField("spec_version"))?,
            capability_id: self
                .capability_id
                .ok_or(CapabilityError::MissingField("capability_id"))?,
            swarm_id: self
                .swarm_id
                .ok_or(CapabilityError::MissingField("swarm_id"))?,
            issuer: self.issuer.ok_or(CapabilityError::MissingField("issuer"))?,
            subject: self
                .subject
                .ok_or(CapabilityError::MissingField("subject"))?,
            scope: self.scope,
            parent: self.parent,
            valid_from: self
                .valid_from
                .ok_or(CapabilityError::MissingField("valid_from"))?,
            valid_until: self
                .valid_until
                .ok_or(CapabilityError::MissingField("valid_until"))?,
            caveats: self.caveats,
            revocation_endpoint: self.revocation_endpoint,
            issuer_signature: None,
        })
    }

    /// Build and sign with the supplied issuer signing key.
    pub fn sign(self, signing_key: &yutha_crypto::SigningKey) -> Result<Capability> {
        let mut c = self.build()?;
        let bytes = c.canonical_bytes().map_err(CapabilityError::Crypto)?;
        let sig = signing_key.sign_message(&bytes);
        c.issuer_signature = Some(sig);
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caveat::Caveat;
    use yutha_crypto::sign::generate_keypair;

    fn make_cap(scope: Scope) -> Capability {
        let key = generate_keypair();
        Capability::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .capability_id(vec![0u8; 16])
            .swarm_id(SwarmId::new())
            .issuer(Issuer::Agent(AgentId::new()))
            .subject(AgentId::new())
            .scope(scope)
            .valid_from(Timestamp::now())
            .valid_until(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap())
            .sign(&key)
            .unwrap()
    }

    #[test]
    fn check_permits_matching_action() {
        let cap = make_cap(Scope::for_action("send_message"));
        let descriptor = ActionDescriptor {
            action_kind: "send_message".into(),
            ..Default::default()
        };
        let outcome = cap.check(&descriptor);
        assert!(outcome.permitted);
    }

    #[test]
    fn check_denies_disallowed_action() {
        let cap = make_cap(Scope::for_action("send_message"));
        let descriptor = ActionDescriptor {
            action_kind: "exfiltrate".into(),
            ..Default::default()
        };
        let outcome = cap.check(&descriptor);
        assert!(!outcome.permitted);
        assert!(outcome.deny_reason.contains("scope"));
    }

    #[test]
    fn check_denies_when_caveat_fails() {
        let scope = Scope::for_action("send_message");
        let key = generate_keypair();
        let cap = Capability::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .capability_id(vec![0u8; 16])
            .swarm_id(SwarmId::new())
            .issuer(Issuer::Agent(AgentId::new()))
            .subject(AgentId::new())
            .scope(scope)
            .valid_from(Timestamp::now())
            .valid_until(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap())
            .caveat(Caveat::NeverIfTagged {
                forbidden_tags: vec!["external".into()],
            })
            .sign(&key)
            .unwrap();

        let denied = cap.check(&ActionDescriptor {
            action_kind: "send_message".into(),
            resource_tags: vec!["external".into()],
            ..Default::default()
        });
        assert!(!denied.permitted);
        assert!(denied
            .unmet_caveats
            .contains(&"never_if_tagged".to_string()));

        let permitted = cap.check(&ActionDescriptor {
            action_kind: "send_message".into(),
            resource_tags: vec!["internal".into()],
            ..Default::default()
        });
        assert!(permitted.permitted);
    }

    #[test]
    fn is_within_window_respects_bounds() {
        let cap = make_cap(Scope::empty());
        assert!(cap.is_within_window(&cap.valid_from));

        let past = Timestamp::new("1990-01-01T00:00:00Z".into(), 0).unwrap();
        // monotonic_ns of past is 0, which is < cap.valid_from.monotonic_ns
        assert!(!cap.is_within_window(&past));
    }
}
