//! [`Passport`] and [`PassportBuilder`].
//!
//! Mirrors `Passport` from
//! [`/spec/passport/passport-v1.proto`](../../../spec/passport/passport-v1.proto).
//!
//! A passport is content-addressable: hash of its canonical serialization
//! with `agent_signature` cleared is its identifier. Signatures and
//! seal-style metadata are excluded from canonical bytes (same pattern as
//! receipts).

use crate::declarations::{CapabilityDeclaration, ResourceDeclaration};
use crate::error::{PassportError, Result};
use crate::tier::PassportTier;
use yutha_core::{AgentId, PublicKey, Signature, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::Result as CryptoResult;
use yutha_proto::Message;

/// A signed identity manifest. What an agent presents to a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Passport {
    /// Spec version this passport was authored under.
    pub spec_version: SpecVersion,
    /// Stable agent identifier. UUID v7.
    pub agent_id: AgentId,
    /// Swarm this passport is valid for (passports are single-swarm).
    pub swarm_id: SwarmId,
    /// Public key the agent uses to sign envelopes and receipts.
    pub agent_public_key: PublicKey,
    /// Human-readable owner identifier (org / team / individual).
    pub owner: String,
    /// Framework the agent is built on (e.g. `"langgraph"`, `"autogen"`).
    pub framework: String,
    /// Framework version string.
    pub framework_version: String,
    /// What the agent claims it can do. NOT authority — see capability spec.
    pub capabilities: Vec<CapabilityDeclaration>,
    /// Constitution version this agent commits to obey.
    pub accepted_constitution_version: String,
    /// Tier mirroring conformance tiers.
    pub tier: PassportTier,
    /// Declared resource budget.
    pub resources: ResourceDeclaration,
    /// When issued.
    pub issued_at: Timestamp,
    /// When this passport stops being valid. Optional in closed swarms;
    /// required in open/hybrid (sybil mitigation — re-registration cost).
    pub expires_at: Option<Timestamp>,
    /// Default model provider for A2 attribution.
    pub default_model_provider: String,
    /// Default model name.
    pub default_model_name: String,
    /// Self-signature over canonical bytes (signature cleared).
    pub agent_signature: Option<Signature>,
}

impl Passport {
    /// Builder for constructing a passport.
    pub fn builder() -> PassportBuilder {
        PassportBuilder::default()
    }

    /// Check whether this passport has expired against the given monotonic
    /// timestamp. Returns false for passports without `expires_at`.
    pub fn is_expired_at(&self, now: &Timestamp) -> bool {
        self.expires_at
            .as_ref()
            .map(|e| e.monotonic_ns <= now.monotonic_ns)
            .unwrap_or(false)
    }
}

impl Canonical for Passport {
    /// Produce canonical bytes for content-addressing and signature
    /// verification.
    ///
    /// Goes through [`Passport::to_canonical_proto`] (which clears
    /// `agent_signature` and `extensions`) and then encodes via
    /// `prost::Message::encode_to_vec()`. With prost's tag-sorted field
    /// encoding plus `btree_map(["."])` in `yutha-proto`'s build (so the
    /// `bounds` map on each [`CapabilityDeclaration`] encodes with sorted
    /// keys), the result is bytewise deterministic both within a single Rust
    /// process and across spec-conforming implementations.
    fn canonical_bytes(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.to_canonical_proto().encode_to_vec())
    }
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Builder for [`Passport`].
///
/// The agent's signing key produces `agent_signature` at the very end via
/// [`PassportBuilder::sign`]; callers MAY construct unsigned passports for
/// pre-flight validation but the registry will reject them.
#[derive(Debug, Default)]
pub struct PassportBuilder {
    spec_version: Option<SpecVersion>,
    agent_id: Option<AgentId>,
    swarm_id: Option<SwarmId>,
    agent_public_key: Option<PublicKey>,
    owner: String,
    framework: String,
    framework_version: String,
    capabilities: Vec<CapabilityDeclaration>,
    accepted_constitution_version: String,
    tier: PassportTier,
    resources: ResourceDeclaration,
    issued_at: Option<Timestamp>,
    expires_at: Option<Timestamp>,
    default_model_provider: String,
    default_model_name: String,
}

impl PassportBuilder {
    /// Required: spec version.
    pub fn spec_version(mut self, v: SpecVersion) -> Self {
        self.spec_version = Some(v);
        self
    }
    /// Required: agent id.
    pub fn agent_id(mut self, id: AgentId) -> Self {
        self.agent_id = Some(id);
        self
    }
    /// Required: swarm id.
    pub fn swarm_id(mut self, id: SwarmId) -> Self {
        self.swarm_id = Some(id);
        self
    }
    /// Required: agent's public key.
    pub fn agent_public_key(mut self, pk: PublicKey) -> Self {
        self.agent_public_key = Some(pk);
        self
    }
    /// Optional: human-readable owner.
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = owner.into();
        self
    }
    /// Optional: framework + version.
    pub fn framework(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.framework = name.into();
        self.framework_version = version.into();
        self
    }
    /// Optional: add a capability declaration.
    pub fn declares(mut self, decl: CapabilityDeclaration) -> Self {
        self.capabilities.push(decl);
        self
    }
    /// Required: constitution version the agent commits to.
    pub fn accepted_constitution_version(mut self, v: impl Into<String>) -> Self {
        self.accepted_constitution_version = v.into();
        self
    }
    /// Optional: passport tier (default: Minimal).
    pub fn tier(mut self, tier: PassportTier) -> Self {
        self.tier = tier;
        self
    }
    /// Optional: resource declaration.
    pub fn resources(mut self, r: ResourceDeclaration) -> Self {
        self.resources = r;
        self
    }
    /// Required: issued-at timestamp.
    pub fn issued_at(mut self, t: Timestamp) -> Self {
        self.issued_at = Some(t);
        self
    }
    /// Optional: expiration. Required in open/hybrid swarms by topology.
    pub fn expires_at(mut self, t: Timestamp) -> Self {
        self.expires_at = Some(t);
        self
    }
    /// Optional: default model provider for A2 attribution.
    pub fn default_model(mut self, provider: impl Into<String>, name: impl Into<String>) -> Self {
        self.default_model_provider = provider.into();
        self.default_model_name = name.into();
        self
    }

    /// Build an unsigned passport. Useful for pre-flight validation.
    pub fn build_unsigned(self) -> Result<Passport> {
        Ok(Passport {
            spec_version: self
                .spec_version
                .ok_or(PassportError::MissingField("spec_version"))?,
            agent_id: self
                .agent_id
                .ok_or(PassportError::MissingField("agent_id"))?,
            swarm_id: self
                .swarm_id
                .ok_or(PassportError::MissingField("swarm_id"))?,
            agent_public_key: self
                .agent_public_key
                .ok_or(PassportError::MissingField("agent_public_key"))?,
            owner: self.owner,
            framework: self.framework,
            framework_version: self.framework_version,
            capabilities: self.capabilities,
            accepted_constitution_version: self.accepted_constitution_version,
            tier: self.tier,
            resources: self.resources,
            issued_at: self
                .issued_at
                .ok_or(PassportError::MissingField("issued_at"))?,
            expires_at: self.expires_at,
            default_model_provider: self.default_model_provider,
            default_model_name: self.default_model_name,
            agent_signature: None,
        })
    }

    /// Build and sign with the supplied signing key. The signing key's
    /// public counterpart MUST match the `agent_public_key` field — this is
    /// re-checked here.
    pub fn sign(self, signing_key: &yutha_crypto::SigningKey) -> Result<Passport> {
        let mut p = self.build_unsigned()?;
        if p.agent_public_key != signing_key.public() {
            return Err(PassportError::SelfSignatureInvalid);
        }
        let bytes = p.canonical_bytes().map_err(PassportError::Crypto)?;
        let sig = signing_key.sign_message(&bytes);
        p.agent_signature = Some(sig);
        Ok(p)
    }
}

// `Default for PassportTier` is derived in tier.rs with `#[default]` on `Minimal`.

// -----------------------------------------------------------------------------
// Verification
// -----------------------------------------------------------------------------

impl Passport {
    /// Verify the passport's self-signature against the inlined public key.
    /// Returns Ok on success; [`PassportError::SelfSignatureInvalid`] on
    /// mismatch or if the signature is missing.
    pub fn verify_self_signature(&self) -> Result<()> {
        let sig = self
            .agent_signature
            .as_ref()
            .ok_or(PassportError::SelfSignatureInvalid)?;
        let bytes = self.canonical_bytes().map_err(PassportError::Crypto)?;
        yutha_crypto::sign::verify(&self.agent_public_key, &bytes, sig)
            .map_err(|_| PassportError::SelfSignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_crypto::sign::generate_keypair;

    fn fixture() -> (yutha_crypto::SigningKey, AgentId) {
        (generate_keypair(), AgentId::new())
    }

    fn build_signed(key: &yutha_crypto::SigningKey, agent_id: AgentId) -> Passport {
        Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(SwarmId::new())
            .agent_public_key(key.public())
            .owner("test")
            .framework("test-framework", "0.1.0")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(key)
            .unwrap()
    }

    #[test]
    fn builder_requires_required_fields() {
        let result = Passport::builder().build_unsigned();
        assert!(result.is_err());
    }

    #[test]
    fn signed_passport_verifies() {
        let (key, agent_id) = fixture();
        let p = build_signed(&key, agent_id);
        assert!(p.verify_self_signature().is_ok());
    }

    #[test]
    fn passport_with_mismatched_public_key_rejects_at_sign() {
        let (key1, agent_id) = fixture();
        let key2 = generate_keypair();
        let result = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(SwarmId::new())
            .agent_public_key(key2.public()) // mismatch with signing key
            .accepted_constitution_version("1.0.0")
            .issued_at(Timestamp::now())
            .sign(&key1);
        assert!(matches!(result, Err(PassportError::SelfSignatureInvalid)));
    }

    #[test]
    fn tampered_passport_fails_verification() {
        let (key, agent_id) = fixture();
        let mut p = build_signed(&key, agent_id);
        p.owner = "tampered".into();
        assert!(matches!(
            p.verify_self_signature(),
            Err(PassportError::SelfSignatureInvalid)
        ));
    }

    #[test]
    fn unsigned_passport_fails_verification() {
        let (key, agent_id) = fixture();
        let mut p = build_signed(&key, agent_id);
        p.agent_signature = None;
        assert!(matches!(
            p.verify_self_signature(),
            Err(PassportError::SelfSignatureInvalid)
        ));
    }

    #[test]
    fn is_expired_when_past_monotonic() {
        let (key, agent_id) = fixture();
        let mut p = build_signed(&key, agent_id);
        // Force an expires_at strictly less than the issued_at monotonic.
        p.expires_at = Some(
            Timestamp::new(
                "2020-01-01T00:00:00Z".into(),
                p.issued_at.monotonic_ns.saturating_sub(1),
            )
            .unwrap(),
        );
        let now = Timestamp::now();
        assert!(p.is_expired_at(&now));
    }

    #[test]
    fn passport_without_expires_at_never_expires() {
        let (key, agent_id) = fixture();
        let p = build_signed(&key, agent_id);
        let far_future = Timestamp::new("3030-01-01T00:00:00Z".into(), u64::MAX).unwrap();
        assert!(!p.is_expired_at(&far_future));
    }
}
