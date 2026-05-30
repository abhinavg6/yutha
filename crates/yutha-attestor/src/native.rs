//! [`NativeAttestor`] — the zero-dependency default implementation.

use crate::error::AttestorError;
use crate::traits::Attestor;
use crate::types::{AttestationContext, AttestedIdentity};
use async_trait::async_trait;
use std::collections::BTreeMap;

/// The zero-dependency default [`Attestor`] implementation.
///
/// Verifies nothing about an external credential — the credential MUST
/// be empty. The passport's self-signature (verified by the admission
/// handler before [`Attestor::verify`] is called) is the only proof
/// of identity; this Attestor exists so the admission flow has a
/// uniform shape (one Attestor call per registration) regardless of
/// whether external attestation is configured.
///
/// The native flow is behaviourally unchanged from pre-RFC-0016 — only
/// the `agent.register` receipt's evidence gains two new keys:
/// `attested_external_identity = "yutha:native:<hex>"` and
/// `attestor_id = "native"`.
///
/// # When to use
///
/// - Hobby and development swarms — no IdP, no SPIRE, no OIDC issuer.
/// - Tests and conformance scenarios.
/// - Bootstrap path for the control plane itself (the control plane's
///   own passport is registered via the native path even when the
///   configured Attestor is SPIFFE/OIDC, because the control plane is
///   not a workload the IdP knows about).
///
/// # When NOT to use
///
/// - Production deployments inside an enterprise that runs SPIRE or
///   OIDC — switch to `yutha-attestor-spiffe` (Phase E) or
///   `yutha-attestor-oidc` (Phase F).
///
/// # Example
///
/// ```no_run
/// use yutha_attestor::{Attestor, AttestationContext, NativeAttestor};
/// use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let attestor = NativeAttestor::default();
/// let ctx = AttestationContext {
///     swarm_id: SwarmId::new(),
///     claimed_agent_id: AgentId::new(),
///     agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![7u8; 32])?,
/// };
/// let identity = attestor.verify(&ctx, &[]).await?;
/// assert!(identity.external_identity.starts_with("yutha:native:"));
/// assert!(identity.credential_expires_at.is_none());
/// assert!(identity.attributes.is_empty());
/// # Ok(()) }
/// ```
#[derive(Debug, Default)]
pub struct NativeAttestor;

#[async_trait]
impl Attestor for NativeAttestor {
    fn id(&self) -> &str {
        "native"
    }

    async fn verify(
        &self,
        context: &AttestationContext,
        credential: &[u8],
    ) -> Result<AttestedIdentity, AttestorError> {
        if !credential.is_empty() {
            return Err(AttestorError::Rejected(
                "NativeAttestor configured but external_credential was provided; \
                 reconfigure the control plane with a non-native Attestor or omit \
                 the credential"
                    .into(),
            ));
        }
        Ok(AttestedIdentity {
            external_identity: format!(
                "yutha:native:{}",
                hex::encode(context.claimed_agent_id.as_bytes())
            ),
            credential_expires_at: None,
            attributes: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};

    fn ctx_for(agent_id: AgentId) -> AttestationContext {
        AttestationContext {
            swarm_id: SwarmId::new(),
            claimed_agent_id: agent_id,
            agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]).unwrap(),
        }
    }

    /// The defining property of NativeAttestor — empty credential is
    /// accepted, returns a `yutha:native:<hex>` external identity.
    #[tokio::test]
    async fn empty_credential_accepted() {
        let attestor = NativeAttestor;
        let agent_id = AgentId::new();
        let ctx = ctx_for(agent_id);

        let identity = attestor.verify(&ctx, &[]).await.expect("must accept");

        assert_eq!(attestor.id(), "native");
        assert_eq!(
            identity.external_identity,
            format!("yutha:native:{}", hex::encode(agent_id.as_bytes())),
        );
        assert!(identity.credential_expires_at.is_none());
        assert!(identity.attributes.is_empty());
    }

    /// Non-empty credential is rejected with a clear operator-facing
    /// message.
    #[tokio::test]
    async fn nonempty_credential_rejected() {
        let attestor = NativeAttestor;
        let ctx = ctx_for(AgentId::new());

        let err = attestor
            .verify(&ctx, b"some external credential")
            .await
            .expect_err("must reject");

        match err {
            AttestorError::Rejected(msg) => {
                assert!(msg.contains("NativeAttestor"), "{msg}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// The returned external_identity encodes the claimed_agent_id,
    /// not some other field from the context.
    #[tokio::test]
    async fn external_identity_encodes_claimed_agent_id() {
        let attestor = NativeAttestor;
        let agent_a = AgentId::new();
        let agent_b = AgentId::new();
        assert_ne!(agent_a, agent_b, "test setup");

        let identity_a = attestor.verify(&ctx_for(agent_a), &[]).await.unwrap();
        let identity_b = attestor.verify(&ctx_for(agent_b), &[]).await.unwrap();

        assert_ne!(
            identity_a.external_identity, identity_b.external_identity,
            "different agent_ids must produce different external_identities"
        );
        assert_eq!(
            identity_a.external_identity,
            format!("yutha:native:{}", hex::encode(agent_a.as_bytes()))
        );
        assert_eq!(
            identity_b.external_identity,
            format!("yutha:native:{}", hex::encode(agent_b.as_bytes()))
        );
    }

    /// Concurrent-safety smoke: NativeAttestor is `Send + Sync` and
    /// can serve many concurrent verifications without contention or
    /// state corruption.
    #[tokio::test]
    async fn concurrent_verify_safety() {
        use std::sync::Arc;

        let attestor: Arc<dyn Attestor> = Arc::new(NativeAttestor);
        let mut handles = Vec::new();
        for _ in 0..32 {
            let attestor = Arc::clone(&attestor);
            handles.push(tokio::spawn(async move {
                let agent_id = AgentId::new();
                let ctx = ctx_for(agent_id);
                let identity = attestor.verify(&ctx, &[]).await.unwrap();
                assert!(identity.external_identity.starts_with("yutha:native:"));
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }
}
