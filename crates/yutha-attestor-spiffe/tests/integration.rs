//! Integration test for [`SpiffeAttestor`] against a real SPIRE agent.
//!
//! Implements the [`attestor-spiffe.md` §11 docker-spire conformance pattern](../../../spec/identity-keys/attestor-spiffe.md#11-conformance-vectors)
//! end-to-end: fetch a JWT-SVID via the Workload API, hand it to a
//! [`SpiffeAttestor`] connected to the same agent socket, assert the
//! `AttestedIdentity` matches the SPIRE-issued SPIFFE ID.
//!
//! Skipped by default. Runs only when:
//!   - `YUTHA_ATTESTOR_SPIFFE_INTEGRATION_SOCKET` is set to a
//!     reachable SPIRE Workload API socket, AND
//!   - `YUTHA_ATTESTOR_SPIFFE_INTEGRATION_AUDIENCE` is set to an
//!     audience the SPIRE registration entry mints SVIDs for, AND
//!   - the test is invoked with `cargo test -- --ignored`.
//!
//! See [`tests/SPIRE_LOCAL_TESTING.md`](./SPIRE_LOCAL_TESTING.md) for
//! the verified-working local SPIRE setup recipe (macOS + Linux). The
//! operator-facing equivalent will land at
//! `docs/operator/spiffe-attestor.md` in Phase E9.

use spiffe::JwtSource;
use std::path::PathBuf;
use yutha_attestor::{AttestationContext, Attestor};
use yutha_attestor_spiffe::{SpiffeAttestor, SpiffeConfig, TrustBundleSource};
use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};

/// Returns `Some((socket, audience))` if the operator has set the
/// env vars, otherwise `None`. The integration test calls this at
/// the top of every case — if `None`, the case prints a skip message
/// and returns early. Mirrors the
/// [`yutha-signer-vault` integration pattern](../../../yutha-signer-vault/tests/integration.rs)
/// so a missing env-var means "skip this test" rather than fail.
fn skip_unless_env_set() -> Option<(PathBuf, String)> {
    let socket = match std::env::var("YUTHA_ATTESTOR_SPIFFE_INTEGRATION_SOCKET") {
        Ok(s) => PathBuf::from(s),
        Err(_) => {
            eprintln!(
                "yutha-attestor-spiffe integration test skipped: \
                 set YUTHA_ATTESTOR_SPIFFE_INTEGRATION_SOCKET to a SPIRE \
                 agent Workload API socket path + \
                 YUTHA_ATTESTOR_SPIFFE_INTEGRATION_AUDIENCE to a registered \
                 audience to run. See docs/operator/spiffe-attestor.md \
                 for the docker-spire one-liner."
            );
            return None;
        }
    };
    let audience = match std::env::var("YUTHA_ATTESTOR_SPIFFE_INTEGRATION_AUDIENCE") {
        Ok(a) if !a.is_empty() => a,
        _ => {
            eprintln!(
                "yutha-attestor-spiffe integration test skipped: \
                 YUTHA_ATTESTOR_SPIFFE_INTEGRATION_AUDIENCE is unset or empty."
            );
            return None;
        }
    };
    Some((socket, audience))
}

fn dummy_context() -> AttestationContext {
    AttestationContext {
        swarm_id: SwarmId::new(),
        claimed_agent_id: AgentId::new(),
        agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])
            .expect("32-byte placeholder pk"),
    }
}

fn socket_endpoint(path: &std::path::Path) -> String {
    let s = path.to_string_lossy();
    if s.starts_with("unix:") || s.starts_with("tcp:") {
        s.into_owned()
    } else {
        format!("unix:{s}")
    }
}

/// Fetch a JWT-SVID from the Workload API for the given audience.
/// Used to mint the credential that the integration test then hands
/// to `SpiffeAttestor`.
///
/// Uses `JwtSource::builder().endpoint(...)` rather than the lower-
/// level `WorkloadApiClient`; the high-level builder is what the
/// SDK exposes for explicit-endpoint construction in 0.15+.
async fn fetch_jwt_svid(socket: &std::path::Path, audience: &str) -> String {
    let endpoint = socket_endpoint(socket);
    let source = JwtSource::builder()
        .endpoint(&endpoint)
        .build()
        .await
        .expect("JwtSource against integration SPIRE");
    let svid = source
        .get_jwt_svid(&[audience])
        .await
        .expect("get_jwt_svid for the integration audience");
    svid.token().to_string()
}

/// Happy-path round trip: WL-API source + WL-API-fetched SVID →
/// verify succeeds and the `AttestedIdentity` carries the SPIFFE ID
/// SPIRE assigned.
#[tokio::test]
#[ignore]
async fn workload_api_source_verifies_workload_api_svid() {
    let Some((socket, audience)) = skip_unless_env_set() else {
        return;
    };

    let attestor = SpiffeAttestor::connect(SpiffeConfig {
        source: TrustBundleSource::WorkloadApi {
            socket: socket.clone(),
        },
        expected_audience: audience.clone(),
        max_staleness: None,
        clock_skew_tolerance_secs: 60,
        connect_timeout_secs: 10,
    })
    .await
    .expect(
        "SpiffeAttestor::connect against integration SPIRE — \
         confirm the agent is reachable and the audience is registered",
    );
    assert_eq!(attestor.id(), "spiffe");

    let svid_token = fetch_jwt_svid(&socket, &audience).await;

    let identity = attestor
        .verify(&dummy_context(), svid_token.as_bytes())
        .await
        .expect("happy-path verify against SPIRE-minted SVID must succeed");

    assert!(
        identity.external_identity.starts_with("spiffe://"),
        "external_identity must be a SPIFFE ID, got: {}",
        identity.external_identity,
    );
    assert!(identity.credential_expires_at.is_some());
    eprintln!(
        "integration roundtrip OK — attested external_identity = {}",
        identity.external_identity,
    );
}

/// Wrong-audience reject path: connect with audience A, fetch SVID
/// for audience B, verify must reject with `audience mismatch`.
#[tokio::test]
#[ignore]
async fn workload_api_source_rejects_wrong_audience() {
    let Some((socket, audience)) = skip_unless_env_set() else {
        return;
    };

    // Construct an Attestor that expects a DIFFERENT audience than
    // the one the SPIRE registration entry mints. Verification of
    // an SVID for the registered audience must fail.
    let attestor = SpiffeAttestor::connect(SpiffeConfig {
        source: TrustBundleSource::WorkloadApi {
            socket: socket.clone(),
        },
        expected_audience: format!("{audience}-WRONG"),
        max_staleness: None,
        clock_skew_tolerance_secs: 60,
        connect_timeout_secs: 10,
    })
    .await
    .expect("connect");

    let svid_token = fetch_jwt_svid(&socket, &audience).await;

    let err = attestor
        .verify(&dummy_context(), svid_token.as_bytes())
        .await
        .expect_err("audience mismatch must reject");
    match err {
        yutha_attestor::AttestorError::Rejected(msg) => {
            assert!(
                msg.contains("audience mismatch"),
                "spec-pinned message shape; got: {msg}"
            );
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}
