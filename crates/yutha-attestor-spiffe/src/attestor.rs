//! [`SpiffeAttestor`] — [`Attestor`] impl backed by SPIFFE JWT-SVID
//! verification.
//!
//! Implements [`attestor-spiffe.md` §3](../../../spec/identity-keys/attestor-spiffe.md#3-verification-algorithm).
//!
//! # The 9-step verification algorithm
//!
//! Spec §3 pins the exact ordering. Mapping to this module's code:
//!
//! | Step | Spec text                                          | Where it lives                                         |
//! |------|----------------------------------------------------|--------------------------------------------------------|
//! | 0    | empty credential check                             | [`SpiffeAttestor::verify`] — first guard               |
//! | 1    | parse JWS compact serialization                    | `JwtSvid::parse_and_validate` (delegated to SDK)       |
//! | 2    | header decode + `alg`/`typ`/`kid` checks           | `JwtSvid::parse_and_validate` (delegated to SDK)       |
//! | 3    | trust-bundle snapshot + bounded staleness          | [`BundleCache::assert_fresh`] — explicit, before SDK   |
//! | 4    | `kid` lookup in bundle                             | `JwtSvid::parse_and_validate` via [`BundleSource`]     |
//! | 5    | JWS signature verify                               | `JwtSvid::parse_and_validate` (delegated to SDK)       |
//! | 6    | payload JSON decode                                | `JwtSvid::parse_and_validate` (delegated to SDK)       |
//! | 7    | claim checks — sub/td/aud/exp/nbf/iat              | mixed: sub/td/aud/exp via SDK, nbf/iat in [`payload`]  |
//! | 8    | project to AttestedIdentity                        | [`build_attested_identity`] — SDK fields + selectors   |
//! | 9    | return Ok                                          | trailing                                               |
//!
//! Steps 1, 2, 4, 5, 6, and the SDK-covered part of 7 happen inside
//! one [`spiffe::JwtSvid::parse_and_validate`] call. Steps 7d–7e
//! (`nbf`/`iat`) and the spec's clock-skew tolerance live here
//! because the SDK does not check those by design (it documents this
//! in its `parse_and_validate` "Validation Policy" note).

use crate::config::SpiffeConfig;
use crate::error::map_spiffe_error;
use crate::payload::decode_extra_claims;
use crate::source::BundleCache;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use yutha_attestor::{AttestationContext, AttestedIdentity, Attestor, AttestorError};
use yutha_core::Timestamp;

/// Maximum number of `selectors` entries projected into the
/// [`AttestedIdentity::attributes`] map. Per `attestor-spiffe.md` §8.1.
const MAX_SELECTOR_ENTRIES: usize = 64;

/// Maximum total bytes (sum of key.len() + value.len()) of the
/// projected selectors. Per `attestor-spiffe.md` §8.1.
const MAX_SELECTOR_BYTES: usize = 4 * 1024;

/// `Attestor` implementation that verifies SPIFFE JWT-SVIDs against a
/// configured trust bundle.
///
/// See the crate-level docs for the overall posture; see
/// [`SpiffeAttestor::connect`] for the construction flow; see the
/// module-level docs above for the verify-algorithm walkthrough.
#[derive(Debug)]
pub struct SpiffeAttestor {
    /// Operator-configured audience the SVID's `aud` claim MUST
    /// contain. Cached at connect time; never changes for the life of
    /// the process.
    expected_audience: String,

    /// Clock-skew tolerance for `iat`/`nbf` claims, in seconds.
    /// Cached at connect time. Verify path uses this in steps 7d–7e
    /// (since the SDK does not check `nbf`/`iat` and does not apply
    /// clock skew).
    clock_skew_tolerance: Duration,

    /// Bounded-staleness window for the trust-bundle cache.
    /// `None` means the source-default policy applies (see
    /// `attestor-spiffe.md` §5).
    max_staleness: Option<Duration>,

    /// Trust-bundle cache + staleness watchdog. Constructed once in
    /// `connect`. The verify path runs
    /// [`BundleCache::assert_fresh`] explicitly (step 3) and then
    /// passes `&self.cache` to
    /// [`spiffe::JwtSvid::parse_and_validate`] via the
    /// `BundleSource` trait impl in `source.rs` (steps 4 + 5).
    cache: BundleCache,
}

impl SpiffeAttestor {
    /// Connect to the configured trust-bundle source, fetch the
    /// initial bundle, and return a ready-to-use `SpiffeAttestor`.
    ///
    /// See the spec memo's §4 and the [`crate::TrustBundleSource`]
    /// docs for the per-source semantics. This entry point is the
    /// only public construction path; `--attestor spiffe` in the
    /// control-plane CLI calls through here.
    ///
    /// # Errors
    ///
    /// - [`AttestorError::Internal`] for [`SpiffeConfig::validate`]
    ///   failures (empty audience, zero timeout).
    /// - [`AttestorError::TrustRootUnavailable`] for source-side
    ///   construction failures: static-file read errors, JWKS shape
    ///   issues, Workload-API connect / initial-sync failures.
    /// - [`AttestorError::Malformed`] for static-file JSON shape
    ///   errors (missing `trust_domain`, missing/empty `keys`).
    pub async fn connect(config: SpiffeConfig) -> Result<Self, AttestorError> {
        config.validate()?;

        let cache = BundleCache::connect(&config).await?;

        tracing::info!(
            source = config.source.tag(),
            audience = %config.expected_audience,
            "yutha-attestor-spiffe connected"
        );

        Ok(Self {
            expected_audience: config.expected_audience,
            clock_skew_tolerance: Duration::from_secs(config.clock_skew_tolerance_secs),
            max_staleness: config.max_staleness,
            cache,
        })
    }
}

#[async_trait]
impl Attestor for SpiffeAttestor {
    fn id(&self) -> &str {
        "spiffe"
    }

    /// Verify a SPIFFE JWT-SVID against the cached trust bundle.
    ///
    /// Runs the 9-step algorithm pinned by
    /// [`attestor-spiffe.md` §3](../../../spec/identity-keys/attestor-spiffe.md#3-verification-algorithm).
    /// See this module's top-level doc for the step-to-code mapping.
    ///
    /// # Errors
    ///
    /// See [`crate::map_spiffe_error`] for the
    /// [`spiffe::JwtSvidError`] → [`AttestorError`] mapping, and
    /// `attestor-spiffe.md` §9 for the canonical message-shape
    /// table. The `_context` arg is currently unused — the
    /// passport's self-signature (verified by the admission handler
    /// before `verify` is called) plus the SVID's audience binding
    /// provide the key-binding proof per spec §3.1.
    async fn verify(
        &self,
        _context: &AttestationContext,
        credential: &[u8],
    ) -> Result<AttestedIdentity, AttestorError> {
        // ── Step 0: empty credential check ────────────────────────
        if credential.is_empty() {
            return Err(AttestorError::Rejected(
                "empty credential; SPIFFE Attestor requires a JWT-SVID".to_string(),
            ));
        }

        // The credential is the raw JWS compact serialization (ASCII
        // bytes). Convert to &str up front; non-UTF-8 is structurally
        // not a JWS.
        let token = std::str::from_utf8(credential)
            .map_err(|_| AttestorError::Malformed("credential is not valid UTF-8".to_string()))?;

        // ── Step 3: bounded-staleness check (BEFORE signature verify) ──
        // Spec §3 explicitly: "Step 3 before step 5 because the
        // bundle snapshot is the slower path on cold-cache cases;
        // failing fast on TrustRootUnavailable avoids spending CPU
        // on a JWS verify that will be discarded."
        self.cache.assert_fresh(self.max_staleness)?;

        // ── Steps 1, 2, 4, 5, 6, partial 7: delegate to SDK ───────
        // JwtSvid::parse_and_validate does:
        //   - JWS compact parse + base64url decode (steps 1, 6)
        //   - header alg + typ + kid validation (step 2)
        //   - bundle lookup via our BundleSource impl (step 4)
        //   - JWS signature verify via jsonwebtoken backend (step 5)
        //   - sub well-formed + trust-domain-in-bundle (step 7a, 7b)
        //   - aud contains expected_audience (step 7c)
        //   - exp > now() (step 7d) — NO clock-skew leeway, per spec
        let svid = spiffe::JwtSvid::parse_and_validate(
            token,
            &self.cache,
            &[self.expected_audience.as_str()],
        )
        .map_err(map_spiffe_error)?;

        // ── Steps 7e–7f: nbf + iat with clock-skew tolerance ──────
        // The SDK doesn't check these (its docs are explicit). We
        // decode the payload ourselves to get the raw `nbf`/`iat`
        // and the `selectors` claim that step 8 projects.
        let extra = decode_extra_claims(token)?;

        let now_unix = current_unix_secs();
        let tolerance = i64::try_from(self.clock_skew_tolerance.as_secs()).unwrap_or(i64::MAX);

        if let Some(nbf) = extra.nbf {
            if nbf > now_unix.saturating_add(tolerance) {
                return Err(AttestorError::Rejected("nbf in the future".to_string()));
            }
        }
        if let Some(iat) = extra.iat {
            if iat > now_unix.saturating_add(tolerance) {
                return Err(AttestorError::Rejected("iat in the future".to_string()));
            }
        }

        // ── Step 8: project to AttestedIdentity ───────────────────
        build_attested_identity(&svid, extra.selectors)
    }
}

/// Project the verified SVID + extracted `selectors` into the trait's
/// [`AttestedIdentity`] return type.
///
/// `external_identity` is the SPIFFE ID as a canonical
/// `spiffe://<trust-domain>/<path>` string (spec §7);
/// `credential_expires_at` is the `exp` claim rendered as an RFC 3339
/// wall-clock; `attributes` is the spec §8 projection of `selectors`.
fn build_attested_identity(
    svid: &spiffe::JwtSvid,
    selectors: Option<BTreeMap<String, String>>,
) -> Result<AttestedIdentity, AttestorError> {
    let external_identity = svid.spiffe_id().to_string();

    let expires_at = offset_datetime_to_timestamp(svid.expiry())?;

    let attributes = selectors.map(project_selectors).unwrap_or_default();

    Ok(AttestedIdentity {
        external_identity,
        credential_expires_at: Some(expires_at),
        attributes,
    })
}

/// Apply spec §8 caps: ≤ 64 entries, ≤ 4 KiB total key+value bytes.
/// Truncates with a warning log when either cap is hit.
fn project_selectors(selectors: BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut total_bytes: usize = 0;
    let mut truncated = false;

    for (k, v) in selectors {
        if out.len() >= MAX_SELECTOR_ENTRIES {
            truncated = true;
            break;
        }
        let entry_bytes = k.len().saturating_add(v.len());
        if total_bytes.saturating_add(entry_bytes) > MAX_SELECTOR_BYTES {
            truncated = true;
            break;
        }
        total_bytes = total_bytes.saturating_add(entry_bytes);
        out.insert(k, v);
    }

    if truncated {
        tracing::warn!(
            entries_kept = out.len(),
            bytes_kept = total_bytes,
            "yutha-attestor-spiffe: selectors projection truncated to \
             stay within spec §8.1 caps ({MAX_SELECTOR_ENTRIES} entries / \
             {MAX_SELECTOR_BYTES} bytes); some selectors did not land in \
             the agent.register evidence"
        );
    }
    out
}

/// Convert a `time::OffsetDateTime` (what `JwtSvid::expiry` returns)
/// into a Yutha [`Timestamp`]. The `monotonic_ns` field is set to 0
/// because the input is an external wall-clock instant; per
/// `Timestamp`'s contract, cross-process consumers compare wall_clock
/// via the `wall_at_or_after` / `wall_after` helpers, not
/// `monotonic_ns`.
fn offset_datetime_to_timestamp(dt: time::OffsetDateTime) -> Result<Timestamp, AttestorError> {
    let wall_clock = dt.format(&Rfc3339).map_err(|e| {
        AttestorError::Internal(format!("could not format JWT exp as RFC 3339: {e}"))
    })?;
    Timestamp::new(wall_clock, 0).map_err(|e| {
        AttestorError::Internal(format!("could not construct Timestamp from JWT exp: {e}"))
    })
}

/// Unix-time `now()` as `i64` seconds. Saturates to `0` on the
/// vanishingly-rare case of clock skew below the Unix epoch.
fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::TrustBundleSource;
    use std::io::Write;
    use std::path::PathBuf;

    /// Per-call unique temp path. Cargo runs tests in this module
    /// concurrently; a process-id-only filename collides + races with
    /// per-test teardown. An atomic counter disambiguates.
    fn write_temp_bundle() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let body = serde_json::json!({
            "trust_domain": "example.org",
            "keys": [{
                "kty": "EC",
                "kid": "test-key-1",
                "crv": "P-256",
                "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
                "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
            }]
        });
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "yutha-attestor-spiffe-attestor-test-{}-{}.json",
            std::process::id(),
            unique,
        ));
        let mut f = std::fs::File::create(&path).expect("temp file create");
        f.write_all(serde_json::to_vec(&body).expect("ser").as_slice())
            .expect("write");
        path
    }

    fn baseline_config_for(path: PathBuf) -> SpiffeConfig {
        SpiffeConfig {
            source: TrustBundleSource::StaticFile { path },
            expected_audience: "yutha-test".to_string(),
            max_staleness: None,
            clock_skew_tolerance_secs: 60,
            connect_timeout_secs: 10,
        }
    }

    #[tokio::test]
    async fn connect_validates_config() {
        let path = write_temp_bundle();
        let mut cfg = baseline_config_for(path.clone());
        cfg.expected_audience.clear();
        let err = SpiffeAttestor::connect(cfg)
            .await
            .expect_err("connect must reject empty audience");
        assert!(matches!(err, AttestorError::Internal(_)));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn connect_accepts_baseline_with_real_static_file() {
        let path = write_temp_bundle();
        let attestor = SpiffeAttestor::connect(baseline_config_for(path.clone()))
            .await
            .expect("baseline config + real bundle must connect");
        assert_eq!(attestor.id(), "spiffe");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn connect_surfaces_missing_static_file() {
        let cfg = baseline_config_for(PathBuf::from("/nonexistent/does-not-exist.json"));
        let err = SpiffeAttestor::connect(cfg)
            .await
            .expect_err("missing file must fail connect");
        assert!(matches!(err, AttestorError::TrustRootUnavailable(_)));
    }

    #[tokio::test]
    async fn verify_rejects_empty_credential() {
        let path = write_temp_bundle();
        let attestor = SpiffeAttestor::connect(baseline_config_for(path.clone()))
            .await
            .expect("connect");

        use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};
        let context = AttestationContext {
            swarm_id: SwarmId::new(),
            claimed_agent_id: AgentId::new(),
            agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])
                .expect("32-byte pk"),
        };

        let err = attestor
            .verify(&context, b"")
            .await
            .expect_err("empty credential must be rejected");
        match err {
            AttestorError::Rejected(msg) => {
                assert!(
                    msg.contains("empty credential"),
                    "spec-pinned message shape; got: {msg}"
                )
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn verify_rejects_non_utf8_credential() {
        let path = write_temp_bundle();
        let attestor = SpiffeAttestor::connect(baseline_config_for(path.clone()))
            .await
            .expect("connect");

        use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};
        let context = AttestationContext {
            swarm_id: SwarmId::new(),
            claimed_agent_id: AgentId::new(),
            agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])
                .expect("32-byte pk"),
        };

        // 0x80 is an invalid first byte for a UTF-8 sequence.
        let err = attestor
            .verify(&context, &[0x80, 0x80, 0x80])
            .await
            .expect_err("non-utf8 must be malformed");
        assert!(matches!(err, AttestorError::Malformed(_)));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn verify_rejects_garbled_token_as_malformed() {
        let path = write_temp_bundle();
        let attestor = SpiffeAttestor::connect(baseline_config_for(path.clone()))
            .await
            .expect("connect");

        use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};
        let context = AttestationContext {
            swarm_id: SwarmId::new(),
            claimed_agent_id: AgentId::new(),
            agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])
                .expect("32-byte pk"),
        };

        // Valid UTF-8 but not a 3-part JWS.
        let err = attestor
            .verify(&context, b"this.is.not.a.real.jwt")
            .await
            .expect_err("garbled token must be malformed");
        // Could be Malformed (parse fail) or Rejected (auth not found
        // if it parsed past the format check). The point is it MUST
        // NOT be Ok and MUST NOT panic.
        assert!(matches!(
            err,
            AttestorError::Malformed(_) | AttestorError::Rejected(_)
        ));
        let _ = std::fs::remove_file(path);
    }

    // --- Selector projection caps ---

    #[test]
    fn project_selectors_under_caps_round_trips() {
        let mut input = BTreeMap::new();
        input.insert("k8s_ns".to_string(), "billing".to_string());
        input.insert("k8s_sa".to_string(), "processor".to_string());

        let out = project_selectors(input.clone());
        assert_eq!(out, input);
    }

    #[test]
    fn project_selectors_truncates_at_entry_cap() {
        let mut input = BTreeMap::new();
        for i in 0..MAX_SELECTOR_ENTRIES + 10 {
            input.insert(format!("k{i:03}"), format!("v{i:03}"));
        }
        let out = project_selectors(input);
        assert_eq!(out.len(), MAX_SELECTOR_ENTRIES);
    }

    #[test]
    fn project_selectors_truncates_at_byte_cap() {
        let mut input = BTreeMap::new();
        // 100-byte keys + 100-byte values × 30 entries = 6000 bytes,
        // past the 4 KiB cap.
        for i in 0..30 {
            input.insert("k".repeat(100) + &i.to_string(), "v".repeat(100));
        }
        let out = project_selectors(input);
        let total: usize = out.iter().map(|(k, v)| k.len() + v.len()).sum();
        assert!(
            total <= MAX_SELECTOR_BYTES,
            "byte-cap must hold post-projection: {total}"
        );
    }

    // --- Timestamp conversion ---

    #[test]
    fn offset_datetime_to_timestamp_produces_rfc3339() {
        // Roundtrip rather than hand-computing a Unix value: pick
        // any post-epoch instant, convert to Timestamp, and assert
        // the wall_clock parses back to the same OffsetDateTime.
        let unix = 1_768_465_845_i64;
        let dt = time::OffsetDateTime::from_unix_timestamp(unix).unwrap();
        let ts = offset_datetime_to_timestamp(dt).expect("converts");

        // monotonic_ns is intentionally 0 for external timestamps —
        // see fn docs.
        assert_eq!(ts.monotonic_ns, 0);

        // Wall-clock must roundtrip cleanly through RFC 3339.
        let parsed = time::OffsetDateTime::parse(&ts.wall_clock, &Rfc3339)
            .expect("wall_clock must be valid RFC 3339");
        assert_eq!(parsed.unix_timestamp(), unix);
    }

    #[test]
    fn current_unix_secs_is_post_2026() {
        // Sanity check: we ran this test AFTER the Unix epoch, by a
        // long way. The exact value depends on the test's wall clock.
        let now = current_unix_secs();
        assert!(now > 1_700_000_000, "now={now} should be past 2023");
    }
}
