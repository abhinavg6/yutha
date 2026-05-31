//! [`OidcAttestor`] — the [`Attestor`] impl for OpenID Connect ID tokens.
//!
//! As of **F4+F5 (this commit)** the verify body is live: it implements
//! the 9-step algorithm pinned in
//! [`/spec/identity-keys/attestor-oidc.md` §3](../../../../spec/identity-keys/attestor-oidc.md#3-verification-algorithm),
//! delegating signature + iss/aud/exp/nbf checks to
//! [`jsonwebtoken::decode`] (steps 5 + most of 7), with our own
//! pre-checks for empty credential / header / kid (steps 0-2),
//! cache freshness + lookup (steps 3-4), manual `iat` check (the
//! one library doesn't do), and AttestedIdentity construction
//! (step 8). Error mapping per spec §9 lives in [`crate::error`].
//!
//! [`Attestor`]: yutha_attestor::Attestor

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, TokenData, Validation};
use serde_json::Value;
use yutha_attestor::{AttestationContext, AttestedIdentity, Attestor, AttestorError};
use yutha_core::Timestamp;

use crate::config::OidcConfig;
use crate::error::map_oidc_error;
use crate::jwks_cache::JwksCache;
use crate::payload::project_allowlisted_claims;

/// OpenID Connect Attestor.
///
/// Verifies OIDC ID tokens against a configured JWKS and returns
/// `oidc:<iss>:<sub>` as the attested external identity. Construct via
/// [`OidcAttestor::connect`].
#[derive(Debug)]
pub struct OidcAttestor {
    /// The full config — read by [`Self::verify`] every call to
    /// consult `expected_issuer`, `expected_audience`, `allowed_algs`,
    /// `project_claims`, and `clock_skew_tolerance_secs`.
    config: OidcConfig,
    /// JWKS cache warmed at `connect()` time. Cloneable share-state
    /// behind `Arc`; cheap to hand to background-refresh tasks.
    cache: JwksCache,
}

impl OidcAttestor {
    /// Construct an attestor by validating the config and warming the
    /// JWKS cache.
    ///
    /// Steps at construction:
    /// 1. [`OidcConfig::validate`] — fails fast on operator
    ///    misconfiguration (empty issuer, HMAC in allowlist, etc.).
    /// 2. [`JwksCache::warm`] — fetches the initial JWKS via the
    ///    configured [`JwksSource`]:
    ///    - **Discovery:** GETs `<issuer>/.well-known/openid-configuration`,
    ///      validates the doc's `issuer` field exact-matches
    ///      `expected_issuer` per spec §6.3, then GETs the discovery
    ///      doc's `jwks_uri`.
    ///    - **JwksUri:** GETs the operator-provided URL directly.
    ///    - **StaticFile:** reads + parses the file from disk.
    /// 3. Returns `Self { config, cache }`.
    ///
    /// Any of the steps above failing returns an `AttestorError`; the
    /// control plane refuses to start (this matches the SPIFFE
    /// Attestor's connect-fatal posture from Phase E).
    ///
    /// [`JwksSource`]: crate::JwksSource
    pub async fn connect(config: OidcConfig) -> Result<Self, AttestorError> {
        config.validate()?;
        let cache = JwksCache::warm(
            config.source.clone(),
            &config.expected_issuer,
            config.cache_ttl_secs,
            config.max_staleness_secs,
            config.connect_timeout_secs,
        )
        .await?;
        Ok(Self { config, cache })
    }

    /// Test/inspection: how many keys did warm-up load.
    #[cfg(test)]
    pub(crate) async fn cache_key_count(&self) -> usize {
        self.cache.key_count().await
    }
}

#[async_trait]
impl Attestor for OidcAttestor {
    fn id(&self) -> &str {
        "oidc"
    }

    /// Verify an OIDC ID token per spec §3.
    ///
    /// Algorithm (step numbers match the spec):
    ///
    /// 0. Empty credential check.
    /// 1. JWS compact-serialization parse via [`decode_header`].
    /// 2. Header validation: `kid` required, `alg` in operator
    ///    allow-list (config.validate already filtered HS* + `none`).
    /// 3. [`JwksCache::assert_fresh`] (might fire a background TTL
    ///    refresh; doesn't block).
    /// 4. [`JwksCache::lookup`] (blocking kid-miss refresh + retry).
    /// 5+7-partial. [`jsonwebtoken::decode`] does the signature
    ///    verify AND iss/aud/exp/nbf claim checks in one shot (the
    ///    `Validation` struct configures all four).
    /// 6. Payload is already `serde_json::Value` from `decode`'s
    ///    deserialize — no separate step.
    /// 7-tail. Manual `iat` check (jsonwebtoken doesn't validate iat).
    /// 8. Project to `AttestedIdentity`: `external_identity =
    ///    "oidc:<iss>:<sub>"`, `credential_expires_at = exp` rendered
    ///    as RFC 3339, `attributes` per `payload::project_allowlisted_claims`.
    /// 9. Return Ok.
    ///
    /// # Spec-deviation note
    ///
    /// Spec §3 step 7 lists claim-check sub-ordering as
    /// `iss → sub → aud → exp → iat → nbf`. `jsonwebtoken::decode`
    /// checks them in library order (signature → exp → nbf → iss →
    /// aud). The security-critical "signature before claims"
    /// invariant (step 5 before step 7) IS preserved. The sub-
    /// ordering of claim-failure messages is a UX consideration that
    /// the library's order also handles reasonably (operators see
    /// "credential expired" first when both exp and iss are wrong,
    /// which is the more actionable diagnostic). Re-evaluate if a
    /// specific operator workflow needs the spec's exact sub-order.
    async fn verify(
        &self,
        _context: &AttestationContext,
        credential: &[u8],
    ) -> Result<AttestedIdentity, AttestorError> {
        // ---------------------------------------------------------------
        // Step 0: empty credential check.
        // ---------------------------------------------------------------
        if credential.is_empty() {
            return Err(AttestorError::Rejected(
                "empty credential; OIDC Attestor requires an ID token".to_string(),
            ));
        }

        // The credential MUST be a UTF-8 JWS compact serialization.
        // We treat any non-UTF-8 input as a JWS parse failure (it
        // can't be a base64url-encoded JWT either way).
        let token = std::str::from_utf8(credential)
            .map_err(|_| AttestorError::Malformed("not a JWS compact serialization".to_string()))?;

        // ---------------------------------------------------------------
        // Step 1: parse the JWS header. Catches the most common
        // "not a JWT" failures (missing dots, bad base64, bad JSON
        // in the header segment) before we touch any cache state.
        // ---------------------------------------------------------------
        let header = decode_header(token).map_err(map_oidc_error)?;

        // ---------------------------------------------------------------
        // Step 2: header validation per spec §2.1.
        //   - `kid` is required (strict mode; spec §2.1.1 documents
        //     why we don't auto-pick from a single-key JWKS).
        //   - `typ`, if present, MUST be "JWT" or "JOSE".
        //   - `alg` MUST be in the operator-configured allow-list.
        //     config.validate() already filtered HS* + `none` from
        //     allowed_algs at startup, so any alg in allowed_algs is
        //     by construction asymmetric.
        // ---------------------------------------------------------------
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AttestorError::Malformed("header: missing kid".to_string()))?;

        if let Some(typ) = header.typ.as_deref() {
            // Case-insensitive per RFC 7519 / RFC 7515 conventions.
            if !typ.eq_ignore_ascii_case("JWT") && !typ.eq_ignore_ascii_case("JOSE") {
                return Err(AttestorError::Malformed(
                    "header: unsupported typ".to_string(),
                ));
            }
        }

        let alg_name = algorithm_name(header.alg);
        if !self
            .config
            .allowed_algs
            .iter()
            .any(|a| a.eq_ignore_ascii_case(alg_name))
        {
            return Err(AttestorError::Malformed(
                "header: unsupported alg".to_string(),
            ));
        }

        // ---------------------------------------------------------------
        // Step 3: cache freshness gate. Past TTL but within
        // max_staleness fires a background refresh (we continue);
        // past max_staleness returns TrustRootUnavailable.
        // ---------------------------------------------------------------
        self.cache.assert_fresh().await?;

        // ---------------------------------------------------------------
        // Step 4: JWKS lookup by kid. On miss, the cache kicks off a
        // deduplicated blocking refresh and retries the lookup once.
        // After that, a missing kid is genuinely unknown.
        // ---------------------------------------------------------------
        let jwk = self
            .cache
            .lookup(kid)
            .await?
            .ok_or_else(|| AttestorError::Rejected("kid not found in JWKS".to_string()))?;

        // ---------------------------------------------------------------
        // Steps 5 + 7-partial: signature verify + iss/aud/exp/nbf
        // claim checks in one `jsonwebtoken::decode` call.
        //
        // `Validation::new(header.alg)` restricts verify to this
        // exact algorithm (no negotiation; the JWKS key MUST sign
        // for the alg the header declared). We pre-screened the
        // alg against config.allowed_algs in step 2; here we're
        // pinning the per-call validator to that specific alg.
        // ---------------------------------------------------------------
        let mut validation = Validation::new(header.alg);
        validation.required_spec_claims.insert("iss".to_string());
        validation.required_spec_claims.insert("aud".to_string());
        // exp is already in `required_spec_claims` by default; iat is
        // not validated by jsonwebtoken (we do it manually post-decode).
        validation.set_issuer(&[&self.config.expected_issuer]);
        validation.set_audience(&[&self.config.expected_audience]);
        validation.leeway = self.config.clock_skew_tolerance_secs;
        validation.validate_nbf = true;

        let token_data: TokenData<Value> =
            decode::<Value>(token, &jwk.decoding_key, &validation).map_err(map_oidc_error)?;

        // ---------------------------------------------------------------
        // Step 6: payload is already `serde_json::Value` from decode.
        // ---------------------------------------------------------------
        let payload = token_data.claims;

        // ---------------------------------------------------------------
        // Step 7-tail: manual iat check (spec §3 step 7; jsonwebtoken
        // doesn't validate iat). Required per spec §2.2.
        // ---------------------------------------------------------------
        let iat = payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| AttestorError::Malformed("payload: missing/invalid iat".to_string()))?;
        let now_secs = current_unix_secs();
        if iat > now_secs.saturating_add(self.config.clock_skew_tolerance_secs as i64) {
            return Err(AttestorError::Rejected("iat in the future".to_string()));
        }

        // ---------------------------------------------------------------
        // Step 8: extract iss / sub / exp; build AttestedIdentity.
        //
        // iss is guaranteed present + non-empty (jsonwebtoken's
        // set_issuer + required_spec_claims check). We extract it
        // for the external_identity composite.
        //
        // sub is NOT validated by jsonwebtoken; we require it
        // non-empty per spec §2.2.
        //
        // exp is guaranteed present + > now (jsonwebtoken's default
        // exp check). We extract it for credential_expires_at.
        // ---------------------------------------------------------------
        let iss = payload
            .get("iss")
            .and_then(Value::as_str)
            .ok_or_else(|| AttestorError::Malformed("payload: missing iss".to_string()))?;
        let sub = payload
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AttestorError::Malformed("payload: sub empty or not a string".to_string())
            })?;
        let exp = payload
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(|| AttestorError::Malformed("payload: missing/invalid exp".to_string()))?;

        let external_identity = format!("oidc:{iss}:{sub}");
        let credential_expires_at = Some(unix_secs_to_timestamp(exp)?);
        let attributes = project_allowlisted_claims(&payload, &self.config.project_claims);

        // ---------------------------------------------------------------
        // Step 9: success.
        // ---------------------------------------------------------------
        Ok(AttestedIdentity {
            external_identity,
            credential_expires_at,
            attributes,
        })
    }
}

/// Stable string name for a `jsonwebtoken::Algorithm` variant.
/// Pinned by hand so a future jsonwebtoken bump that adds new
/// algorithm variants (or renames the Display format) doesn't
/// silently change the algorithm-allowlist matching semantics.
fn algorithm_name(alg: Algorithm) -> &'static str {
    use jsonwebtoken::Algorithm::*;
    match alg {
        HS256 => "HS256",
        HS384 => "HS384",
        HS512 => "HS512",
        ES256 => "ES256",
        ES384 => "ES384",
        RS256 => "RS256",
        RS384 => "RS384",
        RS512 => "RS512",
        PS256 => "PS256",
        PS384 => "PS384",
        PS512 => "PS512",
        EdDSA => "EdDSA",
    }
}

/// Convert a Unix-epoch-seconds integer (from a verified JWT `exp`
/// claim) into a [`yutha_core::Timestamp`].
///
/// Mirrors the SPIFFE crate's `offset_datetime_to_timestamp`. The
/// `monotonic_ns` field is set to `0` because we don't have a local
/// monotonic reading for an external-issuer timestamp; per
/// `Timestamp`'s contract, cross-process consumers compare
/// `wall_clock` and tolerate `monotonic_ns == 0`.
fn unix_secs_to_timestamp(exp_secs: i64) -> Result<Timestamp, AttestorError> {
    let dt = time::OffsetDateTime::from_unix_timestamp(exp_secs).map_err(|err| {
        AttestorError::Internal(format!(
            "could not construct OffsetDateTime from JWT exp: {err}"
        ))
    })?;
    let wall_clock = dt
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|err| {
            AttestorError::Internal(format!("RFC 3339 format failed for JWT exp: {err}"))
        })?;
    Timestamp::new(wall_clock, 0).map_err(|err| {
        AttestorError::Internal(format!("could not construct Timestamp from JWT exp: {err}"))
    })
}

/// Wall-clock now as Unix seconds. Saturates on SystemTime-before-
/// epoch (impossible in practice; the `unwrap_or(0)` makes the
/// branch explicit).
fn current_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::JwksSource;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};

    /// Two-key RSA JWKS body (same fixture jwks_cache + attestor F3
    /// tests use). The keys' n/e components come from Google's
    /// production JWKS — we only ever PARSE them; we never sign with
    /// the corresponding private keys (which we don't have).
    fn fixture_jwks_body() -> String {
        serde_json::json!({
            "keys": [
                {
                    "use": "sig", "kty": "RSA", "alg": "RS256", "kid": "kid-1",
                    "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                    "e": "AQAB",
                },
                {
                    "use": "sig", "kty": "RSA", "alg": "RS256", "kid": "kid-2",
                    "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
                    "e": "AQAB",
                }
            ]
        })
        .to_string()
    }

    fn temp_jwks() -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(fixture_jwks_body().as_bytes()).unwrap();
        f
    }

    fn static_file_config(path: &std::path::Path) -> OidcConfig {
        OidcConfig {
            source: JwksSource::StaticFile {
                path: path.to_path_buf(),
            },
            expected_issuer: "https://login.example.com".into(),
            expected_audience: "yutha-test".into(),
            allowed_algs: vec!["RS256".into()],
            project_claims: vec![],
            cache_ttl_secs: 3600,
            max_staleness_secs: None,
            clock_skew_tolerance_secs: 60,
            connect_timeout_secs: 10,
            allow_insecure_http: false,
        }
    }

    fn dummy_context() -> AttestationContext {
        AttestationContext {
            swarm_id: SwarmId::new(),
            claimed_agent_id: AgentId::new(),
            agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]).unwrap(),
        }
    }

    // -----------------------------------------------------------------
    // F4 negative-path tests. Positive-path tests (full sign + verify
    // round trip) land in F7 with the in-process mock OIDC server +
    // forged keypairs.
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_config_rejects_before_warming_cache() {
        let file = temp_jwks();
        let mut cfg = static_file_config(file.path());
        cfg.expected_audience = String::new();
        let err = OidcAttestor::connect(cfg).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected_audience"),
            "expected validate() error about empty audience; got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_connect_warms_cache() {
        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .expect("static-file connect succeeds against valid JWKS");
        assert_eq!(attestor.id(), "oidc");
        assert_eq!(attestor.cache_key_count().await, 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_credential_rejected() {
        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let err = attestor.verify(&dummy_context(), &[]).await.unwrap_err();
        match err {
            AttestorError::Rejected(msg) => {
                assert!(msg.contains("empty credential"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_jws_rejected() {
        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let err = attestor
            .verify(&dummy_context(), b"not.a.jwt")
            .await
            .unwrap_err();
        // "not.a.jwt" parses as base64url segments but the header
        // payload decode fails → Malformed.
        assert!(matches!(err, AttestorError::Malformed(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_utf8_credential_rejected_as_malformed() {
        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let bad_utf8: &[u8] = &[0xFF, 0xFE, 0xFD];
        let err = attestor
            .verify(&dummy_context(), bad_utf8)
            .await
            .unwrap_err();
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("not a JWS"));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn header_missing_kid_rejected() {
        // Forge a JWS with valid base64url segments but a header
        // lacking `kid`. Signature segment is junk — we never reach
        // signature verify because step 2 rejects on missing kid.
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = b64.encode(br#"{"sub":"x"}"#);
        let sig = b64.encode(b"junk-signature");
        let token = format!("{header}.{payload}.{sig}");

        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let err = attestor
            .verify(&dummy_context(), token.as_bytes())
            .await
            .unwrap_err();
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("missing kid"), "got: {msg}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn header_unsupported_typ_rejected() {
        // Forge a JWS whose header declares typ="foo" (not JWT/JOSE).
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"RS256","typ":"foo","kid":"kid-1"}"#);
        let payload = b64.encode(br#"{"sub":"x"}"#);
        let sig = b64.encode(b"junk");
        let token = format!("{header}.{payload}.{sig}");

        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let err = attestor
            .verify(&dummy_context(), token.as_bytes())
            .await
            .unwrap_err();
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("unsupported typ"), "got: {msg}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn header_typ_jose_accepted() {
        // typ=JOSE is allowed per spec §2.1. Use it; the kid+alg
        // check passes; signature verify fails (no valid sig) →
        // Rejected (not Malformed-from-typ).
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"RS256","typ":"JOSE","kid":"kid-1"}"#);
        let payload = b64.encode(
            br#"{"iss":"https://login.example.com","aud":"yutha-test","sub":"u","exp":9999999999,"iat":1700000000}"#,
        );
        let sig = b64.encode(b"junk");
        let token = format!("{header}.{payload}.{sig}");

        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let err = attestor
            .verify(&dummy_context(), token.as_bytes())
            .await
            .unwrap_err();
        // typ=JOSE accepted; we fail downstream at signature verify.
        match err {
            AttestorError::Rejected(msg) => {
                assert!(
                    !msg.contains("typ"),
                    "typ=JOSE should be accepted; got: {msg}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn header_alg_not_in_allowlist_rejected() {
        // Forge a JWS whose header declares ES256, but our allow-list
        // only permits RS256.
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"ES256","typ":"JWT","kid":"kid-1"}"#);
        let payload = b64.encode(br#"{"sub":"x"}"#);
        let sig = b64.encode(b"junk-signature");
        let token = format!("{header}.{payload}.{sig}");

        let file = temp_jwks();
        let mut cfg = static_file_config(file.path());
        cfg.allowed_algs = vec!["RS256".into()];
        let attestor = OidcAttestor::connect(cfg).await.unwrap();
        let err = attestor
            .verify(&dummy_context(), token.as_bytes())
            .await
            .unwrap_err();
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("unsupported alg"), "got: {msg}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kid_not_in_jwks_rejected() {
        // Forge a JWS whose header references a kid not present in
        // the static-file JWKS. The static-file source has no
        // refresh path, so a missing kid is `Rejected` immediately.
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"RS256","typ":"JWT","kid":"never-issued"}"#);
        let payload = b64.encode(br#"{"sub":"x"}"#);
        let sig = b64.encode(b"junk-signature");
        let token = format!("{header}.{payload}.{sig}");

        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let err = attestor
            .verify(&dummy_context(), token.as_bytes())
            .await
            .unwrap_err();
        match err {
            AttestorError::Rejected(msg) => {
                assert!(msg.contains("kid not found"), "got: {msg}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signature_verify_failure_rejected() {
        // Forge a JWS with a valid kid but a junk signature. Step 5
        // (signature verify) rejects.
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"RS256","typ":"JWT","kid":"kid-1"}"#);
        let payload = b64.encode(
            br#"{"iss":"https://login.example.com","aud":"yutha-test","sub":"u","exp":9999999999,"iat":1700000000}"#,
        );
        let sig = b64.encode(b"definitely-not-a-real-rsa-signature");
        let token = format!("{header}.{payload}.{sig}");

        let file = temp_jwks();
        let attestor = OidcAttestor::connect(static_file_config(file.path()))
            .await
            .unwrap();
        let err = attestor
            .verify(&dummy_context(), token.as_bytes())
            .await
            .unwrap_err();
        match err {
            AttestorError::Rejected(msg) => {
                assert!(msg.contains("signature"), "got: {msg}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // algorithm_name + unix_secs_to_timestamp lower-level checks
    // -----------------------------------------------------------------

    #[test]
    fn algorithm_name_covers_known_variants() {
        assert_eq!(algorithm_name(Algorithm::RS256), "RS256");
        assert_eq!(algorithm_name(Algorithm::ES256), "ES256");
        assert_eq!(algorithm_name(Algorithm::EdDSA), "EdDSA");
        assert_eq!(algorithm_name(Algorithm::HS256), "HS256");
    }

    #[test]
    fn unix_secs_to_timestamp_round_trip() {
        // 2026-01-01T00:00:00Z = 1767225600.
        let ts = unix_secs_to_timestamp(1_767_225_600).unwrap();
        assert!(
            ts.wall_clock.starts_with("2026-01-01"),
            "got wall_clock: {}",
            ts.wall_clock
        );
        assert_eq!(ts.monotonic_ns, 0);
    }
}
