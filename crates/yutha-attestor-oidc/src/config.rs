//! Construction-time configuration for [`OidcAttestor`].
//!
//! Mirrors the operator-visible CLI flags pinned in
//! [`/spec/identity-keys/attestor-oidc.md` §10](../../../../spec/identity-keys/attestor-oidc.md#10-cli-flag-surface).
//! Field-by-field defaults are documented inline; [`OidcConfig::validate`]
//! is the single place that fails-fast on operator misconfiguration.
//!
//! [`OidcAttestor`]: crate::OidcAttestor

use yutha_attestor::AttestorError;

use crate::source::JwksSource;

/// Configuration for [`OidcAttestor`].
///
/// Construct via the struct-literal form (every field is `pub`), then
/// either let [`OidcAttestor::connect`] validate at construction or call
/// [`OidcConfig::validate`] explicitly during a config-validation phase.
///
/// All fields correspond 1:1 to a `--attestor-oidc-*` flag on the
/// `yutha-control-plane` binary; see the spec's §10 for canonical
/// defaults and validation rules.
///
/// [`OidcAttestor`]: crate::OidcAttestor
/// [`OidcAttestor::connect`]: crate::OidcAttestor::connect
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Which JWKS source flavour the Attestor reads from.
    /// See [`JwksSource`] for the three modes.
    pub source: JwksSource,

    /// The IdP's issuer URL, exactly as it appears in the `iss` claim of
    /// minted ID tokens. The spec's §3 step 7 enforces string-equal
    /// against this value. In Discovery mode (§4.1), the discovery-doc
    /// `issuer` field is ALSO checked against this value at construction
    /// (spec §6.3, RFC 8414 §3.3).
    ///
    /// Examples:
    /// - Auth0: `https://<tenant>.auth0.com/` (trailing slash matters)
    /// - Okta: `https://<org>.okta.com`
    /// - Google: `https://accounts.google.com`
    /// - Keycloak: `https://<host>/realms/<realm>`
    /// - Azure AD: `https://login.microsoftonline.com/<tenant-id>/v2.0`
    ///
    /// Copy from the IdP's discovery doc; do not normalize.
    pub expected_issuer: String,

    /// The audience value Yutha is registered as in the IdP. The Attestor
    /// rejects any ID token whose `aud` claim does not contain this
    /// exact value. See spec §6.1 for naming guidance — production
    /// `yutha-<swarm-name>-<env>` is the recommended shape; generic
    /// values like `yutha-prod` invite cross-system replay.
    pub expected_audience: String,

    /// Allow-list of JWS `alg` header values. The spec's §2.1 default
    /// is `["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"]`.
    /// `none` and `HS*` are silently filtered out of this list at
    /// validation time (they are architecturally disallowed — see spec
    /// §2.1 for the HMAC rationale).
    pub allowed_algs: Vec<String>,

    /// ID-token claims to project into [`AttestedIdentity::attributes`].
    /// Default empty (no projection). See spec §8.1 for value-handling
    /// rules (string → verbatim, array-of-string → comma-joined,
    /// other shapes → skipped with warning).
    ///
    /// [`AttestedIdentity::attributes`]: yutha_attestor::AttestedIdentity::attributes
    pub project_claims: Vec<String>,

    /// JWKS cache TTL in seconds. Default 3600 (1 h). Minimum 60 — the
    /// validator rejects shorter values to avoid hammering the IdP.
    /// Spec §5.1; ignored for the static-file source.
    pub cache_ttl_secs: u64,

    /// Maximum staleness window in seconds before the Attestor stops
    /// serving from a stale cache.
    /// - `None` → discovery / JWKS-URI default of 86400 (24 h); static
    ///   file default of `Duration::MAX` (no staleness check).
    /// - `Some(0)` → hard fail on TTL expiry (strictest policy).
    /// - `Some(n)` for `n > cache_ttl_secs` → degrade gracefully if the
    ///   IdP is briefly unreachable; reject past `n` seconds.
    ///
    /// Spec §5.1.
    pub max_staleness_secs: Option<u64>,

    /// Clock-skew tolerance applied to `iat` and `nbf` checks, in
    /// seconds. Default 60. Spec §3 step 7. Must be non-negative.
    pub clock_skew_tolerance_secs: u64,

    /// Cold-start connect timeout for the discovery-doc fetch and the
    /// initial JWKS fetch, in seconds. Default 10. Ignored for the
    /// static-file source.
    pub connect_timeout_secs: u64,

    /// Permit HTTP (not just HTTPS) URLs for issuer + JWKS endpoints.
    /// Default `false`. Setting to `true` violates OpenID Connect Core
    /// §2 ("Communication ... MUST utilize TLS") and emits a startup
    /// warning. The flag exists for the F7 in-process mock-OIDC test
    /// server and local-developer Keycloak/dex setups.
    pub allow_insecure_http: bool,
}

impl OidcConfig {
    /// Validate the configuration. Returns the first error encountered
    /// (does not collect all problems — operators see one fix at a time).
    ///
    /// `OidcAttestor::connect` calls this internally; operators can also
    /// call it during a config-parsing phase to fail fast before the
    /// async runtime is up.
    pub fn validate(&self) -> Result<(), AttestorError> {
        if self.expected_issuer.is_empty() {
            return Err(AttestorError::Internal(
                "OidcConfig: expected_issuer must not be empty".to_string(),
            ));
        }

        if !self.allow_insecure_http && !self.expected_issuer.starts_with("https://") {
            return Err(AttestorError::Internal(format!(
                "OidcConfig: expected_issuer must be HTTPS unless \
                 allow_insecure_http is set (got: {} — pass \
                 --attestor-oidc-allow-insecure-http for the F7 mock-OIDC \
                 server or local IdPs)",
                redact_url(&self.expected_issuer),
            )));
        }

        if self.expected_audience.is_empty() {
            return Err(AttestorError::Internal(
                "OidcConfig: expected_audience must not be empty".to_string(),
            ));
        }

        if self.allowed_algs.is_empty() {
            return Err(AttestorError::Internal(
                "OidcConfig: allowed_algs must not be empty (default is \
                 RS256, RS384, RS512, ES256, ES384, EdDSA — see spec §2.1)"
                    .to_string(),
            ));
        }

        // HS* and `none` are architecturally disallowed per spec §2.1.
        // Catch operator-provided values early at config time rather than
        // surfacing as a per-credential Malformed reject later.
        for alg in &self.allowed_algs {
            let upper = alg.to_ascii_uppercase();
            if upper == "NONE" || upper == "HS256" || upper == "HS384" || upper == "HS512" {
                return Err(AttestorError::Internal(format!(
                    "OidcConfig: alg {alg:?} is architecturally disallowed \
                     (HMAC requires shared-secret distribution that breaks \
                     the OIDC trust model; `none` is never accepted). \
                     Remove from allowed_algs."
                )));
            }
        }

        if self.cache_ttl_secs < 60 {
            return Err(AttestorError::Internal(format!(
                "OidcConfig: cache_ttl_secs must be at least 60 (got {})",
                self.cache_ttl_secs,
            )));
        }

        // `clock_skew_tolerance_secs` is u64 so non-negative by type.
        // Upper-bound sanity: > 1 day skew is almost certainly a bug.
        if self.clock_skew_tolerance_secs > 86_400 {
            return Err(AttestorError::Internal(format!(
                "OidcConfig: clock_skew_tolerance_secs={} is unreasonably \
                 large (>1 day). Tighten to 60–300 unless you have a \
                 specific NTP situation",
                self.clock_skew_tolerance_secs,
            )));
        }

        self.source.validate(self.allow_insecure_http)?;
        Ok(())
    }
}

/// Strip the path + query off a URL so error messages don't leak issuer
/// path components that might encode tenant identifiers. Used for the
/// occasional config-error message that has to mention the URL.
fn redact_url(url: &str) -> String {
    match url.find("://").and_then(|i| {
        let rest = &url[i + 3..];
        rest.find('/').map(|j| &url[..i + 3 + j])
    }) {
        Some(scheme_and_host) => format!("{scheme_and_host}/<redacted-path>"),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn happy() -> OidcConfig {
        OidcConfig {
            source: JwksSource::Discovery {
                issuer_url: "https://login.example.com".to_string(),
            },
            expected_issuer: "https://login.example.com".to_string(),
            expected_audience: "yutha-test".to_string(),
            allowed_algs: vec!["RS256".into(), "ES256".into()],
            project_claims: vec![],
            cache_ttl_secs: 3600,
            max_staleness_secs: Some(86_400),
            clock_skew_tolerance_secs: 60,
            connect_timeout_secs: 10,
            allow_insecure_http: false,
        }
    }

    #[test]
    fn happy_path_validates() {
        happy().validate().expect("happy config validates");
    }

    #[test]
    fn empty_issuer_rejected() {
        let mut c = happy();
        c.expected_issuer = String::new();
        let err = c.validate().unwrap_err();
        assert!(matches!(err, AttestorError::Internal(_)));
    }

    #[test]
    fn http_issuer_rejected_without_escape_hatch() {
        let mut c = happy();
        c.expected_issuer = "http://login.example.com".to_string();
        c.source = JwksSource::Discovery {
            issuer_url: c.expected_issuer.clone(),
        };
        let err = c.validate().unwrap_err();
        assert!(matches!(err, AttestorError::Internal(_)));
    }

    #[test]
    fn http_issuer_allowed_with_escape_hatch() {
        let mut c = happy();
        c.expected_issuer = "http://localhost:9090".to_string();
        c.source = JwksSource::Discovery {
            issuer_url: c.expected_issuer.clone(),
        };
        c.allow_insecure_http = true;
        c.validate().expect("escape hatch permits http");
    }

    #[test]
    fn empty_audience_rejected() {
        let mut c = happy();
        c.expected_audience = String::new();
        let err = c.validate().unwrap_err();
        assert!(matches!(err, AttestorError::Internal(_)));
    }

    #[test]
    fn hmac_in_allowlist_rejected_at_config_time() {
        let mut c = happy();
        c.allowed_algs = vec!["RS256".into(), "HS256".into()];
        let err = c.validate().unwrap_err();
        assert!(matches!(err, AttestorError::Internal(_)));
    }

    #[test]
    fn alg_none_rejected_at_config_time() {
        let mut c = happy();
        c.allowed_algs = vec!["RS256".into(), "none".into()];
        let err = c.validate().unwrap_err();
        assert!(matches!(err, AttestorError::Internal(_)));
    }

    #[test]
    fn cache_ttl_too_low_rejected() {
        let mut c = happy();
        c.cache_ttl_secs = 30;
        let err = c.validate().unwrap_err();
        assert!(matches!(err, AttestorError::Internal(_)));
    }

    #[test]
    fn static_file_source_validates() {
        let mut c = happy();
        c.source = JwksSource::StaticFile {
            path: PathBuf::from("/etc/yutha/oidc-jwks.json"),
        };
        c.validate().expect("static-file source validates");
    }

    #[test]
    fn jwks_uri_override_validates() {
        let mut c = happy();
        c.source = JwksSource::JwksUri {
            url: "https://login.example.com/custom-jwks".to_string(),
        };
        c.validate().expect("jwks-uri override validates");
    }
}
