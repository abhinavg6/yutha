//! Where the [`OidcAttestor`] reads its JWKS from.
//!
//! Three mutually-exclusive flavours per
//! [`/spec/identity-keys/attestor-oidc.md` §4](../../../../spec/identity-keys/attestor-oidc.md#4-jwks-sources).
//! The variant decides whether `OidcAttestor::connect` performs:
//! - a full OIDC discovery fetch (one HTTP call to the well-known
//!   endpoint + one to the linked JWKS URL),
//! - a direct JWKS-URL fetch (skipping discovery),
//! - or a local-file read (no network).
//!
//! [`OidcAttestor`]: crate::OidcAttestor

use std::path::PathBuf;

use yutha_attestor::AttestorError;

/// One of three JWKS source flavours.
///
/// Operators pick a flavour at startup via mutually-exclusive CLI flags
/// (spec §10); [`OidcAttestor::connect`] enforces the same exclusivity
/// at construction.
///
/// [`OidcAttestor::connect`]: crate::OidcAttestor::connect
#[derive(Debug, Clone)]
pub enum JwksSource {
    /// Standard OIDC Discovery. The Attestor fetches
    /// `<issuer_url>/.well-known/openid-configuration` at construction,
    /// validates the doc's `issuer` field exact-matches the operator's
    /// `expected_issuer` (spec §6.3), then fetches the JWKS at the
    /// discovery doc's `jwks_uri`. This is the default path operators
    /// should choose unless they have a specific reason not to.
    ///
    /// `issuer_url` is typically equal to `OidcConfig::expected_issuer`
    /// but is stored on the source so the discovery-fetch logic doesn't
    /// have to reach back into the wrapping config. The two are
    /// independent: the spec permits operators with non-trivial IdP
    /// proxies to point Discovery at a different host than the one the
    /// `iss` claim carries.
    Discovery {
        /// The OIDC-discovery base URL the Attestor fetches
        /// `/.well-known/openid-configuration` from.
        issuer_url: String,
    },

    /// JWKS-URI override. For IdPs whose discovery doc is misconfigured,
    /// missing, or hidden behind an authenticated endpoint, operators
    /// may bypass discovery by providing the JWKS URL directly. The
    /// discovery-doc `issuer` exact-match check (spec §6.3) is skipped
    /// in this mode; the `iss`-claim check (spec §3 step 7) still
    /// applies to every credential.
    ///
    /// Use sparingly — see spec §4.2 for the trade-off.
    JwksUri {
        /// The fully-qualified JWKS endpoint URL.
        url: String,
    },

    /// Static JWKS file. For air-gapped deployments or operators who
    /// want JWKS rotation to be a deliberate file-replace + restart.
    /// The Attestor reads the file once at construction; rotation
    /// requires writing a new file and restarting the control plane.
    /// No live fetches, no kid-miss refresh (a missing kid rejects
    /// immediately).
    ///
    /// Spec §4.3.
    StaticFile {
        /// Filesystem path to the JWKS JSON document.
        path: PathBuf,
    },
}

impl JwksSource {
    /// Validate source-flavour-specific invariants.
    ///
    /// - URLs must use HTTPS unless `allow_insecure_http` is set.
    /// - File paths must be non-empty (existence is checked at
    ///   construction time, not at config-validation time, so an
    ///   operator missing-file mistake fails with a clearer error from
    ///   the actual file-read).
    ///
    /// Cross-flavour mutual exclusion is enforced at the CLI layer
    /// (`AttestorArg::build` in `yutha-control-plane`); this method
    /// only checks the chosen variant's own invariants.
    pub fn validate(&self, allow_insecure_http: bool) -> Result<(), AttestorError> {
        match self {
            JwksSource::Discovery { issuer_url } => {
                check_url(issuer_url, allow_insecure_http, "Discovery issuer_url")
            }
            JwksSource::JwksUri { url } => check_url(url, allow_insecure_http, "JwksUri url"),
            JwksSource::StaticFile { path } => {
                if path.as_os_str().is_empty() {
                    return Err(AttestorError::Internal(
                        "JwksSource::StaticFile: path must not be empty".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Short tag used to identify which source flavour produced
    /// something, without leaking URLs / paths. Used by
    /// `JwksCache::Debug` (F3) and the F5 error mapping in
    /// `error.rs::map_oidc_error` for the
    /// `"JWKS refresh failed (<source-tag>): ..."` message shape per
    /// spec §9.
    pub(crate) fn tag(&self) -> &'static str {
        match self {
            JwksSource::Discovery { .. } => "discovery",
            JwksSource::JwksUri { .. } => "jwks-uri",
            JwksSource::StaticFile { .. } => "static-file",
        }
    }
}

fn check_url(url: &str, allow_insecure_http: bool, field: &str) -> Result<(), AttestorError> {
    if url.is_empty() {
        return Err(AttestorError::Internal(format!(
            "{field}: must not be empty"
        )));
    }
    let is_https = url.starts_with("https://");
    let is_http = url.starts_with("http://");
    if !is_https && !is_http {
        return Err(AttestorError::Internal(format!(
            "{field}: URL must start with http:// or https://"
        )));
    }
    if is_http && !allow_insecure_http {
        return Err(AttestorError::Internal(format!(
            "{field}: HTTPS required (set allow_insecure_http for the F7 \
             mock-OIDC server or local IdPs)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_https_validates() {
        let s = JwksSource::Discovery {
            issuer_url: "https://login.example.com".into(),
        };
        s.validate(false).unwrap();
    }

    #[test]
    fn discovery_http_rejected_without_escape_hatch() {
        let s = JwksSource::Discovery {
            issuer_url: "http://login.example.com".into(),
        };
        assert!(s.validate(false).is_err());
        assert!(s.validate(true).is_ok());
    }

    #[test]
    fn discovery_no_scheme_rejected() {
        let s = JwksSource::Discovery {
            issuer_url: "login.example.com".into(),
        };
        assert!(s.validate(true).is_err());
    }

    #[test]
    fn jwks_uri_https_validates() {
        let s = JwksSource::JwksUri {
            url: "https://login.example.com/jwks".into(),
        };
        s.validate(false).unwrap();
    }

    #[test]
    fn static_file_with_path_validates() {
        let s = JwksSource::StaticFile {
            path: PathBuf::from("/etc/yutha/oidc-jwks.json"),
        };
        s.validate(false).unwrap();
    }

    #[test]
    fn static_file_empty_path_rejected() {
        let s = JwksSource::StaticFile {
            path: PathBuf::new(),
        };
        assert!(s.validate(false).is_err());
    }

    #[test]
    fn tag_identifies_flavour() {
        let d = JwksSource::Discovery {
            issuer_url: "https://x".into(),
        };
        let j = JwksSource::JwksUri {
            url: "https://x".into(),
        };
        let f = JwksSource::StaticFile {
            path: PathBuf::from("/x"),
        };
        assert_eq!(d.tag(), "discovery");
        assert_eq!(j.tag(), "jwks-uri");
        assert_eq!(f.tag(), "static-file");
    }
}
