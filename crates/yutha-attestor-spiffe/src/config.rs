//! [`SpiffeConfig`] — construction-time configuration for [`crate::SpiffeAttestor`].
//!
//! Implements [`attestor-spiffe.md` §10](../../../spec/identity-keys/attestor-spiffe.md#10-cli-flag-surface)
//! at the type level. Operators populate via CLI flags
//! (`--attestor-spiffe-*`) in `yutha-control-plane`; Phase E6 wires the
//! flag → struct translation.
//!
//! Fields with `Option<T>` carry "use the spec default" semantics; the
//! spec docs cite the defaults so this struct's docs do not repeat them.

use crate::source::TrustBundleSource;
use std::time::Duration;

/// Construction-time configuration for [`crate::SpiffeAttestor`].
///
/// All fields are consumed exactly once at
/// [`crate::SpiffeAttestor::connect`] time. Changing them after
/// construction has no effect (the running Attestor caches its
/// resolved trust bundle and audience value).
#[derive(Debug, Clone)]
pub struct SpiffeConfig {
    /// Where to fetch the trust bundle from. Exactly one of the two
    /// [`TrustBundleSource`] variants; the CLI surface enforces this
    /// at startup.
    pub source: TrustBundleSource,

    /// The operator-configured audience value. SVIDs whose `aud` claim
    /// does not contain this exact string are
    /// [`AttestorError::Rejected`](yutha_attestor::AttestorError::Rejected).
    /// Empty string is a startup-time fatal — see the spec memo's §6.1
    /// guidance on choosing a swarm-specific audience.
    pub expected_audience: String,

    /// Bounded-staleness window. When the cache's `last_refresh_at` is
    /// older than this, every subsequent
    /// [`Attestor::verify`](yutha_attestor::Attestor::verify) call
    /// returns
    /// [`TrustRootUnavailable`](yutha_attestor::AttestorError::TrustRootUnavailable).
    ///
    /// - `None` for [`TrustBundleSource::WorkloadApi`] selects the
    ///   spec default: `2 × spiffe_refresh_hint` from the most recent
    ///   bundle, with floor 60 s + ceiling 24 h.
    /// - `None` for [`TrustBundleSource::StaticFile`] selects
    ///   [`Duration::MAX`] (no staleness check) — the static path has
    ///   no live refresh.
    /// - `Some(Duration::ZERO)` selects "hard fail on TTL expiry"
    ///   (strictest policy; spec memo §5).
    pub max_staleness: Option<Duration>,

    /// Tolerance for `iat` / `nbf` claims slightly ahead of local
    /// wall-clock. The spec default is 60 seconds. Setting `0` enforces
    /// strict-equality; large values weaken the freshness guarantee.
    pub clock_skew_tolerance_secs: u64,

    /// Cold-start timeout for the [`TrustBundleSource::WorkloadApi`]
    /// flavour — the maximum wait for the first stream message before
    /// construction fails. Ignored for the static-file source. Spec
    /// default 10 s.
    pub connect_timeout_secs: u64,
}

impl SpiffeConfig {
    /// Validate fields that the type system cannot express (non-empty
    /// audience, non-degenerate timeouts). Called by
    /// [`crate::SpiffeAttestor::connect`] before any I/O.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`AttestorError::Internal`](yutha_attestor::AttestorError::Internal)
    /// with a brief, operator-actionable message naming the offending
    /// field. (Construction-time validation does not fit the
    /// `Malformed` / `Rejected` / `TrustRootUnavailable` variants —
    /// those describe credential-verification outcomes, not
    /// configuration shape.)
    pub fn validate(&self) -> Result<(), yutha_attestor::AttestorError> {
        if self.expected_audience.is_empty() {
            return Err(yutha_attestor::AttestorError::Internal(
                "SpiffeConfig.expected_audience must be non-empty; pass a \
                 swarm-specific value via --attestor-spiffe-audience"
                    .to_string(),
            ));
        }
        if self.connect_timeout_secs == 0 {
            return Err(yutha_attestor::AttestorError::Internal(
                "SpiffeConfig.connect_timeout_secs must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn baseline() -> SpiffeConfig {
        SpiffeConfig {
            source: TrustBundleSource::StaticFile {
                path: PathBuf::from("/tmp/bundle.json"),
            },
            expected_audience: "yutha-test".to_string(),
            max_staleness: None,
            clock_skew_tolerance_secs: 60,
            connect_timeout_secs: 10,
        }
    }

    #[test]
    fn validate_accepts_baseline() {
        baseline()
            .validate()
            .expect("baseline config must validate");
    }

    #[test]
    fn validate_rejects_empty_audience() {
        let mut cfg = baseline();
        cfg.expected_audience.clear();
        let err = cfg.validate().expect_err("empty audience must fail");
        assert!(format!("{err}").contains("expected_audience"));
    }

    #[test]
    fn validate_rejects_zero_connect_timeout() {
        let mut cfg = baseline();
        cfg.connect_timeout_secs = 0;
        let err = cfg.validate().expect_err("zero connect_timeout must fail");
        assert!(format!("{err}").contains("connect_timeout_secs"));
    }
}
