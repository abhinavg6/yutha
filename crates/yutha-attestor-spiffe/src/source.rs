//! Trust-bundle plumbing for the SPIFFE Attestor.
//!
//! Implements [`attestor-spiffe.md` §4–§5](../../../spec/identity-keys/attestor-spiffe.md#4-trust-bundle-sources)
//! — the static-file + Workload-API sources, plus the bounded-staleness
//! policy that protects against silently serving a frozen bundle while
//! the live source is unreachable.
//!
//! # Layout
//!
//! - [`TrustBundleSource`] — the construction-time discriminator
//!   operators choose via CLI flags. Public API surface.
//! - [`BundleCache`] — the runtime cache [`crate::SpiffeAttestor`]
//!   consults on every `verify()`. Two variants matching the source
//!   choice. Crate-private.
//! - [`BundleCache::lookup`] — the verify-time entry point: given a
//!   `TrustDomain`, returns the current `JwtBundle` or maps a missing /
//!   stale / unreachable state to an `AttestorError`.
//!
//! # Why we use `spiffe::JwtSource` as-is
//!
//! The `JwtSource` from the SPIFFE SDK already does everything the
//! Workload-API path needs: streaming the bundle set from a SPIRE
//! agent socket, atomic swap on rotation, exponential-backoff
//! reconnect, an `is_healthy()` signal that flips false when the
//! SDK has lost touch with usable authorities. Wrapping it gives us:
//!   - one fewer concurrency abstraction in this crate;
//!   - free benefit from upstream bugfixes/perf work;
//!   - the SDK's `is_healthy()` semantics aligned with our
//!     bounded-staleness contract.
//!
//! The cache adds, on top of the SDK:
//!   - the [`SpiffeConfig`]-driven configuration plumbing (socket path,
//!     initial-sync timeout, reconnect backoff window);
//!   - the static-file flavour (which the SDK does not provide
//!     directly);
//!   - the bounded-staleness check (the static path's "stale" is
//!     wall-clock vs. construction time; the Workload-API path's
//!     "stale" is `!source.is_healthy()`).

use crate::config::SpiffeConfig;
use serde::Deserialize;
use spiffe::{bundle::BundleSource, jwt_source::JwtSource, JwtBundle, TrustDomain};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use yutha_attestor::AttestorError;

/// Where the SPIFFE Attestor obtains its trust bundle.
///
/// Construction-time choice; cannot be changed without re-creating the
/// [`crate::SpiffeAttestor`]. Operators select via the CLI flags
/// `--attestor-spiffe-socket` (→ [`WorkloadApi`](Self::WorkloadApi))
/// and `--attestor-spiffe-bundle-file` (→ [`StaticFile`](Self::StaticFile)).
///
/// See [`attestor-spiffe.md` §4.3](../../../spec/identity-keys/attestor-spiffe.md#43-exactly-one-source)
/// for why the two flavours are mutually exclusive.
#[derive(Debug, Clone)]
pub enum TrustBundleSource {
    /// Static JSON file containing a [SPIFFE Trust Bundle](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format).
    ///
    /// Read once at construction; no live rotation. Operators rotate
    /// by replacing the file and restarting the control plane.
    /// Appropriate for air-gapped, edge, and dev environments where
    /// running a SPIRE agent sidecar is infeasible.
    StaticFile {
        /// Filesystem path to the bundle JSON.
        path: PathBuf,
    },

    /// Long-lived stream from a SPIRE agent's Workload API socket.
    ///
    /// At construction the Attestor connects, awaits the initial
    /// bundle message (bounded by [`SpiffeConfig::connect_timeout_secs`]),
    /// and the underlying SDK runs a background task that atomically
    /// swaps the cached bundle on every subsequent stream message.
    /// Mid-stream disconnects reconnect with exponential backoff
    /// while the last-known bundle continues to serve verification —
    /// up to [`SpiffeConfig::max_staleness`].
    WorkloadApi {
        /// Filesystem path to the SPIRE agent's Workload API socket
        /// (e.g., `/run/spire/sockets/agent.sock`). Accepted in either
        /// bare-path form or `unix://...` URI form by the underlying
        /// SDK.
        socket: PathBuf,
    },
}

impl TrustBundleSource {
    /// A short tag used in tracing logs + error messages to identify
    /// which source variant produced a given event. Kept small + low-
    /// entropy so it does not leak operator path information.
    pub(crate) fn tag(&self) -> &'static str {
        match self {
            Self::StaticFile { .. } => "static-file",
            Self::WorkloadApi { .. } => "workload-api",
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
//                              BundleCache
// ───────────────────────────────────────────────────────────────────────────

/// Runtime trust-bundle cache the [`crate::SpiffeAttestor`] consults
/// on every `verify()`.
///
/// Two variants, one per [`TrustBundleSource`]. Both expose the same
/// [`lookup`](Self::lookup) entry point so the verify hot path does
/// not need to branch on which flavour is in play.
///
/// Crate-private: this type is an implementation detail of
/// [`crate::SpiffeAttestor`] and not part of the public API.
pub(crate) enum BundleCache {
    Static {
        /// The single trust-domain bundle parsed from the static file
        /// at construction. Held in an `Arc` because the bundle
        /// itself is cheaply clonable but verify-time consumers want
        /// a borrowed view.
        bundle: Arc<JwtBundle>,
        /// Wall-clock at construction. The static path has no live
        /// refresh; if the operator sets a finite `max_staleness`,
        /// this is what we compare against to fail closed after the
        /// configured window (the "restart-the-control-plane-to-rotate"
        /// cron pattern from `attestor-spiffe.md` §5).
        loaded_at: Instant,
        /// Snapshot of the source tag for tracing / error messages.
        source_tag: &'static str,
    },
    WorkloadApi {
        /// The SDK's hot-rotating cache. We hand it our verify call
        /// via [`BundleSource::bundle_for_trust_domain`] on every
        /// lookup; the SDK's atomic-swap pattern means concurrent
        /// readers never see a torn intermediate.
        source: Arc<JwtSource>,
        /// Snapshot of the source tag for tracing / error messages.
        source_tag: &'static str,
    },
}

impl std::fmt::Debug for BundleCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static {
                bundle,
                loaded_at,
                source_tag,
            } => f
                .debug_struct("BundleCache::Static")
                .field("source_tag", source_tag)
                .field("trust_domain", &bundle.trust_domain().as_str())
                .field("loaded_at", loaded_at)
                .finish(),
            Self::WorkloadApi { source_tag, .. } => f
                .debug_struct("BundleCache::WorkloadApi")
                .field("source_tag", source_tag)
                .field("source", &"<spiffe::JwtSource — bundle set redacted>")
                .finish(),
        }
    }
}

impl BundleCache {
    /// Construct the cache by initialising whichever source the
    /// `config` selected.
    ///
    /// For [`TrustBundleSource::StaticFile`] this reads + parses the
    /// file once. The whole construction is `async` for parity with
    /// the Workload-API path; the static-file path does no I/O on a
    /// runtime besides the synchronous read.
    ///
    /// For [`TrustBundleSource::WorkloadApi`] this builds a
    /// [`spiffe::JwtSource`] via [`JwtSourceBuilder`], setting the
    /// configured endpoint + initial-sync timeout, and waits for the
    /// SDK's initial sync to complete (or the timeout to fire).
    ///
    /// # Errors
    ///
    /// - [`AttestorError::TrustRootUnavailable`] for any source-side
    ///   construction failure: file read errors, JSON parse failures,
    ///   Workload-API connect failures, initial-sync timeouts. The
    ///   error message names the source-tag + a short reason; no
    ///   credential or claim contents per the RFC 0016 §3.1 PII rule
    ///   (this is the construction path, not the verify path — there
    ///   is no credential here to leak — but the rule applies
    ///   uniformly).
    /// - [`AttestorError::Malformed`] for static-file JSON shape
    ///   errors (missing `trust_domain`, missing `keys`, malformed
    ///   JWK entries). Same path as a credential being malformed;
    ///   construction failure means an operator typo'd the bundle.
    pub(crate) async fn connect(config: &SpiffeConfig) -> Result<Self, AttestorError> {
        match &config.source {
            TrustBundleSource::StaticFile { path } => {
                let bundle = load_static_bundle(path)?;
                Ok(Self::Static {
                    bundle: Arc::new(bundle),
                    loaded_at: Instant::now(),
                    source_tag: config.source.tag(),
                })
            }
            TrustBundleSource::WorkloadApi { socket } => {
                let endpoint = workload_api_endpoint_str(socket);
                let initial_sync_timeout = Duration::from_secs(config.connect_timeout_secs);

                let source = spiffe::JwtSourceBuilder::new()
                    .endpoint(&endpoint)
                    .initial_sync_timeout(initial_sync_timeout)
                    .build()
                    .await
                    .map_err(|e| {
                        AttestorError::TrustRootUnavailable(format!(
                            "trust bundle unavailable (workload-api): \
                             initial sync failed: {e}"
                        ))
                    })?;

                Ok(Self::WorkloadApi {
                    source: Arc::new(source),
                    source_tag: config.source.tag(),
                })
            }
        }
    }

    /// Look up the bundle for a given SPIFFE trust domain.
    ///
    /// Applies the bounded-staleness check first; if the cache is
    /// stale, returns [`AttestorError::TrustRootUnavailable`] without
    /// consulting the underlying source.
    ///
    /// Returns [`AttestorError::Rejected`] if the cache is fresh but
    /// has no entry for the requested trust domain (the SVID's `sub`
    /// names a trust domain neither in the static file nor in the
    /// Workload-API's federated set).
    ///
    /// # Phase E3 scope
    ///
    /// This is the entry point the Phase E4 [`crate::SpiffeAttestor::verify`]
    /// will call to resolve the signing-authority lookup. In E3 it
    /// exists but has no consumer yet; the scaffold's `verify` still
    /// short-circuits with the "lands in E4" stub.
    #[allow(dead_code)] // E4 wires this into the verify path
    pub(crate) fn lookup(
        &self,
        trust_domain: &TrustDomain,
        max_staleness: Option<Duration>,
    ) -> Result<Arc<JwtBundle>, AttestorError> {
        self.assert_fresh(max_staleness)?;

        match self {
            Self::Static { bundle, .. } => {
                if bundle.trust_domain() == trust_domain {
                    Ok(Arc::clone(bundle))
                } else {
                    Err(AttestorError::Rejected(
                        "trust domain not in bundle".to_string(),
                    ))
                }
            }
            Self::WorkloadApi { source, source_tag } => {
                let maybe = source.bundle_for_trust_domain(trust_domain).map_err(|e| {
                    AttestorError::TrustRootUnavailable(format!(
                        "trust bundle unavailable ({source_tag}): \
                             bundle lookup failed: {e}"
                    ))
                })?;
                maybe.ok_or_else(|| {
                    AttestorError::Rejected("trust domain not in bundle".to_string())
                })
            }
        }
    }

    /// Check the bounded-staleness contract from
    /// [`attestor-spiffe.md` §5](../../../spec/identity-keys/attestor-spiffe.md#5-bounded-staleness-policy).
    ///
    /// - **Static path:** `now - loaded_at` against `max_staleness`.
    ///   `None` means no check (the default for static).
    /// - **Workload-API path:** [`JwtSource::is_healthy`] is the
    ///   SDK's signal that the source currently has usable
    ///   authorities; we treat `!is_healthy()` as "stale beyond the
    ///   bounded window" because the SDK's own reconnect/backoff has
    ///   not produced a fresh bundle within its own freshness budget.
    pub(crate) fn assert_fresh(
        &self,
        max_staleness: Option<Duration>,
    ) -> Result<(), AttestorError> {
        match self {
            Self::Static {
                loaded_at,
                source_tag,
                ..
            } => {
                if let Some(window) = max_staleness {
                    let elapsed = loaded_at.elapsed();
                    if elapsed > window {
                        return Err(AttestorError::TrustRootUnavailable(format!(
                            "trust bundle stale ({source_tag}): \
                                 last refresh was {}s ago; max staleness \
                                 window is {}s",
                            elapsed.as_secs(),
                            window.as_secs(),
                        )));
                    }
                }
                Ok(())
            }
            Self::WorkloadApi { source, source_tag } => {
                if !source.is_healthy() {
                    return Err(AttestorError::TrustRootUnavailable(format!(
                        "trust bundle stale ({source_tag}): \
                             JwtSource reports unhealthy — SPIRE agent \
                             unreachable or no usable authorities"
                    )));
                }
                Ok(())
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
//                       BundleSource trait integration
// ───────────────────────────────────────────────────────────────────────────

/// Error type the [`BundleSource`] impl returns for source-side
/// lookup failures.
///
/// The SDK's [`spiffe::JwtSvid::parse_and_validate`] wraps this in
/// [`spiffe::JwtSvidError::BundleSourceError`], which
/// [`crate::map_spiffe_error`] then maps to
/// [`AttestorError::TrustRootUnavailable`].
///
/// Crate-private: callers see the boxed error through the SDK's
/// error variant; they never construct this directly.
#[derive(Debug, Error)]
pub(crate) enum BundleCacheLookupError {
    /// The Workload-API SDK's `bundle_for_trust_domain` returned an
    /// error. Wrapped as a `Box<dyn Error>` because the SDK's error
    /// type is opaque + non-exhaustive.
    #[error("workload-api bundle lookup failed: {0}")]
    WorkloadApi(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl BundleSource for BundleCache {
    type Item = JwtBundle;
    type Error = BundleCacheLookupError;

    /// SDK-trait method: look up the bundle for a given trust domain.
    ///
    /// Does NOT perform the bounded-staleness check (see
    /// [`BundleCache::assert_fresh`] / [`BundleCache::lookup`] for
    /// that). The verify path runs `assert_fresh` first, then passes
    /// `&self` here for the SDK's
    /// [`spiffe::JwtSvid::parse_and_validate`] to consult; checking
    /// staleness twice in one verify call is redundant.
    fn bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<Arc<JwtBundle>>, BundleCacheLookupError> {
        match self {
            Self::Static { bundle, .. } => {
                if bundle.trust_domain() == trust_domain {
                    Ok(Some(Arc::clone(bundle)))
                } else {
                    Ok(None)
                }
            }
            Self::WorkloadApi { source, .. } => source
                .bundle_for_trust_domain(trust_domain)
                .map_err(|e| BundleCacheLookupError::WorkloadApi(Box::new(e))),
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
//                          Static-file parsing
// ───────────────────────────────────────────────────────────────────────────

/// Wire shape for the [`TrustBundleSource::StaticFile`] JSON. The
/// fields beyond `trust_domain` + `keys` are accepted-and-ignored so
/// operators can use a SPIFFE-shaped bundle dump verbatim (Yutha does
/// not consume `spiffe_sequence` / `spiffe_refresh_hint` for static
/// bundles — operators rotate by file replacement + restart).
#[derive(Debug, Deserialize)]
struct StaticBundleFile {
    trust_domain: String,
    keys: Vec<serde_json::Value>,
    // Intentionally non-exhaustive at the type level; extra fields in
    // the JSON are ignored by serde's default behaviour.
}

fn workload_api_endpoint_str(path: &Path) -> String {
    // The SDK's JwtSourceBuilder::endpoint accepts either a bare
    // filesystem path or a `unix://` URI. We normalise to URI form so
    // tracing logs are unambiguous about what was passed.
    let s = path.to_string_lossy();
    if s.starts_with("unix:") || s.starts_with("tcp:") {
        s.into_owned()
    } else {
        format!("unix:{s}")
    }
}

fn load_static_bundle(path: &Path) -> Result<JwtBundle, AttestorError> {
    let bytes = std::fs::read(path).map_err(|e| {
        AttestorError::TrustRootUnavailable(format!(
            "trust bundle unavailable (static-file): read failed: {e}"
        ))
    })?;

    let parsed: StaticBundleFile = serde_json::from_slice(&bytes).map_err(|e| {
        AttestorError::Malformed(format!("static bundle file is not valid JSON: {e}"))
    })?;

    let trust_domain = TrustDomain::try_from(parsed.trust_domain.as_str()).map_err(|e| {
        AttestorError::Malformed(format!(
            "static bundle trust_domain is not a valid SPIFFE \
                 trust domain: {e}"
        ))
    })?;

    if parsed.keys.is_empty() {
        return Err(AttestorError::Malformed(
            "static bundle keys array is empty".to_string(),
        ));
    }

    // The SDK's from_jwt_authorities wants a raw JWKS document
    // (`{"keys": [...]}`). Re-serialise just the keys array under
    // that wrapper.
    let jwks = serde_json::json!({ "keys": parsed.keys });
    let jwks_bytes = serde_json::to_vec(&jwks).map_err(|e| {
        AttestorError::Internal(format!("static bundle keys re-serialisation failed: {e}"))
    })?;

    JwtBundle::from_jwt_authorities(trust_domain, &jwks_bytes).map_err(|e| {
        AttestorError::Malformed(format!("static bundle keys did not parse as a JWKS: {e}"))
    })
}

// ───────────────────────────────────────────────────────────────────────────
//                                 Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A minimal valid JWKS payload that JwtBundle::from_jwt_authorities
    /// will accept. EC P-256 keys are the easiest to craft inline.
    fn valid_jwks_keys() -> serde_json::Value {
        serde_json::json!([{
            "kty": "EC",
            "kid": "test-key-1",
            "crv": "P-256",
            "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
            "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
        }])
    }

    /// Per-call unique temp path. Cargo runs tests in this module
    /// concurrently; using only `process::id()` collides across the
    /// 5+ callers and races with their teardown `remove_file` calls.
    /// An atomic counter scoped to this module disambiguates.
    fn write_temp_bundle(body: &serde_json::Value) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "yutha-attestor-spiffe-source-test-{}-{}.json",
            std::process::id(),
            unique,
        ));
        let mut f = std::fs::File::create(&path).expect("temp file create");
        f.write_all(serde_json::to_vec(body).expect("serialize").as_slice())
            .expect("write");
        path
    }

    #[test]
    fn load_static_bundle_round_trips_valid_jwks() {
        let path = write_temp_bundle(&serde_json::json!({
            "trust_domain": "example.org",
            "keys": valid_jwks_keys(),
        }));

        let bundle = load_static_bundle(&path).expect("valid bundle must load");
        assert_eq!(bundle.trust_domain().as_str(), "example.org");
        assert!(bundle.find_jwt_authority("test-key-1").is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_static_bundle_ignores_extra_top_level_fields() {
        // SPIFFE bundles in the wild carry spiffe_sequence /
        // spiffe_refresh_hint; we must accept-and-ignore those rather
        // than fail strict-parse.
        let path = write_temp_bundle(&serde_json::json!({
            "spiffe_sequence": 0,
            "spiffe_refresh_hint": 600,
            "trust_domain": "example.org",
            "keys": valid_jwks_keys(),
        }));
        load_static_bundle(&path).expect("extra fields must be ignored");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_static_bundle_rejects_missing_trust_domain() {
        let path = write_temp_bundle(&serde_json::json!({
            "keys": valid_jwks_keys(),
        }));
        let err = load_static_bundle(&path).expect_err("missing td must fail");
        assert!(matches!(err, AttestorError::Malformed(_)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_static_bundle_rejects_empty_keys() {
        let path = write_temp_bundle(&serde_json::json!({
            "trust_domain": "example.org",
            "keys": [],
        }));
        let err = load_static_bundle(&path).expect_err("empty keys must fail");
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("empty"), "got: {msg}")
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_static_bundle_rejects_missing_file() {
        let bogus = PathBuf::from("/nonexistent/does/not/exist.json");
        let err = load_static_bundle(&bogus).expect_err("missing file");
        assert!(matches!(err, AttestorError::TrustRootUnavailable(_)));
    }

    #[test]
    fn workload_api_endpoint_normalises_bare_path() {
        let p = PathBuf::from("/run/spire/sockets/agent.sock");
        assert_eq!(
            workload_api_endpoint_str(&p),
            "unix:/run/spire/sockets/agent.sock"
        );
    }

    #[test]
    fn workload_api_endpoint_preserves_existing_uri() {
        let p = PathBuf::from("unix:///tmp/spire.sock");
        assert_eq!(workload_api_endpoint_str(&p), "unix:///tmp/spire.sock");
    }

    // --- BundleCache integration ---

    fn baseline_static_config_for(path: PathBuf) -> SpiffeConfig {
        SpiffeConfig {
            source: TrustBundleSource::StaticFile { path },
            expected_audience: "yutha-test".to_string(),
            max_staleness: None,
            clock_skew_tolerance_secs: 60,
            connect_timeout_secs: 10,
        }
    }

    #[tokio::test]
    async fn cache_static_lookup_returns_bundle_for_matching_td() {
        let path = write_temp_bundle(&serde_json::json!({
            "trust_domain": "example.org",
            "keys": valid_jwks_keys(),
        }));
        let cache = BundleCache::connect(&baseline_static_config_for(path.clone()))
            .await
            .expect("connect");

        let td = TrustDomain::try_from("example.org").unwrap();
        let bundle = cache.lookup(&td, None).expect("matching td");
        assert_eq!(bundle.trust_domain().as_str(), "example.org");

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cache_static_lookup_rejects_unknown_td() {
        let path = write_temp_bundle(&serde_json::json!({
            "trust_domain": "example.org",
            "keys": valid_jwks_keys(),
        }));
        let cache = BundleCache::connect(&baseline_static_config_for(path.clone()))
            .await
            .expect("connect");

        let td = TrustDomain::try_from("other.example.org").unwrap();
        let err = cache.lookup(&td, None).expect_err("unknown td");
        assert!(matches!(err, AttestorError::Rejected(_)));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cache_static_lookup_enforces_bounded_staleness() {
        let path = write_temp_bundle(&serde_json::json!({
            "trust_domain": "example.org",
            "keys": valid_jwks_keys(),
        }));
        let cache = BundleCache::connect(&baseline_static_config_for(path.clone()))
            .await
            .expect("connect");

        // Zero-duration staleness window forces immediate failure
        // (anything past loaded_at + 0 is stale).
        let td = TrustDomain::try_from("example.org").unwrap();
        std::thread::sleep(Duration::from_millis(5)); // ensure now > loaded_at
        let err = cache
            .lookup(&td, Some(Duration::from_secs(0)))
            .expect_err("zero window must fail");
        match err {
            AttestorError::TrustRootUnavailable(msg) => {
                assert!(msg.contains("stale"), "got: {msg}")
            }
            other => panic!("expected TrustRootUnavailable, got {other:?}"),
        }

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cache_static_lookup_no_staleness_check_when_window_none() {
        let path = write_temp_bundle(&serde_json::json!({
            "trust_domain": "example.org",
            "keys": valid_jwks_keys(),
        }));
        let cache = BundleCache::connect(&baseline_static_config_for(path.clone()))
            .await
            .expect("connect");

        let td = TrustDomain::try_from("example.org").unwrap();
        // Even with a slept-past delay, None disables the check.
        std::thread::sleep(Duration::from_millis(5));
        cache
            .lookup(&td, None)
            .expect("None disables staleness check");

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cache_connect_surfaces_static_file_io_errors() {
        let cfg = baseline_static_config_for(PathBuf::from("/nonexistent/does-not-exist.json"));
        let err = BundleCache::connect(&cfg)
            .await
            .expect_err("missing file must fail connect");
        assert!(matches!(err, AttestorError::TrustRootUnavailable(_)));
    }
}
