//! In-memory JWKS cache with TTL refresh + kid-miss async refresh.
//!
//! Implements [spec §5](../../../../spec/identity-keys/attestor-oidc.md#5-jwks-cache--bounded-staleness)
//! end-to-end. Phase F's [F0 recon decision](../../../../spec/identity-keys/attestor-oidc.md#0-scope)
//! was that the cache + refresh state machine stays in-tree (not behind
//! the `jwks_client_rs` opinionated client) so the audit-relevant
//! refresh semantics live where security review can find them.
//!
//! # Architecture
//!
//! - **Backing store:** `Arc<tokio::sync::RwLock<HashMap<String, jwks::Jwk>>>`,
//!   keyed by `kid`. Read locks are held only for the duration of a
//!   `HashMap::get`; write locks are held only during the atomic-swap
//!   replacement after a successful fetch. Verify-path reads NEVER see
//!   a torn intermediate.
//! - **Refresh dedup:** `Arc<tokio::sync::Mutex<()>>` — at most one
//!   in-flight refetch per Attestor instance, regardless of how many
//!   concurrent verify calls trigger it.
//! - **TTL semantics:** lazy. `assert_fresh()` checks `now - last_refresh_at`;
//!   past TTL but within `max_staleness`, fires a `tokio::spawn`'d
//!   background refresh (deduplicated) and continues serving from the
//!   cached JWKS. Past `max_staleness`, returns `TrustRootUnavailable`.
//! - **Kid-miss semantics:** blocking. `lookup(kid)` on a miss takes
//!   the refresh dedup mutex, refetches synchronously, and retries the
//!   lookup once.
//! - **Static-file mode:** no refresh (background or kid-miss); the
//!   file is read once at `warm()` and held for the process lifetime.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jwks::Jwk;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};
use yutha_attestor::AttestorError;

use crate::source::JwksSource;

/// JWKS-payload + connect-timeout caps lifted out of [`OidcConfig`]
/// into a value type so the cache doesn't depend on the wider config.
/// Construct via [`JwksCache::warm`] which extracts these from the
/// caller's [`OidcConfig`].
///
/// [`OidcConfig`]: crate::OidcConfig
#[derive(Debug, Clone)]
pub(crate) struct CacheConfig {
    pub cache_ttl: Duration,
    /// `None` → no staleness check (used for the static-file source
    /// unless the operator explicitly sets a finite max_staleness).
    pub max_staleness: Option<Duration>,
    pub connect_timeout: Duration,
}

/// JWKS payload cap from spec §5.3: 64 KiB.
const JWKS_PAYLOAD_MAX_BYTES: usize = 64 * 1024;

/// In-memory JWKS cache.
///
/// Construct via [`JwksCache::warm`]; query via [`JwksCache::lookup`]
/// and [`JwksCache::assert_fresh`].
///
/// Cloneable: the underlying state is behind `Arc`, so a clone shares
/// the same cache + the same refresh dedup mutex. This lets the
/// [`crate::OidcAttestor`] hold the cache by value while internally
/// `Arc`-ed.
///
/// `Debug` is implemented manually (not derived) because `jwks::Jwk`
/// does not derive `Debug`. The manual impl also deliberately skips
/// the key material — debug-logging an Attestor MUST NOT leak the
/// public-key bytes it's verifying signatures with.
#[derive(Clone)]
pub struct JwksCache {
    /// Source flavour — held so refresh paths know how to refetch.
    source: JwksSource,
    /// JWKS payload, kid → Jwk. Wrapped in `RwLock` for atomic swaps
    /// during refresh; outer `Arc` for cheap clones.
    keys: Arc<RwLock<HashMap<String, Jwk>>>,
    /// Wall-clock instant the last successful refresh completed.
    /// Wrapped in `RwLock` so refresh-task writes don't block reads.
    last_refresh_at: Arc<RwLock<Instant>>,
    /// Refresh-in-progress lock. Held during a refetch so concurrent
    /// callers wait for a single refresh rather than triggering N.
    refresh_dedup: Arc<Mutex<()>>,
    /// TTL + staleness + timeout caps.
    config: CacheConfig,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render summary state only; never the keys themselves (would
        // leak public-key bytes into operator logs that might transit
        // through audit pipelines).
        f.debug_struct("JwksCache")
            .field("source", &self.source.tag())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl JwksCache {
    /// Construct + warm the cache from the source.
    ///
    /// Fetches the initial JWKS:
    /// - **Discovery:** GETs `<issuer_url>/.well-known/openid-configuration`,
    ///   validates the doc's `issuer` field exact-matches
    ///   `expected_issuer` per spec §6.3, then GETs the discovery doc's
    ///   `jwks_uri`.
    /// - **JwksUri:** GETs the operator-provided URL directly.
    /// - **StaticFile:** reads + parses the file from disk.
    ///
    /// Returns `Self` on success; the initial JWKS is in the cache.
    /// Failure is fatal — the control plane refuses to start (spec §9
    /// "JWKS source unavailable at construction").
    ///
    /// The `expected_issuer` parameter is only consulted for the
    /// Discovery-mode `issuer` exact-match check; it's threaded
    /// separately from `OidcConfig` to keep this constructor's
    /// signature focused.
    pub async fn warm(
        source: JwksSource,
        expected_issuer: &str,
        cache_ttl_secs: u64,
        max_staleness_secs: Option<u64>,
        connect_timeout_secs: u64,
    ) -> Result<Self, AttestorError> {
        let config = CacheConfig {
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            max_staleness: max_staleness_secs.map(Duration::from_secs),
            connect_timeout: Duration::from_secs(connect_timeout_secs),
        };

        let initial = fetch_jwks(&source, expected_issuer, &config).await?;

        if initial.is_empty() {
            return Err(AttestorError::TrustRootUnavailable(format!(
                "JWKS source ({}) returned zero keys; refusing to start",
                source.tag(),
            )));
        }

        Ok(Self {
            source,
            keys: Arc::new(RwLock::new(initial)),
            last_refresh_at: Arc::new(RwLock::new(Instant::now())),
            refresh_dedup: Arc::new(Mutex::new(())),
            config,
        })
    }

    /// Check whether the cache is fresh enough to serve from.
    ///
    /// Three outcomes per spec §5.1:
    /// - **Within TTL:** `Ok(())`, no refresh kicked off.
    /// - **Past TTL but within `max_staleness`:** `Ok(())`, fires a
    ///   `tokio::spawn`'d background refresh (deduplicated). The
    ///   verify call continues using the still-cached JWKS.
    /// - **Past `max_staleness`:** `Err(TrustRootUnavailable(...))`.
    ///
    /// The static-file source treats `max_staleness = None` as
    /// `Duration::MAX` (no staleness check ever), matching spec §4.3.
    pub async fn assert_fresh(&self) -> Result<(), AttestorError> {
        if matches!(self.source, JwksSource::StaticFile { .. }) {
            // Static-file: skip the TTL machinery entirely unless the
            // operator explicitly set a max_staleness.
            if let Some(max) = self.config.max_staleness {
                let elapsed = self.last_refresh_at.read().await.elapsed();
                if elapsed > max {
                    return Err(AttestorError::TrustRootUnavailable(format!(
                        "JWKS stale: last refresh was {}s ago; max staleness \
                         window is {}s (static-file source — restart the \
                         control plane after rotating the file)",
                        elapsed.as_secs(),
                        max.as_secs(),
                    )));
                }
            }
            return Ok(());
        }

        let elapsed = self.last_refresh_at.read().await.elapsed();

        // Past max_staleness → hard reject.
        if let Some(max) = self.config.max_staleness {
            if elapsed > max {
                return Err(AttestorError::TrustRootUnavailable(format!(
                    "JWKS stale: last refresh was {}s ago; max staleness \
                     window is {}s",
                    elapsed.as_secs(),
                    max.as_secs(),
                )));
            }
        }

        // Past TTL but within max_staleness → kick off background
        // refresh (deduplicated). Don't wait for it.
        if elapsed > self.config.cache_ttl {
            self.spawn_background_refresh();
        }

        Ok(())
    }

    /// Look up a key by `kid`.
    ///
    /// Two paths per spec §5.2:
    /// - **Cache hit:** return the key.
    /// - **Cache miss:** acquire the refresh dedup lock, refetch the
    ///   JWKS synchronously (callers waiting on the same lock share
    ///   one refetch), retry the lookup once against the refreshed
    ///   cache. If still missing, return `Ok(None)` — the caller maps
    ///   this to `Rejected("kid not found in JWKS")`. If the refetch
    ///   itself fails, return `TrustRootUnavailable`.
    ///
    /// Static-file source: no kid-miss refresh; a miss is `Ok(None)`
    /// immediately.
    pub async fn lookup(&self, kid: &str) -> Result<Option<Jwk>, AttestorError> {
        // Fast path: try the current cache.
        if let Some(jwk) = self.keys.read().await.get(kid).cloned() {
            return Ok(Some(jwk));
        }

        // Static-file: no refresh path. The kid is genuinely unknown.
        if matches!(self.source, JwksSource::StaticFile { .. }) {
            return Ok(None);
        }

        // Slow path: kid-miss async refresh + retry.
        debug!(
            kid_present_in_cache = false,
            "kid not in JWKS cache; \
                                                triggering deduplicated refresh"
        );
        self.refresh_now().await?;
        Ok(self.keys.read().await.get(kid).cloned())
    }

    /// Fire a `tokio::spawn`'d background refresh, deduplicated against
    /// any in-flight refresh. Errors are logged via tracing but not
    /// propagated — the verify call continues using the still-cached
    /// JWKS (spec §5.1 second bullet).
    fn spawn_background_refresh(&self) {
        let dedup = self.refresh_dedup.clone();
        let keys = self.keys.clone();
        let last_refresh_at = self.last_refresh_at.clone();
        let source = self.source.clone();
        // No expected_issuer for background refreshes: the discovery-
        // doc `issuer` check is a one-time-at-construction check; once
        // we're warmed, we trust the source URL.
        let expected_issuer = String::new();
        let config = self.config.clone();
        tokio::spawn(async move {
            // try_lock instead of lock — if a refresh is already in
            // flight, just drop this attempt.
            let Ok(_guard) = dedup.try_lock() else {
                debug!("background JWKS refresh skipped — already in flight");
                return;
            };
            match fetch_jwks(&source, &expected_issuer, &config).await {
                Ok(fresh) if !fresh.is_empty() => {
                    *keys.write().await = fresh;
                    *last_refresh_at.write().await = Instant::now();
                    debug!("background JWKS refresh completed");
                }
                Ok(_) => warn!(
                    "background JWKS refresh returned zero keys; \
                     keeping stale cache"
                ),
                Err(err) => warn!(
                    error = %err,
                    "background JWKS refresh failed; keeping stale cache"
                ),
            }
        });
    }

    /// Blocking refresh — called by `lookup` on kid-miss. Deduplicated
    /// against any other in-flight refresh (concurrent callers share
    /// the same refetch). On failure, the cache is NOT invalidated —
    /// callers continue serving from the still-cached JWKS until the
    /// next refresh succeeds.
    ///
    /// Dedup semantics: snapshot `last_refresh_at` BEFORE acquiring
    /// the lock, then re-read AFTER. If the value changed during our
    /// wait, another caller refreshed and we can skip our own
    /// refetch — the post-`refresh_now` lookup retry will see their
    /// fresh cache. (An earlier F3 implementation used a
    /// "skip if cache was refreshed in the last 100 ms" wall-clock
    /// heuristic; that was wrong for kid-rotation cases where the
    /// rotation happens shortly after the initial warm — the kid-
    /// miss-triggered refresh would be skipped and the caller would
    /// keep seeing a stale cache without the rotated kid. F7
    /// integration test `kid_rotation_triggers_refresh_and_verify_succeeds`
    /// guards against this regression.)
    async fn refresh_now(&self) -> Result<(), AttestorError> {
        let before_lock = *self.last_refresh_at.read().await;
        let _guard = self.refresh_dedup.lock().await;

        let after_lock = *self.last_refresh_at.read().await;
        if after_lock != before_lock {
            // Another caller refreshed while we waited; their fetch
            // covers ours.
            return Ok(());
        }

        let fresh = fetch_jwks(&self.source, "", &self.config).await?;
        if fresh.is_empty() {
            return Err(AttestorError::TrustRootUnavailable(format!(
                "JWKS refresh ({}): source returned zero keys",
                self.source.tag(),
            )));
        }
        *self.keys.write().await = fresh;
        *self.last_refresh_at.write().await = Instant::now();
        Ok(())
    }

    /// Test/inspection: how many keys are currently cached.
    #[cfg(test)]
    pub(crate) async fn key_count(&self) -> usize {
        self.keys.read().await.len()
    }
}

// ---------------------------------------------------------------------------
// Source-specific fetch logic.
// ---------------------------------------------------------------------------

/// Top-level fetch dispatcher. Reads from the source and returns a
/// `kid -> Jwk` map.
///
/// `expected_issuer` is only consulted for the Discovery-mode `issuer`
/// exact-match check (spec §6.3); ignored otherwise. Pass `""` for
/// background-refresh paths where the check has already happened once
/// at construction.
async fn fetch_jwks(
    source: &JwksSource,
    expected_issuer: &str,
    config: &CacheConfig,
) -> Result<HashMap<String, Jwk>, AttestorError> {
    match source {
        JwksSource::Discovery { issuer_url } => {
            fetch_via_discovery(issuer_url, expected_issuer, config).await
        }
        JwksSource::JwksUri { url } => fetch_via_jwks_url(url, config).await,
        JwksSource::StaticFile { path } => parse_static_file(path),
    }
}

/// Discovery-mode fetch: GET the well-known doc, validate `issuer`
/// per spec §6.3 (if `expected_issuer` is non-empty), extract
/// `jwks_uri`, GET the JWKS.
async fn fetch_via_discovery(
    issuer_url: &str,
    expected_issuer: &str,
    config: &CacheConfig,
) -> Result<HashMap<String, Jwk>, AttestorError> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .connect_timeout(config.connect_timeout)
        .build()
        .map_err(|err| {
            AttestorError::TrustRootUnavailable(format!(
                "Discovery: failed to build HTTP client: {err}"
            ))
        })?;

    let resp = client.get(&well_known).send().await.map_err(|err| {
        AttestorError::TrustRootUnavailable(format!(
            "Discovery: GET /.well-known/openid-configuration failed: {err}"
        ))
    })?;

    if !resp.status().is_success() {
        return Err(AttestorError::TrustRootUnavailable(format!(
            "Discovery: GET /.well-known/openid-configuration returned \
             HTTP {}",
            resp.status().as_u16(),
        )));
    }

    let doc: DiscoveryDoc = resp.json().await.map_err(|err| {
        AttestorError::TrustRootUnavailable(format!(
            "Discovery: response body is not a valid JSON discovery \
             document: {err}"
        ))
    })?;

    // Spec §6.3: discovery-doc `issuer` MUST exact-match operator's
    // expected_issuer per RFC 8414 §3.3. Skip when called from the
    // background-refresh path (expected_issuer == "").
    if !expected_issuer.is_empty() && doc.issuer != expected_issuer {
        return Err(AttestorError::TrustRootUnavailable(
            "Discovery: discovery-doc `issuer` field does not exact-match \
             operator-configured expected_issuer (per RFC 8414 §3.3 / spec §6.3). \
             Refusing to trust the JWKS this discovery doc points at."
                .to_string(),
        ));
    }

    fetch_via_jwks_url(&doc.jwks_uri, config).await
}

/// Direct-JWKS-URL fetch: enforce the 64-KiB size cap by reading the
/// body as text first.
async fn fetch_via_jwks_url(
    url: &str,
    config: &CacheConfig,
) -> Result<HashMap<String, Jwk>, AttestorError> {
    let client = reqwest::Client::builder()
        .connect_timeout(config.connect_timeout)
        .build()
        .map_err(|err| {
            AttestorError::TrustRootUnavailable(format!(
                "JWKS fetch: failed to build HTTP client: {err}"
            ))
        })?;

    let resp = client.get(url).send().await.map_err(|err| {
        AttestorError::TrustRootUnavailable(format!("JWKS fetch: GET failed: {err}"))
    })?;

    if !resp.status().is_success() {
        return Err(AttestorError::TrustRootUnavailable(format!(
            "JWKS fetch: GET returned HTTP {}",
            resp.status().as_u16(),
        )));
    }

    let body = resp.text().await.map_err(|err| {
        AttestorError::TrustRootUnavailable(format!(
            "JWKS fetch: failed to read response body: {err}"
        ))
    })?;

    if body.len() > JWKS_PAYLOAD_MAX_BYTES {
        return Err(AttestorError::TrustRootUnavailable(format!(
            "JWKS payload exceeds {} bytes cap ({} bytes); spec §5.3",
            JWKS_PAYLOAD_MAX_BYTES,
            body.len(),
        )));
    }

    parse_jwks_body(&body)
}

/// Static-file mode: open + read + parse + size-check.
fn parse_static_file(path: &Path) -> Result<HashMap<String, Jwk>, AttestorError> {
    let body = std::fs::read_to_string(path).map_err(|err| {
        AttestorError::TrustRootUnavailable(format!(
            "Static-file JWKS: failed to read {}: {err}",
            path.display(),
        ))
    })?;

    if body.len() > JWKS_PAYLOAD_MAX_BYTES {
        return Err(AttestorError::TrustRootUnavailable(format!(
            "Static-file JWKS: payload exceeds {} bytes cap ({} bytes); \
             spec §5.3",
            JWKS_PAYLOAD_MAX_BYTES,
            body.len(),
        )));
    }

    parse_jwks_body(&body)
}

/// Parse a JWKS JSON body. The `jwks` crate exposes only
/// URL-fetching constructors (no `from_str` / `from_bytes`), so we
/// roll the same parse path ourselves: `serde_json` into
/// `jsonwebtoken::jwk::JwkSet`, then `jwks::JwkEntry::from_jsonwebkey_ref`
/// per entry. Returns the kid → Jwk map in the same shape `Jwks::keys`
/// would produce — byte-identical across static-file and network paths.
fn parse_jwks_body(body: &str) -> Result<HashMap<String, Jwk>, AttestorError> {
    // The `jwks` crate's `from_jwks_url_with_client` does
    // `client.get(url).send().json::<jsonwebtoken::jwk::JwkSet>()` then
    // iterates `JwkEntry::try_from(jwk)` over `jwks.keys`. We mirror
    // the same algorithm against an in-memory body so static-file mode
    // produces byte-identical `Jwk` values to the network-fetch path.
    let raw_set: jsonwebtoken::jwk::JwkSet = serde_json::from_str(body)
        .map_err(|err| AttestorError::TrustRootUnavailable(format!("JWKS parse: {err}")))?;

    let mut out = HashMap::with_capacity(raw_set.keys.len());
    for raw_jwk in raw_set.keys {
        let entry = jwks::JwkEntry::from_jsonwebkey_ref(&raw_jwk).map_err(|err| {
            AttestorError::TrustRootUnavailable(format!("JWKS parse: key entry rejected: {err}"))
        })?;
        out.insert(entry.kid, entry.jwk);
    }
    Ok(out)
}

/// Just the fields the Attestor consumes from the OIDC discovery doc.
/// `serde(deny_unknown_fields)` is NOT set — discovery docs carry many
/// optional fields the spec lets us ignore (authorization_endpoint,
/// token_endpoint, etc.).
#[derive(Debug, Deserialize)]
struct DiscoveryDoc {
    /// REQUIRED per OpenID Connect Discovery 1.0 §3. The Attestor
    /// exact-matches this against operator-configured expected_issuer
    /// per spec §6.3.
    issuer: String,
    /// REQUIRED per OpenID Connect Discovery 1.0 §3. Where the JWKS
    /// lives.
    jwks_uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Build a minimal valid two-key JWKS body. Real-world JWKS shapes
    /// from major IdPs match this structure; we just use static keys
    /// to keep the test stable.
    fn fixture_jwks_body() -> String {
        // From the `jwks` crate's own test (Google's published JWKS).
        // Two RSA keys, RS256, with kids "kid-1" and "kid-2".
        serde_json::json!({
            "keys": [
                {
                    "use": "sig",
                    "kty": "RSA",
                    "alg": "RS256",
                    "kid": "kid-1",
                    "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                    "e": "AQAB",
                },
                {
                    "use": "sig",
                    "kty": "RSA",
                    "alg": "RS256",
                    "kid": "kid-2",
                    "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
                    "e": "AQAB",
                }
            ]
        })
        .to_string()
    }

    fn temp_jwks_file(body: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(body.as_bytes()).unwrap();
        file
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_warms_and_serves_keys() {
        let file = temp_jwks_file(&fixture_jwks_body());
        let cache = JwksCache::warm(
            JwksSource::StaticFile {
                path: file.path().to_path_buf(),
            },
            "https://login.example.com",
            3600,
            None,
            10,
        )
        .await
        .expect("static-file JWKS warms");

        assert_eq!(cache.key_count().await, 2);

        let hit = cache.lookup("kid-1").await.unwrap();
        assert!(hit.is_some(), "kid-1 should hit");
        let hit = cache.lookup("kid-2").await.unwrap();
        assert!(hit.is_some(), "kid-2 should hit");

        let miss = cache.lookup("never-issued").await.unwrap();
        assert!(miss.is_none(), "unknown kid should miss");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_assert_fresh_passes_without_max_staleness() {
        let file = temp_jwks_file(&fixture_jwks_body());
        let cache = JwksCache::warm(
            JwksSource::StaticFile {
                path: file.path().to_path_buf(),
            },
            "https://login.example.com",
            3600,
            None, // no max_staleness on static-file
            10,
        )
        .await
        .unwrap();

        cache
            .assert_fresh()
            .await
            .expect("static-file with max_staleness=None is always fresh");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_missing_path_errors() {
        let res = JwksCache::warm(
            JwksSource::StaticFile {
                path: PathBuf::from("/this/path/does/not/exist.json"),
            },
            "https://login.example.com",
            3600,
            None,
            10,
        )
        .await;
        let err = res.unwrap_err();
        assert!(matches!(err, AttestorError::TrustRootUnavailable(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_empty_keys_array_errors() {
        let file = temp_jwks_file(&serde_json::json!({ "keys": [] }).to_string());
        let res = JwksCache::warm(
            JwksSource::StaticFile {
                path: file.path().to_path_buf(),
            },
            "https://login.example.com",
            3600,
            None,
            10,
        )
        .await;
        let err = res.unwrap_err();
        assert!(matches!(err, AttestorError::TrustRootUnavailable(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_oversize_payload_errors() {
        // Build a JWKS body > 64 KiB by stuffing the `n` field with
        // base64url padding.
        let mut body = String::from(
            r#"{"keys":[{"use":"sig","kty":"RSA","alg":"RS256","kid":"big","e":"AQAB","n":""#,
        );
        // 65 KiB of base64url-safe chars.
        body.push_str(&"A".repeat(65 * 1024));
        body.push_str(r#""}]}"#);
        let file = temp_jwks_file(&body);
        let res = JwksCache::warm(
            JwksSource::StaticFile {
                path: file.path().to_path_buf(),
            },
            "https://login.example.com",
            3600,
            None,
            10,
        )
        .await;
        let err = res.unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, AttestorError::TrustRootUnavailable(_)));
        assert!(
            msg.contains("exceeds") && msg.contains("65"),
            "expected size-cap error mentioning byte count; got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_malformed_json_errors() {
        let file = temp_jwks_file("not actually json");
        let res = JwksCache::warm(
            JwksSource::StaticFile {
                path: file.path().to_path_buf(),
            },
            "https://login.example.com",
            3600,
            None,
            10,
        )
        .await;
        assert!(matches!(
            res.unwrap_err(),
            AttestorError::TrustRootUnavailable(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn static_file_with_max_staleness_set_passes_when_fresh() {
        let file = temp_jwks_file(&fixture_jwks_body());
        let cache = JwksCache::warm(
            JwksSource::StaticFile {
                path: file.path().to_path_buf(),
            },
            "https://login.example.com",
            3600,
            Some(3600), // operator opted in to staleness check
            10,
        )
        .await
        .unwrap();

        cache
            .assert_fresh()
            .await
            .expect("just-warmed cache is fresh");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cache_clone_shares_state() {
        let file = temp_jwks_file(&fixture_jwks_body());
        let cache = JwksCache::warm(
            JwksSource::StaticFile {
                path: file.path().to_path_buf(),
            },
            "https://login.example.com",
            3600,
            None,
            10,
        )
        .await
        .unwrap();

        let cloned = cache.clone();
        // Both clones see the same number of keys.
        assert_eq!(cache.key_count().await, cloned.key_count().await);
    }
}
