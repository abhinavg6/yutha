//! Yutha control-plane binary.
//!
//! Brings the in-memory backends up, registers a bootstrap agent end-to-end,
//! and exposes a gRPC server on `--grpc-addr` (default `127.0.0.1:50051`)
//! across four services from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto).
//!
//! Implementation status (all four services wired):
//!   - `ReceiptService` (Get, Query) — wired through to the
//!     [`ReceiptStore`](yutha_receipt::ReceiptStore).
//!   - `AdmissionService` (Register, Revoke, GetTopology) — wired through
//!     to the [`Registry`](yutha_registry::Registry). `RotateKey` returns
//!     `UNIMPLEMENTED` pending a spec RFC (the wire shape can't carry a
//!     self-signed continuation passport).
//!   - `CapabilityService` (Issue, Attenuate, Revoke, Check) — wired
//!     through to the [`CapabilityStore`](yutha_capability::CapabilityStore).
//!     Issuance signs with the control-plane's key as a scaffolding
//!     shortcut; a future RFC pins down per-issuer signing.
//!   - `EnvelopeService.Send` — wired through to
//!     [`Transport::send`](yutha_transport::Transport).
//!   - `EnvelopeService.Subscribe` — server-streaming. Idempotently
//!     registers the bearer's inbox on first call and forwards every
//!     delivered envelope + its `envelope.deliver` receipt id.
//!
//! Always-on infrastructure:
//!   - bearer-token verification ([`crate::auth::require_bearer_auth`]) —
//!     called by every handler that requires auth. Validates an
//!     `authorization: bearer <hex>` metadata header end-to-end against
//!     the registered passport's public key.
//!   - gRPC reflection (so `grpcurl <addr> list` works without proto files)
//!   - optional TLS (server cert; presence of --client-ca opts into mTLS)

#![forbid(unsafe_code)]

mod auth;
mod grpc;
mod quarantine_adapter;
mod receipt_publisher;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{info, warn};
use yutha_capability::{CapabilityStore, MemoryCapabilityStore};
use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::hash::sha256;
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_proto::control_plane::v1::{
    admission_service_server::AdmissionServiceServer,
    capability_service_server::CapabilityServiceServer,
    constitution_service_server::ConstitutionServiceServer,
    envelope_service_server::EnvelopeServiceServer, receipt_service_server::ReceiptServiceServer,
    replay_service_server::ReplayServiceServer,
};
use yutha_proto::FILE_DESCRIPTOR_SET;
use yutha_receipt::{
    ActionKindQuery, MemoryStore as MemoryReceiptStore, PassportResolver, Query, ReceiptStore,
};
use yutha_registry::{
    AdmissionPolicy, ClosedPolicy, MemoryRegistry, OpenPolicy, Registry, Topology, TopologyMode,
};
use yutha_signer::{InProcessSigner, Signer};
use yutha_transport::{MemoryTransport, Transport};

use auth::BearerInterceptor;
use grpc::{
    admission::AdmissionHandler, capability::CapabilityHandler, constitution::ConstitutionHandler,
    envelope::EnvelopeHandler, receipt::ReceiptHandler, ControlPlaneState,
};
use receipt_publisher::{emit_enforcement_receipt, EnforcementReceiptView, PublishingReceiptStore};
use tokio::sync::mpsc;
use yutha_cedar_plus::ReceiptView;

/// Yutha control plane.
#[derive(Debug, Parser)]
#[command(name = "yutha", version, about, long_about = None)]
struct Cli {
    /// gRPC listen address. Default is loopback-only; bind to 0.0.0.0
    /// for non-local access (and consider TLS).
    #[arg(long, env = "YUTHA_GRPC_ADDR", default_value = "127.0.0.1:50051")]
    grpc_addr: SocketAddr,

    /// TLS server certificate (PEM). When set, the gRPC server requires
    /// TLS. Pair with --tls-key.
    #[arg(long, env = "YUTHA_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// TLS server private key (PEM). Required when --tls-cert is set.
    #[arg(long, env = "YUTHA_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Client CA bundle (PEM). When set, the gRPC server requires
    /// client certs (mTLS). Layered on top of bearer-token auth.
    #[arg(long, env = "YUTHA_CLIENT_CA")]
    client_ca: Option<PathBuf>,

    /// Admission policy for the registry.
    ///
    /// - `closed` (default) — only the bootstrap agent is allowlisted.
    ///   Matches production posture: no agent can join without
    ///   pre-registration. Used by the existing
    ///   `test_integration.py` smoke tests.
    /// - `open` — any well-formed passport with `expires_at` set and
    ///   tier ≥ Minimal is admitted. Intended for demos and local
    ///   development (the Stage-4c LangGraph customer-support demo
    ///   uses this mode so its five agents can self-register).
    ///   **Never enable in production**: open mode imposes no Sybil
    ///   resistance beyond the default `OpenPolicy` requirements.
    #[arg(long, env = "YUTHA_ADMISSION_MODE", value_enum, default_value_t = AdmissionModeArg::Closed)]
    admission_mode: AdmissionModeArg,

    /// Whether `EnvelopeService.Send` is gated by a capability check
    /// (RFC 0007).
    ///
    /// - `auto` (default) — follow the admission-mode default: closed
    ///   → require cap; open → permissive (legacy v1.0 behavior).
    /// - `true` — force-require a capability_id on every Send,
    ///   regardless of admission mode.
    /// - `false` — force-permit Sends without a capability_id,
    ///   regardless of admission mode. Useful during the v1.0 → v1.1
    ///   migration window when clients are not yet updated.
    ///
    /// When a Send presents a capability_id under any setting, the
    /// check runs and emits a `capability.check.{pass,deny}` receipt;
    /// deny rejects the send. The flag governs only the
    /// "cap_id absent" branch.
    #[arg(
        long,
        env = "YUTHA_REQUIRE_CAP_FOR_SEND",
        value_enum,
        default_value_t = RequireCapForSendArg::Auto
    )]
    require_cap_for_send: RequireCapForSendArg,

    /// External-identity `Attestor` to consult on every registration
    /// (RFC 0016).
    ///
    /// - `native` (default) — `NativeAttestor`: accepts empty
    ///   `external_credential`, records `yutha:native:<hex>` as the
    ///   attested external identity. Behaviorally identical to the
    ///   pre-RFC-0016 flow modulo two new evidence keys on
    ///   `agent.register`.
    /// - `spiffe` — `yutha-attestor-spiffe` (Phase E). Verifies SPIFFE
    ///   JWT-SVIDs against a configured trust bundle. Pair with the
    ///   `--attestor-spiffe-*` flags: REQUIRED `--attestor-spiffe-audience`
    ///   plus EXACTLY ONE of `--attestor-spiffe-socket` (SPIRE Workload
    ///   API socket, hot rotation) or `--attestor-spiffe-bundle-file`
    ///   (static JWKS, air-gapped). See
    ///   /spec/identity-keys/attestor-spiffe.md §10 for the full flag
    ///   surface.
    /// - `oidc` — `yutha-attestor-oidc` (Phase F). Verifies OpenID
    ///   Connect ID tokens against a configured JWKS. Pair with the
    ///   `--attestor-oidc-*` flags: REQUIRED `--attestor-oidc-issuer`
    ///   and `--attestor-oidc-audience`; AT MOST ONE of
    ///   `--attestor-oidc-jwks-uri` (skip discovery, fetch JWKS
    ///   directly) or `--attestor-oidc-jwks-file` (air-gapped, static
    ///   file); default (neither override set) is OIDC Discovery
    ///   against the issuer URL. See
    ///   /spec/identity-keys/attestor-oidc.md §10 for the full flag
    ///   surface and §4 for the source-mode trade-offs.
    #[arg(long, env = "YUTHA_ATTESTOR", value_enum, default_value_t = AttestorArg::Native)]
    attestor: AttestorArg,

    /// SPIRE agent Workload API socket path. REQUIRED when
    /// `--attestor=spiffe` AND `--attestor-spiffe-bundle-file` is unset
    /// (and mutually-exclusive with that flag). The SPIFFE Attestor
    /// connects, awaits the initial trust-bundle sync (bounded by
    /// `--attestor-spiffe-connect-timeout-secs`), and the underlying
    /// SDK hot-rotates the cached bundle on each stream update.
    /// Accepts either a bare path (`/run/spire/sockets/agent.sock`) or
    /// a URI (`unix:/run/spire/sockets/agent.sock`).
    #[arg(long, env = "YUTHA_ATTESTOR_SPIFFE_SOCKET")]
    attestor_spiffe_socket: Option<PathBuf>,

    /// Static JWKS trust-bundle file. REQUIRED when `--attestor=spiffe`
    /// AND `--attestor-spiffe-socket` is unset (and mutually-exclusive
    /// with that flag). Format: SPIFFE Trust Bundle JSON
    /// (`{ "trust_domain": "...", "keys": [<JWKS entries>] }`). Read
    /// once at startup; operators rotate by replacing the file and
    /// restarting. Appropriate for air-gapped, edge, and dev
    /// environments without a SPIRE agent sidecar.
    #[arg(long, env = "YUTHA_ATTESTOR_SPIFFE_BUNDLE_FILE")]
    attestor_spiffe_bundle_file: Option<PathBuf>,

    /// Audience value the SVID's `aud` claim MUST contain. REQUIRED
    /// when `--attestor=spiffe`. Operators choose a swarm-specific
    /// value (`yutha-<swarm-name>-<env>` is the recommended shape per
    /// /spec/identity-keys/attestor-spiffe.md §6.1); generic values
    /// like `yutha-prod` invite cross-system SVID replay.
    #[arg(long, env = "YUTHA_ATTESTOR_SPIFFE_AUDIENCE")]
    attestor_spiffe_audience: Option<String>,

    /// Bounded-staleness window for the SPIFFE trust-bundle cache.
    /// When the cache hasn't refreshed within this window, verify
    /// returns `TrustRootUnavailable`. Default behaviour (when unset)
    /// is source-flavour-specific: Workload API uses
    /// `2 × spiffe_refresh_hint`; static-file uses no check
    /// (`Duration::MAX`). Setting `0` selects "hard fail on TTL
    /// expiry" (strictest). See attestor-spiffe.md §5.
    #[arg(long, env = "YUTHA_ATTESTOR_SPIFFE_MAX_STALENESS_SECS")]
    attestor_spiffe_max_staleness_secs: Option<u64>,

    /// Clock-skew tolerance for `iat` / `nbf` JWT-SVID claims, in
    /// seconds. Defaults to 60. Setting `0` enforces strict equality
    /// (any token timestamp ahead of local wall-clock is rejected);
    /// large values weaken the freshness guarantee.
    #[arg(
        long,
        env = "YUTHA_ATTESTOR_SPIFFE_CLOCK_SKEW_SECS",
        default_value_t = 60
    )]
    attestor_spiffe_clock_skew_secs: u64,

    /// Cold-start timeout for the Workload API source. Maximum wait
    /// for the initial trust-bundle sync message before construction
    /// fails. Defaults to 10 s. Ignored when
    /// `--attestor-spiffe-bundle-file` is in use.
    #[arg(
        long,
        env = "YUTHA_ATTESTOR_SPIFFE_CONNECT_TIMEOUT_SECS",
        default_value_t = 10
    )]
    attestor_spiffe_connect_timeout_secs: u64,

    // -------------------------------------------------------------------
    // OIDC Attestor (Phase F, /spec/identity-keys/attestor-oidc.md §10).
    //
    // All flags below take effect only when `--attestor=oidc`. The
    // three source-mode flags are mutually constrained:
    //   - Default (none set) → OIDC Discovery against `--attestor-oidc-issuer`.
    //   - `--attestor-oidc-jwks-uri <url>` set → skip discovery, fetch
    //     JWKS directly (operator escape hatch for non-standard IdPs).
    //   - `--attestor-oidc-jwks-file <path>` set → static-file (air-
    //     gapped or "rotate by restart" deployments).
    //   - Both override flags set → fatal startup error.
    // -------------------------------------------------------------------
    /// IdP's issuer URL. REQUIRED when `--attestor=oidc`. Must exactly
    /// equal the `iss` claim in minted ID tokens; in Discovery mode
    /// also exact-matched against the discovery doc's `issuer` field
    /// per spec §6.3 / RFC 8414 §3.3.
    ///
    /// MUST be HTTPS unless `--attestor-oidc-allow-insecure-http` is
    /// set. Trailing slashes matter — copy from the IdP's discovery
    /// doc; do not normalize. Examples:
    ///   `https://login.example.okta.com`
    ///   `https://accounts.google.com`
    ///   `https://<tenant>.auth0.com/`
    ///   `https://<host>/realms/<realm>`
    #[arg(long, env = "YUTHA_ATTESTOR_OIDC_ISSUER")]
    attestor_oidc_issuer: Option<String>,

    /// Audience value the ID token's `aud` claim MUST contain.
    /// REQUIRED when `--attestor=oidc`. Operators choose a swarm-
    /// specific value (`yutha-<swarm-name>-<env>` is the recommended
    /// shape per /spec/identity-keys/attestor-oidc.md §6.1); generic
    /// values like `yutha-prod` invite cross-system ID-token replay.
    #[arg(long, env = "YUTHA_ATTESTOR_OIDC_AUDIENCE")]
    attestor_oidc_audience: Option<String>,

    /// Optional JWKS URL override. When set, skips OIDC Discovery
    /// and fetches the JWKS directly from this URL. Use sparingly —
    /// see spec §4.2 for the trade-off (operator loses the
    /// discovery-doc `issuer` integrity check). Mutually exclusive
    /// with `--attestor-oidc-jwks-file`.
    #[arg(long, env = "YUTHA_ATTESTOR_OIDC_JWKS_URI")]
    attestor_oidc_jwks_uri: Option<String>,

    /// Optional static JWKS file path. When set, the Attestor reads
    /// the file once at startup and serves it for the process
    /// lifetime; rotation requires writing a new file and restarting.
    /// Suitable for air-gapped deployments. Mutually exclusive with
    /// `--attestor-oidc-jwks-uri`. Spec §4.3.
    #[arg(long, env = "YUTHA_ATTESTOR_OIDC_JWKS_FILE")]
    attestor_oidc_jwks_file: Option<PathBuf>,

    /// Operator-allowlisted ID-token claims to project into the
    /// `agent.register` receipt's evidence as
    /// `attributes.<claim-name>: <value>` keys. Default empty
    /// (no projection). Repeatable; env-var form takes a comma-
    /// separated list (`YUTHA_ATTESTOR_OIDC_PROJECT_CLAIMS=groups,email,roles`).
    /// Spec §8.
    #[arg(
        long = "attestor-oidc-project-claims",
        env = "YUTHA_ATTESTOR_OIDC_PROJECT_CLAIMS",
        value_delimiter = ','
    )]
    attestor_oidc_project_claims: Vec<String>,

    /// JWS `alg` allow-list. Default: `RS256,RS384,RS512,ES256,ES384,EdDSA`.
    /// `none` and `HS*` are architecturally rejected at startup if
    /// present (HMAC requires shared-secret distribution that breaks
    /// the OIDC trust model; see spec §2.1). Operators can narrow
    /// further per IdP capability. Env-var form takes a comma-
    /// separated list.
    #[arg(
        long = "attestor-oidc-allowed-algs",
        env = "YUTHA_ATTESTOR_OIDC_ALLOWED_ALGS",
        value_delimiter = ',',
        default_values_t = default_oidc_allowed_algs(),
    )]
    attestor_oidc_allowed_algs: Vec<String>,

    /// JWKS cache TTL in seconds. Default 3600 (1 h). Minimum 60;
    /// shorter values are rejected to avoid IdP-side rate-limit
    /// pressure. Ignored when `--attestor-oidc-jwks-file` is in use.
    /// Spec §5.1.
    #[arg(
        long,
        env = "YUTHA_ATTESTOR_OIDC_CACHE_TTL_SECS",
        default_value_t = 3600
    )]
    attestor_oidc_cache_ttl_secs: u64,

    /// Maximum staleness window before the Attestor stops serving
    /// from the cached JWKS. Default behaviour: discovery / JWKS-URI
    /// use 86400 s (24 h); static-file uses no check (`Duration::MAX`).
    /// `0` selects "hard fail on TTL expiry" (strictest policy).
    /// Spec §5.1.
    #[arg(long, env = "YUTHA_ATTESTOR_OIDC_MAX_STALENESS_SECS")]
    attestor_oidc_max_staleness_secs: Option<u64>,

    /// Clock-skew tolerance for `iat` / `nbf` checks, in seconds.
    /// Default 60. Spec §3 step 7.
    #[arg(
        long,
        env = "YUTHA_ATTESTOR_OIDC_CLOCK_SKEW_SECS",
        default_value_t = 60
    )]
    attestor_oidc_clock_skew_secs: u64,

    /// Cold-start connect timeout for the discovery-doc fetch and
    /// the initial JWKS fetch, in seconds. Default 10. Ignored for
    /// the static-file source.
    #[arg(
        long,
        env = "YUTHA_ATTESTOR_OIDC_CONNECT_TIMEOUT_SECS",
        default_value_t = 10
    )]
    attestor_oidc_connect_timeout_secs: u64,

    /// Permit HTTP (not just HTTPS) URLs for issuer + JWKS endpoints.
    /// Default `false`. Setting `true` violates OpenID Connect Core
    /// §2 ("Communication ... MUST utilize TLS") and emits a startup
    /// warning. Exists for the in-process mock-OIDC test server and
    /// local-developer Keycloak/dex setups. Spec §6.4.
    #[arg(
        long,
        env = "YUTHA_ATTESTOR_OIDC_ALLOW_INSECURE_HTTP",
        default_value_t = false
    )]
    attestor_oidc_allow_insecure_http: bool,

    // -------------------------------------------------------------------
    // External Signer backends (Phase G, RFC 0017 §4).
    //
    // `--signer=in-process` (the default) keeps the existing zero-config
    // posture: an `InProcessSigner` keypair is generated at startup and
    // never persisted. Operators promoting to enterprise custody select
    // one of the cloud-KMS backends and pair it with that backend's
    // `--signer-{vault,gcp-kms,azure-kv}-*` flag set. Backend-specific
    // validation (required fields, mutually-exclusive auth methods)
    // lives on [`SignerArg::build`] so a misconfigured `--signer` fails
    // the operator at startup, before any signing call runs.
    //
    // Secret material is always taken via a file path
    // (`--signer-vault-token-file`, `--signer-vault-approle-secret-id-file`)
    // rather than as a raw command-line value, so secrets never appear
    // in `ps aux` output. Cloud-KMS backends use their SDK's standard
    // credential chain (ADC for GCP, DefaultAzureCredential for Azure)
    // and need no Yutha-side secret material in flags.
    // -------------------------------------------------------------------
    /// Custody backend for the control plane's signing identity
    /// (RFC 0015 / RFC 0017).
    ///
    /// - `in-process` (default) — `InProcessSigner`: Ed25519 keypair
    ///   generated at startup, held in process memory only, never
    ///   persisted. Suitable for local dev, integration tests, and the
    ///   existing zero-config posture. No extra flags required.
    /// - `vault` — `yutha-signer-vault` (RFC 0017 §4.1). Signs against a
    ///   HashiCorp Vault transit Ed25519 key. Pair with the
    ///   `--signer-vault-*` flags: REQUIRED `--signer-vault-addr` and
    ///   `--signer-vault-key`; EXACTLY ONE auth method via
    ///   `--signer-vault-token-file` OR the AppRole pair
    ///   (`--signer-vault-approle-role-id` +
    ///   `--signer-vault-approle-secret-id-file`).
    /// - `gcp-kms` — `yutha-signer-gcp-kms` (RFC 0017 §4.2). Signs
    ///   against a GCP Cloud KMS Ed25519 crypto-key version. REQUIRED
    ///   `--signer-gcp-kms-key-version` (full resource path including
    ///   `/cryptoKeyVersions/<n>`). Auth uses Application Default
    ///   Credentials (ADC) — set `GOOGLE_APPLICATION_CREDENTIALS` or
    ///   run on a GCE/GKE instance with the right service account
    ///   attached.
    /// - `azure-kv` — `yutha-signer-azure-kv` (RFC 0017 §4.3). Signs
    ///   against an Azure Managed HSM Ed25519 key. REQUIRED
    ///   `--signer-azure-kv-vault-url` (must be
    ///   `https://*.managedhsm.azure.net` — standard Key Vault does
    ///   not support Ed25519) and `--signer-azure-kv-key-name`. Auth
    ///   uses `DefaultAzureCredential` (env / managed identity /
    ///   Azure CLI, in order).
    ///
    /// The selected backend's `connect()` only runs when the flag is
    /// set away from `in-process`; cloud-KMS HTTP clients are never
    /// constructed in the default configuration.
    #[arg(long, env = "YUTHA_SIGNER", value_enum, default_value_t = SignerArg::InProcess)]
    signer: SignerArg,

    /// Vault HTTPS endpoint, e.g. `https://vault.internal:8200`.
    /// REQUIRED when `--signer=vault`. Plain `http://` is supported for
    /// local dev (`vault server -dev`) but emits a warning at startup.
    #[arg(long, env = "YUTHA_SIGNER_VAULT_ADDR")]
    signer_vault_addr: Option<String>,

    /// Mount path of the Vault transit secrets engine. Default
    /// `transit`. Override to e.g. `transit-yutha` if the operator
    /// mounted the engine elsewhere for tenant isolation. No leading
    /// or trailing slash.
    #[arg(long, env = "YUTHA_SIGNER_VAULT_MOUNT", default_value = "transit")]
    signer_vault_mount: String,

    /// Name of the Vault transit Ed25519 key Yutha will sign with,
    /// e.g. `yutha-bootstrap`. REQUIRED when `--signer=vault`. The key
    /// must be created out-of-band by the operator
    /// (`vault write -f transit/keys/<name> type=ed25519`) before
    /// startup.
    #[arg(long, env = "YUTHA_SIGNER_VAULT_KEY")]
    signer_vault_key: Option<String>,

    /// Vault Enterprise namespace (`X-Vault-Namespace` header). Set
    /// when the transit key lives under a non-root namespace; leave
    /// unset for OSS Vault or the root namespace.
    #[arg(long, env = "YUTHA_SIGNER_VAULT_NAMESPACE")]
    signer_vault_namespace: Option<String>,

    /// Path to a file containing the Vault client token. Read once at
    /// startup; recommended `chmod 600`. Mutually exclusive with the
    /// `--signer-vault-approle-*` pair (Token > AppRole precedence;
    /// see RFC 0017 §3.2). Use this path for `vault server -dev`
    /// integration tests or when a sidecar (e.g. Vault Agent)
    /// pre-provisions a token file the control plane consumes.
    ///
    /// Why a file (not a raw `--signer-vault-token`): keeps the token
    /// out of `ps aux`, shell history, and process-listing scrapes.
    /// Mirrors the Sui-anchoring sealer-key flag's posture
    /// (`--anchor-sealer-key-file`).
    #[arg(long, env = "YUTHA_SIGNER_VAULT_TOKEN_FILE")]
    signer_vault_token_file: Option<PathBuf>,

    /// Mount path of the Vault AppRole auth backend. Default `approle`.
    /// Override if the operator mounted AppRole at a custom path
    /// (e.g. `auth/approle-yutha`).
    #[arg(
        long,
        env = "YUTHA_SIGNER_VAULT_APPROLE_MOUNT",
        default_value = "approle"
    )]
    signer_vault_approle_mount: String,

    /// AppRole `role_id` (typically a UUID, operator-issued). Required
    /// when using AppRole auth. Pair with
    /// `--signer-vault-approle-secret-id-file`.
    #[arg(long, env = "YUTHA_SIGNER_VAULT_APPROLE_ROLE_ID")]
    signer_vault_approle_role_id: Option<String>,

    /// Path to a file containing the AppRole `secret_id`. Read once at
    /// startup; recommended `chmod 600`. Required when using AppRole
    /// auth. Same file-not-raw-value rationale as
    /// `--signer-vault-token-file`.
    #[arg(long, env = "YUTHA_SIGNER_VAULT_APPROLE_SECRET_ID_FILE")]
    signer_vault_approle_secret_id_file: Option<PathBuf>,

    /// Full resource path of the GCP Cloud KMS crypto-key *version*,
    /// e.g.
    /// `projects/yutha-prod/locations/us-central1/keyRings/yutha/cryptoKeys/bootstrap/cryptoKeyVersions/1`.
    /// REQUIRED when `--signer=gcp-kms`. Must include the
    /// `/cryptoKeyVersions/<n>` segment — pinning a specific version
    /// means rotation is operator-controlled per RFC 0017 §3.6.
    #[arg(long, env = "YUTHA_SIGNER_GCP_KMS_KEY_VERSION")]
    signer_gcp_kms_key_version: Option<String>,

    /// Override the default Cloud KMS endpoint
    /// (`https://cloudkms.googleapis.com`). Useful for regional
    /// endpoints (e.g. `https://us-central1-cloudkms.googleapis.com`)
    /// or for proxying through a VPC Service Controls perimeter.
    #[arg(long, env = "YUTHA_SIGNER_GCP_KMS_ENDPOINT")]
    signer_gcp_kms_endpoint: Option<String>,

    /// Full HTTPS URL of the Azure Managed HSM, e.g.
    /// `https://yutha-hsm.managedhsm.azure.net`. REQUIRED when
    /// `--signer=azure-kv`. Must be a Managed HSM
    /// (`*.managedhsm.azure.net`) — standard Key Vault
    /// (`*.vault.azure.net`) does not support Ed25519.
    #[arg(long, env = "YUTHA_SIGNER_AZURE_KV_VAULT_URL")]
    signer_azure_kv_vault_url: Option<String>,

    /// Name of the Ed25519 key inside the Managed HSM. REQUIRED when
    /// `--signer=azure-kv`.
    #[arg(long, env = "YUTHA_SIGNER_AZURE_KV_KEY_NAME")]
    signer_azure_kv_key_name: Option<String>,

    /// Explicit key-version hex string (32 hex chars typical). When
    /// unset, the signer uses the *latest* version — STRONGLY
    /// DISCOURAGED in production because Azure can auto-rotate the
    /// underlying key behind your back, invalidating previously-issued
    /// signatures from the point of view of any verifier that cached
    /// the old public key. Pin explicitly per RFC 0017 §3.6 for
    /// operator-controlled rotation.
    #[arg(long, env = "YUTHA_SIGNER_AZURE_KV_KEY_VERSION")]
    signer_azure_kv_key_version: Option<String>,

    /// Deterministic 32-byte hex seed for the bootstrap agent's
    /// identity (signing key + AgentId + SwarmId).
    ///
    /// When unset, all three are generated randomly at startup
    /// (production behavior; the bootstrap key stays in-process and
    /// is never exposed). When set, the seed is fed into:
    ///
    ///   - the Ed25519 signing key directly (32 raw seed bytes)
    ///   - `sha256(seed || 0x01)[:16]` → bootstrap AgentId
    ///   - `sha256(seed || 0x02)[:16]` → SwarmId
    ///
    /// so an external client that knows the seed can derive the same
    /// identity and act as the bootstrap agent.
    ///
    /// Use case: end-to-end integration tests (the Python SDK's
    /// `test_integration.py`) that need to authenticate as a known
    /// agent already in the swarm's allowlist. The seed travels
    /// through the same channel as any production secret (env var or
    /// file) and never widens the server's auth surface — the closed
    /// admission policy is unchanged.
    ///
    /// **WARNING:** logged at startup. Pass via env var
    /// (`YUTHA_BOOTSTRAP_SEED`) rather than `--bootstrap-seed` on the
    /// command line so it doesn't appear in `ps aux`. Do NOT enable
    /// in production unless you've explicitly chosen the seed from a
    /// KMS-backed source.
    #[arg(long, env = "YUTHA_BOOTSTRAP_SEED")]
    bootstrap_seed: Option<String>,

    /// Operator public key (Ed25519, 32 bytes, hex-encoded) the
    /// control plane should trust for `OperatorBearerToken`
    /// verification (RFC 0009 §3.4).
    ///
    /// When this flag is unset, `AdmissionService.OperatorRevoke`
    /// returns `FAILED_PRECONDITION: operator credentials not
    /// enabled` for every call. When set, operator clients
    /// presenting tokens signed by the corresponding private key
    /// can evict agents.
    ///
    /// The operator *private* key MUST stay in operator tooling
    /// (separate binary, sealed secret, HSM, etc.) — the control
    /// plane only ever needs the public counterpart. Compromise of
    /// the operator public key changes nothing; compromise of the
    /// private key compromises the swarm's eviction layer (operator
    /// can revoke any agent), so treat it as a load-bearing secret.
    ///
    /// Rotation: stop the server, restart with a new key. Phase 1
    /// doesn't support runtime rotation; future RFC.
    #[arg(long, env = "YUTHA_OPERATOR_PUBLIC_KEY")]
    operator_public_key: Option<String>,

    /// Workload-schema extensions to load alongside the canonical v1.1
    /// schema. Each value is the file stem of a workload under
    /// `/spec/constitution/canonical-schemas/v1.1.0/` (e.g.
    /// `support-queue`, `code-review`). Repeatable.
    ///
    /// Operators activating a constitution whose Cedar policy
    /// references workload-namespaced actions or entities (e.g.
    /// `Yutha::SupportQueue::Action::"IssueRefund"`) MUST start the
    /// server with the corresponding `--workload <name>` flag so the
    /// Cedar validator recognizes the namespace at load time.
    ///
    /// The env-var form accepts a comma-separated list:
    /// `YUTHA_WORKLOADS=support-queue,code-review`.
    #[arg(long = "workload", env = "YUTHA_WORKLOADS", value_delimiter = ',')]
    workloads: Vec<String>,

    /// Receipt-store backend. `memory` (default) is non-persistent
    /// in-process storage; suitable for local dev, integration tests,
    /// and demos. `postgres` is the production backend — requires
    /// `--postgres-url` (or `YUTHA_POSTGRES_URL`) to be set.
    #[arg(long, env = "YUTHA_RECEIPT_BACKEND", value_enum, default_value_t = ReceiptBackendArg::Memory)]
    receipt_backend: ReceiptBackendArg,

    /// Postgres connection URL for `--receipt-backend postgres`.
    /// Standard libpq URL form
    /// (`postgresql://user:pass@host:port/database`). Migrations run
    /// automatically on startup against this database.
    #[arg(long, env = "YUTHA_POSTGRES_URL")]
    postgres_url: Option<String>,

    // -------------------------------------------------------------------
    // Sui-anchoring driver (RFC 0014 verifiability Layer 1).
    //
    // The four `--anchor-*` flags below are required-together: provide
    // all four to enable the AnchorDriver background task, or none to
    // leave anchoring disabled. Partial configuration is rejected at
    // startup with a clear error. See
    // `/docs/operator/sui-anchoring.md` for end-to-end operator setup.
    //
    // When enabled, the driver polls the receipt store for unsealed
    // receipts past the on-chain watermark, batches them per the
    // cadence knobs, signs the canonical preimage, and submits
    // `commit_batch_from_arrays` PTBs to the operator-deployed
    // `receipt_anchor` Move package. AnchorCommitted events become the
    // public audit trail; the local SealStore is updated in lockstep
    // for fast off-chain seal-status queries.
    // -------------------------------------------------------------------
    /// Sui RPC URL (gRPC) to anchor against. Localnet: `http://127.0.0.1:9000`.
    /// Testnet: `https://fullnode.testnet.sui.io`. Mainnet: `https://fullnode.mainnet.sui.io`.
    ///
    /// Enabling anchoring requires all four `--anchor-*` flags to be set.
    #[arg(long, env = "YUTHA_ANCHOR_SUI_RPC_URL")]
    anchor_sui_rpc_url: Option<String>,

    /// Operator-deployed `receipt_anchor` package id, 0x-prefixed hex.
    /// Obtained from `sui client publish` / `sui client test-publish`
    /// against the operator's chosen Sui network.
    #[arg(long, env = "YUTHA_ANCHOR_PACKAGE_ID")]
    anchor_package_id: Option<String>,

    /// Per-swarm `SwarmAnchor` shared-object id, 0x-prefixed hex.
    /// Created via `sui client call ... create_swarm_anchor`. The
    /// `swarm_id` stored on the anchor MUST equal the bootstrap-seed-
    /// derived `SwarmId` this control plane uses for the registry —
    /// see `BootstrapIdentity::from_seed_hex`. Mismatch surfaces as
    /// `ESealerKeyMismatch` (canonical preimage diverges) on every
    /// commit.
    #[arg(long, env = "YUTHA_ANCHOR_SWARM_ANCHOR_ID")]
    anchor_swarm_anchor_id: Option<String>,

    /// Path to a file containing the sealer's `suiprivkey1…` bech32
    /// string (Sui CLI's canonical keystore format). The corresponding
    /// public key MUST equal the on-chain `SwarmAnchor.sealer_pubkey`
    /// or every commit aborts with `ESealerKeyMismatch`.
    ///
    /// File should be `chmod 600`. Generate via the H5 walkthrough's
    /// `sui keytool generate` + `sui keytool export` flow.
    #[arg(long, env = "YUTHA_ANCHOR_SEALER_KEY_FILE")]
    anchor_sealer_key_file: Option<PathBuf>,

    /// Anchor cadence: trigger a seal when this many unsealed receipts
    /// have accumulated. Default 100. Lower for chatty swarms that
    /// want fresher anchors; higher to amortize gas costs.
    #[arg(
        long,
        env = "YUTHA_ANCHOR_BATCH_COUNT_THRESHOLD",
        default_value_t = 100
    )]
    anchor_batch_count_threshold: usize,

    /// Anchor cadence: trigger a seal at most this often (seconds),
    /// regardless of count. Default 10s. Bounds the
    /// indefinitely-unsealed window for quiet swarms.
    #[arg(
        long,
        env = "YUTHA_ANCHOR_BATCH_TIME_THRESHOLD_SECS",
        default_value_t = 10
    )]
    anchor_batch_time_threshold_secs: u64,

    /// Anchor cadence: hard ceiling on a single batch's size. Default
    /// 1000. Protects against backlog blowouts after RPC downtime —
    /// the next batch covers up to this many receipts; the rest waits
    /// for the following tick.
    #[arg(long, env = "YUTHA_ANCHOR_MAX_BATCH_SIZE", default_value_t = 1000)]
    anchor_max_batch_size: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum ReceiptBackendArg {
    Memory,
    Postgres,
}

/// CLI shadow of [`yutha_registry::AdmissionPolicy`]'s variants we expose.
/// `Hybrid` is intentionally not surfaced yet — its policy fields don't
/// map cleanly to a single flag, and there's no demand for it from the
/// command line. When a workload needs it, add it explicitly.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum AdmissionModeArg {
    Closed,
    Open,
}

/// CLI shadow of the configured external-identity [`Attestor`]
/// (RFC 0016). `Native` is the v1 default; `Spiffe` lands in Phase E
/// (`yutha-attestor-spiffe`); `Oidc` is reserved for Phase F.
///
/// [`Attestor`]: yutha_attestor::Attestor
#[derive(Debug, Clone, Copy, ValueEnum)]
enum AttestorArg {
    Native,
    Spiffe,
    Oidc,
}

/// SPIFFE-specific options harvested from [`Cli`]. Built once at
/// startup so [`AttestorArg::build`] can consume the shape that
/// matters to it without growing a `&Cli` dependency.
///
/// The validation rules (audience required + exactly-one-source)
/// live on [`AttestorArg::build`]; this struct is just the value
/// passthrough.
#[derive(Debug, Clone)]
struct SpiffeCliOpts {
    socket: Option<PathBuf>,
    bundle_file: Option<PathBuf>,
    audience: Option<String>,
    max_staleness_secs: Option<u64>,
    clock_skew_secs: u64,
    connect_timeout_secs: u64,
}

impl SpiffeCliOpts {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            socket: cli.attestor_spiffe_socket.clone(),
            bundle_file: cli.attestor_spiffe_bundle_file.clone(),
            audience: cli.attestor_spiffe_audience.clone(),
            max_staleness_secs: cli.attestor_spiffe_max_staleness_secs,
            clock_skew_secs: cli.attestor_spiffe_clock_skew_secs,
            connect_timeout_secs: cli.attestor_spiffe_connect_timeout_secs,
        }
    }
}

/// Default JWS `alg` allow-list for `--attestor-oidc-allowed-algs`,
/// per /spec/identity-keys/attestor-oidc.md §2.1.
///
/// Set as a function (not a `const`) because `clap`'s
/// `default_values_t` requires an expression that constructs a
/// `Vec<String>` at parse time.
fn default_oidc_allowed_algs() -> Vec<String> {
    vec![
        "RS256".into(),
        "RS384".into(),
        "RS512".into(),
        "ES256".into(),
        "ES384".into(),
        "EdDSA".into(),
    ]
}

/// OIDC-specific options harvested from [`Cli`]. Same pattern as
/// [`SpiffeCliOpts`] — the validation rules (issuer/audience
/// required, at-most-one-of jwks-uri/jwks-file) live on
/// [`AttestorArg::build`].
#[derive(Debug, Clone)]
struct OidcCliOpts {
    issuer: Option<String>,
    audience: Option<String>,
    jwks_uri: Option<String>,
    jwks_file: Option<PathBuf>,
    project_claims: Vec<String>,
    allowed_algs: Vec<String>,
    cache_ttl_secs: u64,
    max_staleness_secs: Option<u64>,
    clock_skew_secs: u64,
    connect_timeout_secs: u64,
    allow_insecure_http: bool,
}

impl OidcCliOpts {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            issuer: cli.attestor_oidc_issuer.clone(),
            audience: cli.attestor_oidc_audience.clone(),
            jwks_uri: cli.attestor_oidc_jwks_uri.clone(),
            jwks_file: cli.attestor_oidc_jwks_file.clone(),
            project_claims: cli.attestor_oidc_project_claims.clone(),
            allowed_algs: cli.attestor_oidc_allowed_algs.clone(),
            cache_ttl_secs: cli.attestor_oidc_cache_ttl_secs,
            max_staleness_secs: cli.attestor_oidc_max_staleness_secs,
            clock_skew_secs: cli.attestor_oidc_clock_skew_secs,
            connect_timeout_secs: cli.attestor_oidc_connect_timeout_secs,
            allow_insecure_http: cli.attestor_oidc_allow_insecure_http,
        }
    }
}

/// CLI shadow of the configured custody backend for the control plane's
/// signing identity (RFC 0017). `InProcess` is the v1 default; the three
/// cloud-KMS backends are wired in Phase G via `--signer` + the per-
/// backend `--signer-{vault,gcp-kms,azure-kv}-*` flag sets.
///
/// `--signer=in-process` preserves the existing zero-config posture:
/// integration tests, demos, and local-dev flows that don't set the
/// flag pick up an `InProcessSigner` exactly as before.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SignerArg {
    InProcess,
    Vault,
    GcpKms,
    AzureKv,
}

/// Vault-specific Signer options harvested from [`Cli`]. Built once at
/// startup so [`SignerArg::build`] can consume the shape that matters
/// to it without growing a `&Cli` dependency.
///
/// The validation rules (addr/key required + EXACTLY ONE auth method)
/// live on [`SignerArg::build`]; this struct is just the value
/// passthrough. Mirrors the [`SpiffeCliOpts`] / [`OidcCliOpts`]
/// pattern.
#[derive(Debug, Clone)]
struct VaultSignerCliOpts {
    addr: Option<String>,
    mount: String,
    key: Option<String>,
    namespace: Option<String>,
    token_file: Option<PathBuf>,
    approle_mount: String,
    approle_role_id: Option<String>,
    approle_secret_id_file: Option<PathBuf>,
}

impl VaultSignerCliOpts {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            addr: cli.signer_vault_addr.clone(),
            mount: cli.signer_vault_mount.clone(),
            key: cli.signer_vault_key.clone(),
            namespace: cli.signer_vault_namespace.clone(),
            token_file: cli.signer_vault_token_file.clone(),
            approle_mount: cli.signer_vault_approle_mount.clone(),
            approle_role_id: cli.signer_vault_approle_role_id.clone(),
            approle_secret_id_file: cli.signer_vault_approle_secret_id_file.clone(),
        }
    }
}

/// GCP-KMS-specific Signer options harvested from [`Cli`]. Same
/// passthrough pattern as [`VaultSignerCliOpts`]; validation rule
/// (key-version required + `/cryptoKeyVersions/` shape) lives on
/// [`SignerArg::build`].
#[derive(Debug, Clone)]
struct GcpKmsSignerCliOpts {
    key_version: Option<String>,
    endpoint: Option<String>,
}

impl GcpKmsSignerCliOpts {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            key_version: cli.signer_gcp_kms_key_version.clone(),
            endpoint: cli.signer_gcp_kms_endpoint.clone(),
        }
    }
}

/// Azure-KV-specific Signer options harvested from [`Cli`]. Same
/// passthrough pattern as the others; validation rules (HTTPS URL +
/// Managed HSM host + non-empty key name) live on
/// [`SignerArg::build`].
#[derive(Debug, Clone)]
struct AzureKvSignerCliOpts {
    vault_url: Option<String>,
    key_name: Option<String>,
    key_version: Option<String>,
}

impl AzureKvSignerCliOpts {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            vault_url: cli.signer_azure_kv_vault_url.clone(),
            key_name: cli.signer_azure_kv_key_name.clone(),
            key_version: cli.signer_azure_kv_key_version.clone(),
        }
    }
}

impl AttestorArg {
    /// Construct the configured Attestor.
    ///
    /// Async because `SpiffeAttestor::connect` reads the static
    /// bundle file or initial-syncs the Workload API stream, and
    /// `OidcAttestor::connect` performs the discovery-doc + initial
    /// JWKS fetch (or static-file read). All construction-time I/O
    /// happens here so a misconfigured `--attestor` flag fails the
    /// operator at startup, before any agent registers.
    async fn build(
        self,
        spiffe: SpiffeCliOpts,
        oidc: OidcCliOpts,
    ) -> Result<Arc<dyn yutha_attestor::Attestor>, anyhow::Error> {
        match self {
            Self::Native => Ok(Arc::new(yutha_attestor::NativeAttestor)),
            Self::Spiffe => build_spiffe_attestor(spiffe).await,
            Self::Oidc => build_oidc_attestor(oidc).await,
        }
    }
}

/// Translate [`SpiffeCliOpts`] into a constructed [`SpiffeAttestor`].
///
/// Validates the operator-facing invariants from
/// /spec/identity-keys/attestor-spiffe.md §10:
///
///   - `--attestor-spiffe-audience` is REQUIRED and non-empty.
///   - EXACTLY ONE of `--attestor-spiffe-socket` /
///     `--attestor-spiffe-bundle-file` is set.
///
/// Both checks fail at startup with operator-actionable messages that
/// name the offending flags, before any backend wiring runs.
async fn build_spiffe_attestor(
    opts: SpiffeCliOpts,
) -> Result<Arc<dyn yutha_attestor::Attestor>, anyhow::Error> {
    let audience = opts
        .audience
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--attestor spiffe requires --attestor-spiffe-audience \
                 (a swarm-specific value; see /spec/identity-keys/attestor-spiffe.md §6.1)"
            )
        })?
        .to_string();

    let source = match (&opts.socket, &opts.bundle_file) {
        (Some(socket), None) => yutha_attestor_spiffe::TrustBundleSource::WorkloadApi {
            socket: socket.clone(),
        },
        (None, Some(path)) => {
            yutha_attestor_spiffe::TrustBundleSource::StaticFile { path: path.clone() }
        }
        (None, None) => anyhow::bail!(
            "--attestor spiffe requires EXACTLY ONE of \
             --attestor-spiffe-socket (SPIRE Workload API) or \
             --attestor-spiffe-bundle-file (static JWKS); both are unset. \
             See /spec/identity-keys/attestor-spiffe.md §4."
        ),
        (Some(_), Some(_)) => anyhow::bail!(
            "--attestor spiffe requires EXACTLY ONE of \
             --attestor-spiffe-socket and --attestor-spiffe-bundle-file; \
             both are set. See /spec/identity-keys/attestor-spiffe.md §4.3."
        ),
    };

    let max_staleness = opts.max_staleness_secs.map(std::time::Duration::from_secs);

    let config = yutha_attestor_spiffe::SpiffeConfig {
        source,
        expected_audience: audience,
        max_staleness,
        clock_skew_tolerance_secs: opts.clock_skew_secs,
        connect_timeout_secs: opts.connect_timeout_secs,
    };

    let attestor = yutha_attestor_spiffe::SpiffeAttestor::connect(config)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "SPIFFE Attestor construction failed: {e}. See \
                 /spec/identity-keys/attestor-spiffe.md and \
                 docs/operator/spiffe-attestor.md for troubleshooting."
            )
        })?;

    Ok(Arc::new(attestor))
}

/// Translate [`OidcCliOpts`] into a constructed [`OidcAttestor`].
///
/// Validates the operator-facing invariants from
/// /spec/identity-keys/attestor-oidc.md §10:
///
///   - `--attestor-oidc-issuer` is REQUIRED and non-empty.
///   - `--attestor-oidc-audience` is REQUIRED and non-empty.
///   - AT MOST ONE of `--attestor-oidc-jwks-uri` /
///     `--attestor-oidc-jwks-file` may be set (neither → Discovery).
///
/// All checks fail at startup with operator-actionable messages that
/// name the offending flags, before any backend wiring runs.
///
/// [`OidcAttestor`]: yutha_attestor_oidc::OidcAttestor
async fn build_oidc_attestor(
    opts: OidcCliOpts,
) -> Result<Arc<dyn yutha_attestor::Attestor>, anyhow::Error> {
    let issuer = opts
        .issuer
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--attestor oidc requires --attestor-oidc-issuer \
                 (the IdP's issuer URL; see /spec/identity-keys/attestor-oidc.md §6.1)"
            )
        })?
        .to_string();

    let audience = opts
        .audience
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--attestor oidc requires --attestor-oidc-audience \
                 (a swarm-specific value; see /spec/identity-keys/attestor-oidc.md §6.1)"
            )
        })?
        .to_string();

    let source = match (&opts.jwks_uri, &opts.jwks_file) {
        (None, None) => yutha_attestor_oidc::JwksSource::Discovery {
            issuer_url: issuer.clone(),
        },
        (Some(url), None) => yutha_attestor_oidc::JwksSource::JwksUri { url: url.clone() },
        (None, Some(path)) => yutha_attestor_oidc::JwksSource::StaticFile { path: path.clone() },
        (Some(_), Some(_)) => anyhow::bail!(
            "--attestor oidc requires AT MOST ONE of \
             --attestor-oidc-jwks-uri or --attestor-oidc-jwks-file; \
             both are set. See /spec/identity-keys/attestor-oidc.md §4.4."
        ),
    };

    if opts.allow_insecure_http {
        tracing::warn!(
            "--attestor-oidc-allow-insecure-http is set; the OIDC Attestor \
             will accept HTTP (non-TLS) issuer + JWKS URLs. This violates \
             OpenID Connect Core §2 and MUST NOT be used in production."
        );
    }

    let config = yutha_attestor_oidc::OidcConfig {
        source,
        expected_issuer: issuer,
        expected_audience: audience,
        allowed_algs: opts.allowed_algs,
        project_claims: opts.project_claims,
        cache_ttl_secs: opts.cache_ttl_secs,
        max_staleness_secs: opts.max_staleness_secs,
        clock_skew_tolerance_secs: opts.clock_skew_secs,
        connect_timeout_secs: opts.connect_timeout_secs,
        allow_insecure_http: opts.allow_insecure_http,
    };

    let attestor = yutha_attestor_oidc::OidcAttestor::connect(config)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "OIDC Attestor construction failed: {e}. See \
                 /spec/identity-keys/attestor-oidc.md and \
                 docs/operator/oidc-attestor.md for troubleshooting."
            )
        })?;

    Ok(Arc::new(attestor))
}

impl SignerArg {
    /// Construct the configured Signer.
    ///
    /// Async because every cloud-KMS backend's `connect()` performs at
    /// least one round-trip at startup: Vault logs in (AppRole) or
    /// validates the token (Token auth), GCP KMS fetches the public
    /// key via `GetPublicKey`, Azure Managed HSM does the same via
    /// `get_key`. All construction-time I/O happens here so a
    /// misconfigured `--signer` fails the operator at startup, before
    /// any signing call runs. RFC 0017 §3.2.
    ///
    /// `InProcess` short-circuits without consuming the cloud-KMS
    /// option structs — its `Arc::new(InProcessSigner::generate())`
    /// matches the pre-Phase-G behaviour byte-for-byte and is the
    /// default, so the zero-config posture is preserved for
    /// integration tests and demos.
    async fn build(
        self,
        vault: VaultSignerCliOpts,
        gcp_kms: GcpKmsSignerCliOpts,
        azure_kv: AzureKvSignerCliOpts,
    ) -> Result<Arc<dyn Signer>, anyhow::Error> {
        match self {
            Self::InProcess => Ok(Arc::new(InProcessSigner::generate())),
            Self::Vault => build_vault_signer(vault).await,
            Self::GcpKms => build_gcp_kms_signer(gcp_kms).await,
            Self::AzureKv => build_azure_kv_signer(azure_kv).await,
        }
    }
}

/// Translate [`VaultSignerCliOpts`] into a constructed [`VaultSigner`].
///
/// Validates the operator-facing invariants from RFC 0017 §3.2 and
/// docs/operator/vault-signer.md:
///
///   - `--signer-vault-addr` is REQUIRED and non-empty.
///   - `--signer-vault-key` is REQUIRED and non-empty.
///   - EXACTLY ONE of (a) `--signer-vault-token-file` or
///     (b) `--signer-vault-approle-role-id` +
///     `--signer-vault-approle-secret-id-file` is provided.
///
/// Token and secret-id files are read synchronously at startup (this
/// runs before the gRPC server binds; blocking I/O is fine for one-
/// shot config) and trimmed of trailing whitespace so files written
/// by `echo "$TOKEN" > token` work without surprise.
///
/// All checks fail at startup with operator-actionable messages that
/// name the offending flags, before any backend wiring runs.
///
/// [`VaultSigner`]: yutha_signer_vault::VaultSigner
async fn build_vault_signer(opts: VaultSignerCliOpts) -> Result<Arc<dyn Signer>, anyhow::Error> {
    let address = opts
        .addr
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--signer vault requires --signer-vault-addr \
                 (Vault HTTPS endpoint; see docs/operator/vault-signer.md)"
            )
        })?
        .to_string();

    let key_name = opts
        .key
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--signer vault requires --signer-vault-key \
                 (transit key name; see docs/operator/vault-signer.md)"
            )
        })?
        .to_string();

    // EXACTLY ONE auth method. Token > AppRole precedence mirrors
    // `VaultAuth::from_env()` so the CLI and env-var entry points
    // share a single mental model.
    let auth = match (
        &opts.token_file,
        &opts.approle_role_id,
        &opts.approle_secret_id_file,
    ) {
        (Some(token_path), None, None) => {
            let token = std::fs::read_to_string(token_path)
                .with_context(|| format!("read Vault token file {}", token_path.display()))?
                .trim()
                .to_string();
            if token.is_empty() {
                anyhow::bail!(
                    "Vault token file {} is empty after trim",
                    token_path.display()
                );
            }
            yutha_signer_vault::VaultAuth::Token(token)
        }
        (None, Some(role_id), Some(secret_id_path)) => {
            let secret_id = std::fs::read_to_string(secret_id_path)
                .with_context(|| {
                    format!(
                        "read Vault AppRole secret-id file {}",
                        secret_id_path.display()
                    )
                })?
                .trim()
                .to_string();
            if secret_id.is_empty() {
                anyhow::bail!(
                    "Vault AppRole secret-id file {} is empty after trim",
                    secret_id_path.display()
                );
            }
            yutha_signer_vault::VaultAuth::AppRole {
                mount: opts.approle_mount.clone(),
                role_id: role_id.clone(),
                secret_id,
            }
        }
        (None, None, None) => anyhow::bail!(
            "--signer vault requires EXACTLY ONE auth method: \
             --signer-vault-token-file <path>, OR \
             --signer-vault-approle-role-id <id> + \
             --signer-vault-approle-secret-id-file <path>. \
             See docs/operator/vault-signer.md."
        ),
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => anyhow::bail!(
            "--signer vault requires EXACTLY ONE auth method; \
             --signer-vault-token-file is mutually exclusive with the \
             --signer-vault-approle-* pair. See docs/operator/vault-signer.md."
        ),
        (None, Some(_), None) | (None, None, Some(_)) => anyhow::bail!(
            "--signer vault AppRole auth requires BOTH \
             --signer-vault-approle-role-id and \
             --signer-vault-approle-secret-id-file; only one is set. \
             See docs/operator/vault-signer.md."
        ),
    };

    let config = yutha_signer_vault::VaultConfig {
        address,
        mount: opts.mount,
        key_name,
        auth,
        namespace: opts.namespace,
    };

    let signer = yutha_signer_vault::VaultSigner::connect(config)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Vault Signer construction failed: {e}. See \
                 docs/operator/vault-signer.md for troubleshooting \
                 (mount path, key type=ed25519, auth-method credentials)."
            )
        })?;

    Ok(Arc::new(signer))
}

/// Translate [`GcpKmsSignerCliOpts`] into a constructed [`GcpKmsSigner`].
///
/// Validates the operator-facing invariants from RFC 0017 §3.2 and
/// docs/operator/gcp-kms-signer.md:
///
///   - `--signer-gcp-kms-key-version` is REQUIRED and non-empty.
///
/// The full Cloud KMS resource-path shape check
/// (`/cryptoKeyVersions/<n>` present) is delegated to
/// [`GcpKmsConfig::new`] which fails fast with a Path-named error.
/// Auth is via Application Default Credentials (ADC); set
/// `GOOGLE_APPLICATION_CREDENTIALS` or run on a GCE/GKE instance
/// with the right service account attached.
///
/// [`GcpKmsSigner`]: yutha_signer_gcp_kms::GcpKmsSigner
/// [`GcpKmsConfig::new`]: yutha_signer_gcp_kms::GcpKmsConfig::new
async fn build_gcp_kms_signer(opts: GcpKmsSignerCliOpts) -> Result<Arc<dyn Signer>, anyhow::Error> {
    let key_version = opts
        .key_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--signer gcp-kms requires --signer-gcp-kms-key-version \
                 (full Cloud KMS resource path including /cryptoKeyVersions/<n>; \
                 see docs/operator/gcp-kms-signer.md)"
            )
        })?
        .to_string();

    let config =
        yutha_signer_gcp_kms::GcpKmsConfig::new(key_version, opts.endpoint).map_err(|e| {
            anyhow::anyhow!(
                "--signer gcp-kms: invalid configuration: {e}. \
                 See docs/operator/gcp-kms-signer.md."
            )
        })?;

    let signer = yutha_signer_gcp_kms::GcpKmsSigner::connect(config)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "GCP KMS Signer construction failed: {e}. See \
                 docs/operator/gcp-kms-signer.md for troubleshooting \
                 (ADC credentials, key purpose=ASYMMETRIC_SIGN, \
                 algorithm=EC_SIGN_ED25519)."
            )
        })?;

    Ok(Arc::new(signer))
}

/// Translate [`AzureKvSignerCliOpts`] into a constructed [`AzureKvSigner`].
///
/// Validates the operator-facing invariants from RFC 0017 §3.2 and
/// docs/operator/azure-kv-signer.md:
///
///   - `--signer-azure-kv-vault-url` is REQUIRED and non-empty.
///   - `--signer-azure-kv-key-name` is REQUIRED and non-empty.
///
/// The HTTPS and non-empty-key-name shape checks are delegated to
/// [`AzureKvConfig::new`]. The Managed-HSM-vs-standard-Key-Vault
/// distinction surfaces at `connect()` time (the SDK fails with
/// [`SignerError::UnsupportedAlgorithm`] when pointed at a standard
/// Key Vault that doesn't support Ed25519); the backend also emits a
/// startup warning to make the diagnosis obvious. Auth is via
/// `DefaultAzureCredential` — env vars / managed identity / Azure CLI
/// in that order.
///
/// [`AzureKvSigner`]: yutha_signer_azure_kv::AzureKvSigner
/// [`AzureKvConfig::new`]: yutha_signer_azure_kv::AzureKvConfig::new
/// [`SignerError::UnsupportedAlgorithm`]: yutha_signer::SignerError::UnsupportedAlgorithm
async fn build_azure_kv_signer(
    opts: AzureKvSignerCliOpts,
) -> Result<Arc<dyn Signer>, anyhow::Error> {
    let vault_url = opts
        .vault_url
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--signer azure-kv requires --signer-azure-kv-vault-url \
                 (Managed HSM URL, https://*.managedhsm.azure.net; \
                 see docs/operator/azure-kv-signer.md)"
            )
        })?
        .to_string();

    let key_name = opts
        .key_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--signer azure-kv requires --signer-azure-kv-key-name \
                 (HSM key name; see docs/operator/azure-kv-signer.md)"
            )
        })?
        .to_string();

    let config = yutha_signer_azure_kv::AzureKvConfig::new(vault_url, key_name, opts.key_version)
        .map_err(|e| {
        anyhow::anyhow!(
            "--signer azure-kv: invalid configuration: {e}. \
                 See docs/operator/azure-kv-signer.md."
        )
    })?;

    let signer = yutha_signer_azure_kv::AzureKvSigner::connect(config)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Azure Managed HSM Signer construction failed: {e}. See \
                 docs/operator/azure-kv-signer.md for troubleshooting \
                 (Managed HSM tier required for Ed25519, \
                 DefaultAzureCredential setup, key permissions)."
            )
        })?;

    Ok(Arc::new(signer))
}

/// Three-way control for `Topology.require_capability_for_send`. See
/// RFC 0007. `Auto` derives from `AdmissionModeArg`; the explicit
/// values let operators force-set during migration windows.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum RequireCapForSendArg {
    Auto,
    True,
    False,
}

impl RequireCapForSendArg {
    fn resolve(self, admission: AdmissionModeArg) -> bool {
        match self {
            Self::Auto => matches!(admission, AdmissionModeArg::Closed),
            Self::True => true,
            Self::False => false,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    info!("yutha control-plane starting up");

    let bootstrap_identity = match cli.bootstrap_seed.as_deref() {
        Some(seed_hex) => Some(BootstrapIdentity::from_seed_hex(seed_hex)?),
        None => None,
    };
    let require_cap_for_send = cli.require_cap_for_send.resolve(cli.admission_mode);
    let operator_public_key = match cli.operator_public_key.as_deref() {
        Some(hex) => Some(parse_operator_public_key(hex)?),
        None => None,
    };

    // Resolve the anchor flags up front so partial-config errors fail
    // fast before any backend is constructed. The actual driver-spawn
    // step happens later (after the receipt store + bootstrap identity
    // are available) — see H6c wiring further down.
    let anchor_config = resolve_anchor_config(&cli)?;
    if let Some(ref ac) = anchor_config {
        info!(
            rpc_url = %ac.rpc_url,
            package_id = %ac.package_id_hex,
            swarm_anchor_id = %ac.swarm_anchor_id_hex,
            sealer_key_file = ?ac.sealer_key_file,
            batch_count_threshold = ac.batch_count_threshold,
            batch_time_threshold = ?ac.batch_time_threshold,
            max_batch_size = ac.max_batch_size,
            "Sui anchoring ENABLED (RFC 0014 Layer 1): driver will be spawned after backends initialize"
        );
    } else {
        info!("Sui anchoring disabled (no --anchor-* flags set)");
    }
    // Resolve workload-extension names to their embedded sources.
    // Bail with a clear error on unknown names rather than silently
    // ignoring them — typos would otherwise mask "constitution
    // doesn't validate" failures downstream.
    let mut workload_sources: Vec<&'static str> = Vec::new();
    for name in &cli.workloads {
        match yutha_cedar_plus::workload_extension_by_name(name) {
            Some(src) => workload_sources.push(src),
            None => anyhow::bail!(
                "--workload {name}: unknown workload extension. Known names: \
                 support-queue, code-review (see /spec/constitution/canonical-schemas/v1.1.0/)"
            ),
        }
    }
    // Construct the inner receipt store (the persistence boundary)
    // based on the operator's chosen backend. Wrapping in the
    // PublishingReceiptStore decorator happens inside
    // bootstrap_backends regardless of backend choice.
    //
    // We hold the concrete store as an Arc once, then cast to both
    // `Arc<dyn ReceiptStore>` (for the rest of bootstrap_backends) AND
    // `Arc<dyn SealStore>` (for the H6 anchor driver, if enabled).
    // Once the dyn cast happens via `Arc::new(store as Arc<dyn ...>)`,
    // we can't recover the other trait object from it — so the fork
    // has to happen here, at the typed Arc.
    let (inner_receipt_store, anchor_seal_store): (
        Arc<dyn ReceiptStore>,
        Arc<dyn yutha_receipt::SealStore>,
    ) = match cli.receipt_backend {
        ReceiptBackendArg::Memory => {
            info!("receipt backend: in-memory (non-persistent)");
            let store = Arc::new(MemoryReceiptStore::new());
            (
                Arc::clone(&store) as Arc<dyn ReceiptStore>,
                store as Arc<dyn yutha_receipt::SealStore>,
            )
        }
        ReceiptBackendArg::Postgres => {
            let url = cli.postgres_url.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "--receipt-backend postgres requires --postgres-url \
                     (or YUTHA_POSTGRES_URL=postgresql://...)"
                )
            })?;
            info!("receipt backend: postgres (running migrations)");
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .connect(url)
                .await
                .with_context(|| format!("connect postgres {url}"))?;
            let store = Arc::new(yutha_backend_postgres_receipt::PostgresStore::new(pool));
            store.migrate().await.context("postgres migrate")?;
            (
                Arc::clone(&store) as Arc<dyn ReceiptStore>,
                store as Arc<dyn yutha_receipt::SealStore>,
            )
        }
    };

    // Snapshot the bootstrap swarm_id before `bootstrap_identity` is
    // moved into `bootstrap_backends` below. The Sui-anchor driver
    // (if enabled) needs this to construct the SuiSealer; it MUST
    // equal the `swarm_id` stored on the on-chain `SwarmAnchor` (the
    // operator's responsibility, documented in
    // /docs/operator/sui-anchoring.md). SwarmId is Copy so this is
    // a no-op clone.
    let bootstrap_swarm_id_for_anchor: Option<SwarmId> =
        bootstrap_identity.as_ref().map(|bi| bi.swarm_id);

    // Snapshot the receipt store for the anchor candidate source.
    // bootstrap_backends wraps it in PublishingReceiptStore for the
    // gRPC handlers; the driver wants the underlying store directly
    // so it sees all appended receipts, including ones written by
    // the gRPC path.
    let anchor_receipt_store_for_candidates = Arc::clone(&inner_receipt_store);

    // Phase D / RFC 0016: construct the configured Attestor before
    // bootstrap_backends so a misconfigured --attestor flag (e.g.,
    // --attestor spiffe with neither --attestor-spiffe-socket nor
    // --attestor-spiffe-bundle-file) fails the operator FAST with a
    // clear flag-naming message, before any backend wiring runs.
    //
    // For `--attestor spiffe` (Phase E), construction includes I/O:
    // either reading + parsing the static JWKS file, or initial-
    // syncing the SPIRE Workload API stream (bounded by
    // --attestor-spiffe-connect-timeout-secs). Both happen here, so
    // SPIFFE-related startup failures land at process boot rather
    // than at first registration.
    let spiffe_opts = SpiffeCliOpts::from_cli(&cli);
    let oidc_opts = OidcCliOpts::from_cli(&cli);
    let attestor: Arc<dyn yutha_attestor::Attestor> =
        cli.attestor.build(spiffe_opts, oidc_opts).await?;

    // Phase G: construct the control plane's signing identity from the
    // configured `--signer` backend BEFORE `bootstrap_backends`, so a
    // misconfigured signer fails the operator at startup with a flag-
    // named error (rather than partway through backend wiring). The
    // selected `InProcess` default short-circuits to a generated
    // keypair and preserves the pre-Phase-G zero-config posture.
    //
    // The bootstrap-agent signer (built inside `bootstrap_backends`
    // from `--bootstrap-seed` or randomly) is intentionally kept as
    // `InProcessSigner` and is NOT governed by `--signer`. It's a
    // testing-only identity that operators don't externalise to a
    // cloud KMS — see /spec/identity-keys/attestor-*.md for the
    // distinction.
    let vault_signer_opts = VaultSignerCliOpts::from_cli(&cli);
    let gcp_kms_signer_opts = GcpKmsSignerCliOpts::from_cli(&cli);
    let azure_kv_signer_opts = AzureKvSignerCliOpts::from_cli(&cli);
    let cp_signer: Arc<dyn Signer> = cli
        .signer
        .build(vault_signer_opts, gcp_kms_signer_opts, azure_kv_signer_opts)
        .await?;

    let (state, enforcement_rx) = bootstrap_backends(
        bootstrap_identity,
        cli.admission_mode,
        require_cap_for_send,
        operator_public_key,
        &workload_sources,
        inner_receipt_store,
        attestor,
        cp_signer,
    )
    .await?;

    // F10f: spin up the enforcement-engine forwarder + scheduler-tick
    // background tasks. They run for the lifetime of the process; both
    // exit cleanly when the gRPC server shuts down (the forwarder exits
    // when every publisher Sender is dropped — and the only Sender
    // lives inside the receipt-store Arc held by ControlPlaneState).
    spawn_enforcement_forwarder(Arc::clone(&state), enforcement_rx);
    spawn_scheduler_tick(Arc::clone(&state));

    // H6c: Sui-anchor driver. Spawned only when all four anchor flags
    // were set; the resolver above already validated all-or-nothing.
    // Requires the bootstrap-seed-derived swarm_id (must match the
    // on-chain SwarmAnchor.swarm_id), so we additionally require
    // `--bootstrap-seed` when anchoring is enabled — the random
    // identity branch can't anchor because there's no off-chain
    // source for the swarm_id the operator put on-chain.
    if let Some(ac) = anchor_config {
        let swarm_id = bootstrap_swarm_id_for_anchor.ok_or_else(|| {
            anyhow::anyhow!(
                "Sui anchoring requires --bootstrap-seed (the SwarmAnchor's on-chain \
                 swarm_id must match the seed-derived value)"
            )
        })?;
        spawn_anchor_driver(
            ac,
            swarm_id,
            anchor_receipt_store_for_candidates,
            anchor_seal_store,
        )
        .await
        .context("spawn Sui anchor driver")?;
    }

    serve_grpc(&cli, state).await?;
    Ok(())
}

/// Construct the [`yutha_backend_sui_anchor::AnchorDriver`] from the
/// resolved CLI config and spawn its `run()` loop. Reads the on-chain
/// [`SwarmAnchor`] state once to seed the initial watermark (the
/// driver's monotonic high-water mark across batches).
///
/// Returns on success once the spawn task is dispatched; the driver
/// itself runs forever (until the process exits or a future
/// `shutdown` is wired in).
async fn spawn_anchor_driver(
    cfg: ResolvedAnchorConfig,
    swarm_id: SwarmId,
    receipt_store: Arc<dyn ReceiptStore>,
    seal_store: Arc<dyn yutha_receipt::SealStore>,
) -> anyhow::Result<()> {
    use yutha_backend_sui_anchor::{
        load_sealer_key_from_file, AnchorDriver, AnchorDriverConfig, ReceiptStoreCandidateSource,
        RpcAnchorClient, SuiSealer,
    };

    // 1. Load the sealer key. File contains a single `suiprivkey1…`
    //    bech32 string; the helper strips trailing whitespace.
    let sealer_key = load_sealer_key_from_file(&cfg.sealer_key_file)
        .with_context(|| format!("load sealer key from {}", cfg.sealer_key_file.display()))?;

    // 2. Connect the Sui RPC client. Connection is lazy (the underlying
    //    tonic Channel doesn't dial until first RPC), so this is cheap.
    let client = RpcAnchorClient::connect(
        &cfg.rpc_url,
        sealer_key.clone(),
        &cfg.package_id_hex,
        &cfg.swarm_anchor_id_hex,
    )
    .context("connect Sui RPC anchor client")?;

    // 3. Read the on-chain SwarmAnchor state once at startup — gives us
    //    the initial watermark (last_ns_range_end of the most recent
    //    successful commit, or 0 if no commits yet).
    let anchor_state = {
        use yutha_backend_sui_anchor::SuiAnchorClient;
        client
            .read_anchor_state()
            .await
            .context("read initial SwarmAnchor state")?
    };
    info!(
        batch_count = anchor_state.batch_count,
        last_ns_range_end = anchor_state.last_ns_range_end,
        "Sui anchor: read initial on-chain state"
    );

    // 4. Build the sealer (composes the client + the H2 LocalSealer
    //    preimage path). The swarm_id MUST match the on-chain anchor's
    //    swarm_id — enforced by the operator at create_swarm_anchor
    //    time; mismatch surfaces as `ESealerKeyMismatch` (code 9) on
    //    the first commit because the canonical preimage diverges.
    let sealer = Arc::new(SuiSealer::new(Box::new(client), sealer_key, swarm_id));

    // 5. Wrap the receipt store as the driver's candidate source.
    let candidate_source = Arc::new(ReceiptStoreCandidateSource::new(receipt_store));

    // 6. Assemble the driver config from the CLI flags + the
    //    non-knob defaults (initial_backoff, max_backoff,
    //    idle_poll_interval, retry_attempts).
    let driver_cfg = AnchorDriverConfig {
        batch_count_threshold: cfg.batch_count_threshold,
        batch_time_threshold: cfg.batch_time_threshold,
        max_batch_size: cfg.max_batch_size,
        ..Default::default()
    };

    let driver = AnchorDriver::new(
        driver_cfg,
        sealer,
        candidate_source,
        seal_store,
        anchor_state.last_ns_range_end,
    );

    // 7. Spawn. The loop runs forever (logs each seal via tracing::info;
    //    transient failures back off and retry; permanent failures log
    //    at error and continue the loop). When the process exits, tokio
    //    runtime shutdown cancels the task.
    tokio::spawn(driver.run());
    info!("Sui anchor: driver spawned (cadence loop running)");
    Ok(())
}

/// Drain receipts published by [`PublishingReceiptStore`] and forward
/// them to the [`yutha_cedar_plus::EnforcementEngine`].
///
/// Each owned [`EnforcementReceiptView`] is converted into a borrowed
/// [`ReceiptView`] and passed to [`EnforcementEngine::on_receipt`].
/// Any [`yutha_cedar_plus::EnforcementEffect`]s the engine returns
/// are emitted as `enforcement.*` receipts via
/// [`emit_enforcement_receipt`] (F12). Those emitted receipts loop
/// back through the same channel, but the engine's pattern matcher
/// terminates the cycle: `enforcement.*` kinds only apply reputation
/// deltas and quarantine flips, they don't schedule further effects.
fn spawn_enforcement_forwarder(
    state: Arc<ControlPlaneState>,
    mut rx: mpsc::Receiver<EnforcementReceiptView>,
) {
    tokio::spawn(async move {
        info!("F12: enforcement-receipt forwarder task started");
        while let Some(view) = rx.recv().await {
            // Phase 3b (RFC 0018 §3.5): the enforcement engine MUST
            // NOT react to shadow-mode eval receipts. Shadow is
            // observation-only — its denies don't bump reputation,
            // don't schedule quarantine, don't move sliding-window
            // counters. The receipt store still holds them (the
            // PublishingReceiptStore fans every receipt onto this
            // channel; the substrate's responsibility to the audit
            // trail is unchanged), but the engine never sees them.
            //
            // This is the only filter point — the build_view
            // extractor stays substrate-agnostic, the engine stays
            // ignorant of shadow semantics, and any future
            // additional consumer of shadow receipts (e.g., a Phase
            // 3f OTel exporter surfacing shadow divergence as a
            // metric) subscribes to its own channel.
            if view
                .action_kind
                .starts_with("constitution.evaluate.shadow.")
            {
                continue;
            }
            let borrowed = ReceiptView {
                action_kind: view.action_kind.as_str(),
                principal_id: view.principal_id.as_deref(),
                deny_reason: view.deny_reason.as_deref(),
                forbid_rule_id: view.forbid_rule_id.as_deref(),
                occurred_at_unix_ns: view.occurred_at_unix_ns,
                occurred_at_wall_clock: view.occurred_at_wall_clock.as_str(),
                reputation_delta: view.reputation_delta.clone(),
            };
            let effects = state.enforcement.on_receipt(borrowed).await;
            emit_effects(&state, &effects, "forwarder").await;
        }
        info!("F12: enforcement-receipt forwarder task exiting (channel closed)");
    });
}

/// Drive the enforcement engine's scheduled-transitions queue.
///
/// Per [`yutha_cedar_plus::EnforcementEngine::poll_scheduled`] the
/// control plane is responsible for ticking wall-clock advance. A
/// 1-second cadence matches the spec's "typically once per second"
/// note in enforcement.rs and gives sub-second responsiveness without
/// drowning the engine in empty polls. Any effects produced are
/// emitted as `enforcement.*` receipts via [`emit_enforcement_receipt`]
/// (F12).
fn spawn_scheduler_tick(state: Arc<ControlPlaneState>) {
    use std::time::Duration;
    tokio::spawn(async move {
        info!("F12: enforcement scheduler-tick task started (1s cadence)");
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        // First tick fires immediately; skip it so we don't poll
        // before any receipts have a chance to land.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = Timestamp::now().wall_clock;
            let effects = state.enforcement.poll_scheduled(&now).await;
            emit_effects(&state, &effects, "scheduler").await;
        }
    });
}

/// Persist a batch of [`yutha_cedar_plus::EnforcementEffect`]s as
/// `enforcement.*` receipts. Shared between the forwarder and the
/// scheduler tick — both surfaces produce the same effect type and
/// emit it the same way.
///
/// Errors emit a warn log and continue; an effect failing to persist
/// is a degraded-audit-trail event but should not stop the engine
/// from processing the next one. The most common failure mode is the
/// activate-time race where the forwarder fires before the operator
/// has activated a constitution; in that case there's no
/// `constitution_hash` to embed in the receipt, so we skip emission
/// and the effect is lost.
async fn emit_effects(
    state: &Arc<ControlPlaneState>,
    effects: &[yutha_cedar_plus::EnforcementEffect],
    source: &str,
) {
    if effects.is_empty() {
        return;
    }
    let Some(active) = state.cedar_plus.current().await else {
        for effect in effects {
            warn!(
                action_kind = %effect.action_kind,
                target_agent_id = %effect.target_agent_id,
                source,
                "F12: skipping enforcement-receipt emission — no active constitution"
            );
        }
        return;
    };
    let constitution_hash = active.constitution.constitution_hash.clone();
    let constitution_version = active.constitution.constitution_version.clone();
    let swarm_id = active.constitution.swarm_id;
    drop(active);

    for effect in effects {
        match emit_enforcement_receipt(
            state,
            effect,
            swarm_id,
            &constitution_hash,
            &constitution_version,
        )
        .await
        {
            Ok(receipt_id) => {
                info!(
                    action_kind = %effect.action_kind,
                    target_agent_id = %effect.target_agent_id,
                    enforcement_rule_id = %effect.enforcement_rule_id,
                    reputation_delta = %effect.reputation_delta.0,
                    receipt_id = %receipt_id,
                    source,
                    "F12: enforcement effect emitted as receipt"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    action_kind = %effect.action_kind,
                    target_agent_id = %effect.target_agent_id,
                    source,
                    "F12: enforcement-receipt emission failed; effect lost"
                );
            }
        }
    }
}

/// Deterministically-derived bootstrap-agent identity, optionally
/// supplied by the operator via `--bootstrap-seed` /
/// `YUTHA_BOOTSTRAP_SEED`.
///
/// All three fields are derived from the same 32-byte seed so a
/// client that holds the seed can reconstruct them without any
/// out-of-band coordination with the running server.
struct BootstrapIdentity {
    /// Wrapped in `InProcessSigner` so the bootstrap-signing path is the
    /// same shape as every other signing path (RFC 0015). For
    /// development / integration-test use; production deployments would
    /// front the bootstrap identity with a KMS-backed `Signer` impl.
    signer: InProcessSigner,
    agent_id: AgentId,
    swarm_id: SwarmId,
}

impl BootstrapIdentity {
    fn from_seed_hex(seed_hex: &str) -> anyhow::Result<Self> {
        let seed_bytes =
            hex::decode(seed_hex.trim()).context("bootstrap-seed: hex decode failed")?;
        let seed: [u8; 32] = seed_bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!(
                "bootstrap-seed: expected 32 raw bytes (64 hex chars), got {} bytes",
                v.len()
            )
        })?;
        // Ed25519 takes the seed directly; wrap in InProcessSigner so the
        // downstream construction code can pass `&dyn Signer` uniformly.
        let signer = InProcessSigner::from_bytes(&seed);
        // Domain-separated derivations: a one-byte tag distinguishes
        // the two identifier streams so they can't ever collide.
        let mut agent_input = Vec::with_capacity(33);
        agent_input.extend_from_slice(&seed);
        agent_input.push(0x01);
        let agent_id = AgentId::from_bytes(&sha256(&agent_input).digest[..16])
            .context("bootstrap-seed: derive agent_id")?;

        let mut swarm_input = Vec::with_capacity(33);
        swarm_input.extend_from_slice(&seed);
        swarm_input.push(0x02);
        let swarm_id = SwarmId::from_bytes(&sha256(&swarm_input).digest[..16])
            .context("bootstrap-seed: derive swarm_id")?;

        warn!(
            agent_id = %agent_id,
            swarm_id = %swarm_id,
            "bootstrap-seed in use — bootstrap identity is deterministically derivable by anyone with the seed. Intended for integration tests; never enable in production unless the seed comes from a KMS-backed source."
        );

        Ok(Self {
            signer,
            agent_id,
            swarm_id,
        })
    }
}

/// Bring up the in-memory backends and register a bootstrap agent.
///
/// This is the Phase-1 substrate exercise: every backend gets constructed
/// in the right order, the cp identity is wired in, the bootstrap agent
/// is admitted, and the audit trail is sanity-checked. Same logic as the
/// pre-gRPC binary; we just return the assembled state at the end so the
/// gRPC handlers can share it.
// 8 params (was 7 pre-Phase-G; `cp_signer` joined as the per-backend
// custody handle for the control plane's signing identity). Bundling
// into a config struct would obscure the parameter origins (`cli.*`
// vs constructed-once values) without buying call-site clarity — the
// only call site is `main()`. Matches the s1/s4/s5/s6/s7 conformance
// scenarios' posture for similarly construction-heavy entry points.
#[allow(clippy::too_many_arguments)]
async fn bootstrap_backends(
    bootstrap_identity: Option<BootstrapIdentity>,
    admission_mode: AdmissionModeArg,
    require_capability_for_send: bool,
    operator_public_key: Option<yutha_core::PublicKey>,
    workload_extensions: &[&str],
    inner_receipt_store: Arc<dyn ReceiptStore>,
    attestor: Arc<dyn yutha_attestor::Attestor>,
    cp_signer: Arc<dyn Signer>,
) -> anyhow::Result<(
    Arc<ControlPlaneState>,
    mpsc::Receiver<EnforcementReceiptView>,
)> {
    // If the operator supplied a deterministic bootstrap seed, the
    // resulting (signing_key, agent_id, swarm_id) triplet replaces the
    // random defaults below. Everything downstream — the CLOSED
    // admission policy with this agent in the allowlist, the receipt
    // emission path, the resolver — works identically whether the
    // identity is random or seed-derived.
    //
    // (Match rather than `unwrap_or_else(SwarmId::new)` because
    // clippy's `unwrap_or_default` suggestion is wrong here:
    // `SwarmId::new()` produces a fresh UUID v7, whereas
    // `SwarmId::default()` would be all zeros — very different
    // semantics.)
    let swarm_id = match bootstrap_identity.as_ref() {
        Some(b) => b.swarm_id,
        None => SwarmId::new(),
    };

    // F10f: wrap the inner receipt store with a publisher that fans
    // every successful append onto an mpsc channel. The main task
    // drains that channel and forwards enforcement-relevant receipts
    // into the EnforcementEngine. Per the F10 design decision (see
    // receipt_publisher.rs), the wrapper sits behind the
    // Arc<dyn ReceiptStore> the rest of the system already holds, so
    // every existing emit site picks up publishing automatically with
    // no per-callsite change.
    //
    // The inner store is selected by `--receipt-backend` and passed
    // in by the caller (so we don't pay the in-memory cost when the
    // operator chose Postgres).
    let (publishing_store, enforcement_rx) = PublishingReceiptStore::new(inner_receipt_store);
    let receipt_store: Arc<dyn ReceiptStore> = publishing_store;
    let passport_store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passport_store)));
    info!("resolver adapter wired (passport → receipt)");

    // Phase G: `cp_signer` is now constructed in `main()` from the
    // configured `--signer` backend (InProcess by default; Vault /
    // GCP KMS / Azure KV when the operator opts in) and threaded
    // through as an `Arc<dyn Signer>`. We pull the public key via the
    // trait method here — works uniformly across all backends because
    // every Signer implementation exposes `public_key()` synchronously
    // (RFC 0015 §3.1; the underlying material is cached at connect
    // time so this is a pure accessor, not a network call).
    let cp_public_key = cp_signer.public_key();
    let cp_agent_id = AgentId::new();
    let cp_passport = Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").context("parse spec version")?)
        .agent_id(cp_agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(cp_public_key)
        .owner("yutha control plane")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(cp_signer.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!("build cp passport: {e}"))?;
    passport_store
        .register(cp_passport)
        .await
        .context("register control-plane passport")?;
    info!(
        cp_agent_id = %cp_agent_id,
        "control-plane identity registered (genesis; no receipt)"
    );
    let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_signer));

    // F10g: the cap layer consults the enforcement engine to refuse
    // checks / issuances against quarantined subjects. Construct the
    // engine up-front so it can be shared between the cap store and
    // the ControlPlaneState (where the ConstitutionService.Activate
    // path swaps in a fresh enforcement state on activation).
    let enforcement = Arc::new(yutha_cedar_plus::EnforcementEngine::new());
    let quarantine_source: Arc<dyn yutha_capability::QuarantineSource> = Arc::new(
        quarantine_adapter::EnforcementEngineQuarantineSource::new(Arc::clone(&enforcement)),
    );
    let capability_store: Arc<dyn CapabilityStore> = Arc::new(MemoryCapabilityStore::new(
        Arc::clone(&receipt_store),
        Arc::clone(&resolver),
        Arc::clone(&cp),
        quarantine_source,
    ));
    let transport: Arc<dyn Transport> = Arc::new(MemoryTransport::new(
        Arc::clone(&receipt_store),
        Arc::clone(&resolver),
        Arc::clone(&cp),
    ));

    let (bootstrap_signer, bootstrap_agent_id) = match bootstrap_identity {
        Some(b) => (b.signer, b.agent_id),
        None => (InProcessSigner::generate(), AgentId::new()),
    };
    // expires_at is required by open-mode admission and ignored by
    // closed-mode, so we set it unconditionally. Use a far-future
    // sentinel: the bootstrap identity is server-managed and not
    // expected to rotate within this process's lifetime.
    let bootstrap_expires_at = Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2)
        .map_err(|e| anyhow::anyhow!("build bootstrap expires_at: {e}"))?;
    let bootstrap_passport = Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").context("parse spec version")?)
        .agent_id(bootstrap_agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(bootstrap_signer.public_key())
        .owner("yutha-control-plane bootstrap")
        .framework("none", "n/a")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .expires_at(bootstrap_expires_at)
        .sign(&bootstrap_signer)
        .await
        .map_err(|e| anyhow::anyhow!("build bootstrap passport: {e}"))?;

    let (admission, topology_mode) = match admission_mode {
        AdmissionModeArg::Closed => (
            AdmissionPolicy::Closed(ClosedPolicy {
                allowlisted_agents: vec![bootstrap_agent_id],
                ..Default::default()
            }),
            TopologyMode::Closed,
        ),
        AdmissionModeArg::Open => (
            // OpenPolicy::default() requires tier ≥ Standard, which
            // would reject every Minimal-tier demo passport (including
            // this binary's own bootstrap agent). Relax to Minimal
            // here — open mode is already an explicit "demo only" knob
            // (see the WARN below), so the tier floor doesn't add
            // production safety it can't already get from staying in
            // closed mode.
            AdmissionPolicy::Open(OpenPolicy {
                min_passport_tier: PassportTier::Minimal,
                ..Default::default()
            }),
            TopologyMode::Open,
        ),
    };
    if matches!(admission_mode, AdmissionModeArg::Open) {
        warn!(
            "admission mode: OPEN — any well-formed passport is admitted. \
             Intended for demos and local development only."
        );
    }
    info!(
        require_capability_for_send,
        "Send-path capability enforcement (RFC 0007)"
    );
    let topology = Topology {
        spec_version: SpecVersion::parse("1.0.0").context("parse spec version")?,
        swarm_id,
        mode: topology_mode,
        admission,
        max_capability_lifetime_seconds: 90 * 24 * 60 * 60,
        max_capability_chain_depth: 8,
        default_envelope_ttl_seconds: 300,
        max_epoch_skew: 256,
        external_sends_permitted: false,
        // RFC 0007: governs whether EnvelopeService.Send rejects
        // sends that don't present a capability_id. Resolved from
        // the --require-cap-for-send CLI: `auto` derives from
        // admission_mode (closed → true, open → false), the
        // explicit values override.
        require_capability_for_send,
        initial_constitution_version: "1.0.0".into(),
        operator_key_fingerprint: vec![0u8; 32],
        operator_signature: None,
    };
    // Phase D / RFC 0016: the Attestor that the registry consults on
    // every registration. The `--attestor` flag selects the flavor
    // (native today; spiffe / oidc reserved for Phase E / F).
    // NativeAttestor accepts empty `external_credential` and records
    // `yutha:native:<hex>` as the attested external identity — the
    // hobby-path default. The same `Arc<dyn Attestor>` flows into
    // MemoryRegistry below AND onto ControlPlaneState so handlers can
    // surface the configured flavor in diagnostic responses.

    let registry: Arc<dyn Registry> = Arc::new(MemoryRegistry::new(
        topology,
        Arc::clone(&passport_store),
        Arc::clone(&receipt_store),
        Arc::clone(&resolver),
        Arc::clone(&cp),
        Arc::clone(&attestor),
    )?);
    let mode_str = match admission_mode {
        AdmissionModeArg::Closed => "CLOSED",
        AdmissionModeArg::Open => "OPEN",
    };
    info!(
        swarm_id = %swarm_id,
        mode = mode_str,
        attestor = attestor.id(),
        "registry constructed",
    );

    // Bootstrap passport registers with an empty external_credential
    // — the control plane's own passport is always the native path
    // (no IdP knows about the control plane itself).
    let outcome = registry.register(bootstrap_passport, Vec::new()).await?;
    info!(
        status = ?outcome.status,
        agent_id = %outcome.agent_id,
        receipt = ?outcome.registration_receipt.as_ref().map(|h| h.to_hex()),
        "bootstrap agent registered with receipt"
    );

    match resolver.resolve_actor(&bootstrap_agent_id).await {
        Ok(Some(_pk)) => info!("resolver sees bootstrap agent ✓"),
        Ok(None) => warn!("resolver could not see bootstrap agent (unexpected)"),
        Err(e) => warn!(error = %e, "resolver error (unexpected)"),
    }

    let receipt_count = receipt_store.count().await.unwrap_or(0);
    let register_receipts = receipt_store
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "agent.register".into(),
            }),
            None,
        )
        .await
        .map(|p| p.receipts.len())
        .unwrap_or(0);
    info!(
        receipt_count,
        register_receipts, "receipt store reachable; audit trail populated"
    );

    if operator_public_key.is_some() {
        info!("operator credentials enabled (RFC 0009)");
    }

    // Phase 2 constitution stack — F10b wiring.
    //
    // Construct the cedar-plus evaluator with the embedded v1.1
    // canonical schema (via `include_str!` inside `yutha-cedar-plus`)
    // and the default sandbox bounds from RFC 0012 §3.3. The
    // enforcement engine is freshly empty; both bind to a constitution
    // once an operator calls `ConstitutionService.Activate` (RFC 0010
    // §3.6). Before that activation, EnvelopeService.Send and the
    // capability handlers behave exactly as they did pre-F10 — the
    // constitution layer is opt-in via activate.
    let cedar_schema = yutha_cedar_plus::canonical_schema_v1_1_with_extensions(workload_extensions)
        .context("yutha-cedar-plus canonical schema + workload extensions failed to load")?;
    if !workload_extensions.is_empty() {
        info!(
            workload_count = workload_extensions.len(),
            "loaded workload-schema extensions"
        );
    }
    let cedar_loader = yutha_cedar_plus::ConstitutionLoader::with_default_bounds(cedar_schema);
    let cedar_plus = Arc::new(yutha_cedar_plus::CedarPlusEvaluator::with_default_bounds(
        cedar_loader,
    ));
    // `enforcement` was constructed earlier (F10g hookup) so the cap
    // store can share it; we just re-use that Arc below.

    // Phase 3c (RFC 0018 §4): replay engine backing. Memory backend
    // ships in 3c-C; Postgres impl is a 3c follow-on.
    let replay_store: Arc<dyn yutha_receipt::ReplayStore> =
        Arc::new(yutha_receipt::MemoryReplayStore::new());
    let replay_sessions = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

    Ok((
        Arc::new(ControlPlaneState {
            registry,
            passport_store,
            capability_store,
            transport,
            receipt_store,
            resolver,
            control_plane_identity: cp,
            operator_public_key,
            revoked_agents: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            revocation_signals: Arc::new(
                tokio::sync::RwLock::new(std::collections::HashMap::new()),
            ),
            cedar_plus,
            enforcement,
            attestor,
            replay_store,
            replay_sessions,
        }),
        enforcement_rx,
    ))
}

/// Parse an operator public key from a hex string. Ed25519 keys are 32
/// bytes; the operator presents the compressed-encoding hex form. Used
/// once at startup; failure aborts with a clear error so misconfigs
/// surface immediately.
fn parse_operator_public_key(hex_str: &str) -> anyhow::Result<yutha_core::PublicKey> {
    let bytes = hex::decode(hex_str.trim()).context("--operator-public-key: hex decode failed")?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "--operator-public-key: expected 32 raw bytes (64 hex chars), got {}",
            bytes.len()
        );
    }
    yutha_core::PublicKey::new(yutha_core::SignatureAlgorithm::Ed25519, bytes)
        .map_err(|e| anyhow::anyhow!("--operator-public-key: {e}"))
}

/// Resolved Sui-anchor configuration from the `--anchor-*` flags.
/// `None` = anchoring disabled (no flags set); `Some(_)` = all four
/// required flags present + cadence knobs resolved into typed values.
///
/// The four endpoint flags are required-together: setting any one
/// without the others is a configuration error and surfaces as a
/// startup failure.
struct ResolvedAnchorConfig {
    rpc_url: String,
    package_id_hex: String,
    swarm_anchor_id_hex: String,
    sealer_key_file: PathBuf,
    /// Cadence knobs forwarded into `AnchorDriverConfig`. We pull the
    /// non-knob defaults (initial_backoff, max_backoff,
    /// idle_poll_interval, retry_attempts) from
    /// `AnchorDriverConfig::default()` rather than surfacing them on
    /// the CLI — they're tuning parameters operators rarely change.
    batch_count_threshold: usize,
    batch_time_threshold: std::time::Duration,
    max_batch_size: usize,
}

/// Validate the four `--anchor-*` endpoint flags as a group + parse
/// the cadence knobs. Returns:
///   - `Ok(None)` if all four endpoint flags are absent (anchoring off);
///   - `Ok(Some(_))` if all four are present (anchoring on);
///   - `Err(_)` on partial config (anchoring half-set is a typo, not a feature).
fn resolve_anchor_config(cli: &Cli) -> anyhow::Result<Option<ResolvedAnchorConfig>> {
    let endpoints = [
        ("--anchor-sui-rpc-url", cli.anchor_sui_rpc_url.is_some()),
        ("--anchor-package-id", cli.anchor_package_id.is_some()),
        (
            "--anchor-swarm-anchor-id",
            cli.anchor_swarm_anchor_id.is_some(),
        ),
        (
            "--anchor-sealer-key-file",
            cli.anchor_sealer_key_file.is_some(),
        ),
    ];
    let set_count = endpoints.iter().filter(|(_, v)| *v).count();
    match set_count {
        0 => Ok(None),
        4 => Ok(Some(ResolvedAnchorConfig {
            rpc_url: cli.anchor_sui_rpc_url.clone().unwrap(),
            package_id_hex: cli.anchor_package_id.clone().unwrap(),
            swarm_anchor_id_hex: cli.anchor_swarm_anchor_id.clone().unwrap(),
            sealer_key_file: cli.anchor_sealer_key_file.clone().unwrap(),
            batch_count_threshold: cli.anchor_batch_count_threshold,
            batch_time_threshold: std::time::Duration::from_secs(
                cli.anchor_batch_time_threshold_secs,
            ),
            max_batch_size: cli.anchor_max_batch_size,
        })),
        _ => {
            let missing: Vec<&str> = endpoints
                .iter()
                .filter_map(|(name, present)| if *present { None } else { Some(*name) })
                .collect();
            anyhow::bail!(
                "Sui anchoring partially configured: missing {}. \
                 All four of --anchor-sui-rpc-url, --anchor-package-id, \
                 --anchor-swarm-anchor-id, --anchor-sealer-key-file are required \
                 together to enable anchoring, or all four omitted to disable it.",
                missing.join(", ")
            )
        }
    }
}

/// Build and run the gRPC server. Handles graceful Ctrl-C shutdown.
async fn serve_grpc(cli: &Cli, state: Arc<ControlPlaneState>) -> anyhow::Result<()> {
    // Bearer-token interceptor is a sync passthrough that just emits a
    // trace event noting whether an authorization header is present.
    // Real verification is async (it calls into the passport resolver
    // and runs Ed25519 verify) and lives in `crate::auth::require_bearer_auth`,
    // which handlers call directly. tonic 0.11's interceptor trait is
    // sync, which is why we don't enforce here. Each service gets a
    // fresh clone of the interceptor (tonic's `with_interceptor` takes
    // the interceptor by value).
    let interceptor = BearerInterceptor::new();
    let admission = AdmissionServiceServer::with_interceptor(
        AdmissionHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let capability = CapabilityServiceServer::with_interceptor(
        CapabilityHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let envelope = EnvelopeServiceServer::with_interceptor(
        EnvelopeHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let receipt = ReceiptServiceServer::with_interceptor(
        ReceiptHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let constitution = ConstitutionServiceServer::with_interceptor(
        ConstitutionHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let replay = ReplayServiceServer::with_interceptor(
        grpc::replay::ReplayHandler::new(Arc::clone(&state)),
        interceptor,
    );

    // gRPC reflection from the compiled FileDescriptorSet — lets
    // `grpcurl <addr> list` work without shipping proto files separately.
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()
        .context("build reflection service")?;

    let mut builder = Server::builder();

    // Optional TLS / mTLS. Three states:
    //   - no --tls-cert: plaintext (loopback local-dev default).
    //   - --tls-cert + --tls-key: server TLS.
    //   - --tls-cert + --tls-key + --client-ca: mTLS (server still
    //     verifies bearer token; cert is an additional layer).
    match (
        cli.tls_cert.as_ref(),
        cli.tls_key.as_ref(),
        cli.client_ca.as_ref(),
    ) {
        (None, None, None) => {
            info!(addr = %cli.grpc_addr, "gRPC: plaintext (no TLS configured)");
        }
        (Some(cert_path), Some(key_path), client_ca) => {
            let cert_pem =
                std::fs::read(cert_path).with_context(|| format!("read TLS cert {cert_path:?}"))?;
            let key_pem =
                std::fs::read(key_path).with_context(|| format!("read TLS key {key_path:?}"))?;
            let identity = Identity::from_pem(cert_pem, key_pem);
            let mut tls = ServerTlsConfig::new().identity(identity);
            if let Some(ca_path) = client_ca {
                let ca_pem = std::fs::read(ca_path)
                    .with_context(|| format!("read client CA {ca_path:?}"))?;
                tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(ca_pem));
                info!(addr = %cli.grpc_addr, "gRPC: mTLS (server cert + client CA)");
            } else {
                info!(addr = %cli.grpc_addr, "gRPC: server TLS");
            }
            builder = builder.tls_config(tls).context("apply TLS configuration")?;
        }
        (cert, key, _) => {
            anyhow::bail!(
                "TLS misconfiguration: --tls-cert and --tls-key must be set together \
                 (cert = {:?}, key = {:?})",
                cert.is_some(),
                key.is_some(),
            );
        }
    }

    let router = builder
        .add_service(admission)
        .add_service(capability)
        .add_service(envelope)
        .add_service(receipt)
        .add_service(constitution)
        .add_service(replay)
        .add_service(reflection);

    info!(
        addr = %cli.grpc_addr,
        "yutha control-plane gRPC server listening (all four services wired)"
    );

    router
        .serve_with_shutdown(cli.grpc_addr, async {
            // Graceful shutdown on Ctrl-C. tokio's signal handler is
            // installed once and resolves on SIGINT.
            if let Err(e) = tokio::signal::ctrl_c().await {
                warn!(error = %e, "ctrl-c handler errored; shutting down anyway");
            }
            info!("Ctrl-C received; shutting down gRPC server");
        })
        .await
        .context("gRPC server failed")?;

    info!("shutdown complete");
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,yutha=debug"));
    let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}
