# `yutha-attestor-spiffe`

SPIFFE/SPIRE backend for the Yutha [`Attestor`](../yutha-attestor/) trait. The Phase E reference enterprise Attestor.

> **Spec:** [/spec/identity-keys/attestor-spiffe.md](../../spec/identity-keys/attestor-spiffe.md) — the byte-exact verification contract.
> **Umbrella RFC:** [RFC 0016 — Attestor interface](../../spec/rfcs/0016-attestor-interface.md).
> **Status:** Phase E scaffold (compiles; `verify()` returns `AttestorError::Internal("not yet implemented; lands in E4")`).

## What this crate does

Mediates SPIFFE workload identity into Yutha agent passports. At registration time, the admission handler calls `SpiffeAttestor::verify(context, jwt_svid_bytes)`; the Attestor:

1. Parses the credential as a [SPIFFE JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md).
2. Verifies the signature against the configured trust bundle.
3. Checks `aud` includes the operator-configured audience, `exp` is in the future, and the SPIFFE-ID's trust domain is in the bundle.
4. Returns an `AttestedIdentity` whose `external_identity` is the SVID's SPIFFE ID (`spiffe://...`) and whose `attributes` are the projected workload selectors.

The control plane records `attested_external_identity = spiffe://...` + `attestor_id = "spiffe"` in the `agent.register` receipt's evidence. Auditors can chain Yutha `agent_id`s back to SPIRE-attested workloads.

## Why offline verification

The Attestor holds the trust bundle and verifies signatures itself, NOT delegating to SPIRE on every call (`WorkloadApiClient::validate_jwt_token`). The reasons:

- **Latency.** Per-registration verification is on the admission hot path; bypassing the SPIRE-agent RPC saves a network hop per call.
- **Resilience.** Brief SPIRE-agent outages don't block registrations as long as the cached bundle is within the bounded-staleness window (default 2× the bundle's `spiffe_refresh_hint`; see `attestor-spiffe.md` §6).
- **Topology flexibility.** The static-bundle source supports environments where running a SPIRE agent sidecar next to the control plane is infeasible (air-gapped, edge, dev).

## Trust-bundle sources

Two construction paths. Exactly one is selected at startup; the CLI surface (see `yutha-control-plane`'s `--attestor-spiffe-*` flags) enforces this.

| Source | Construction | Rotation | When to pick |
|---|---|---|---|
| **Static file** | `SpiffeAttestor::from_static_bundle(path, audience)` | None — operator rotates by replacing the file + restarting | Air-gapped, edge, dev; environments without a SPIRE agent socket |
| **Workload API stream** | `SpiffeAttestor::connect_workload_api(socket, audience)` | Atomic swap on every bundle update streamed from the SPIRE agent | Production SPIRE deployments; supports federation + hot rotation |

## Invariants

1. **`verify` is concurrent-safe.** Trust-bundle reads go through an `Arc::swap` or equivalent atomic; never a torn intermediate.
2. **No PII in errors.** `AttestorError` messages MUST NOT include credential bytes, decoded payload fields, or subject identifiers (RFC 0016 §3.1; see `attestor-spiffe.md` §9.1).
3. **Audience binding is mandatory.** A non-empty `--attestor-spiffe-audience` is required; SVIDs whose `aud` claim does not contain that exact value are `Rejected`.

## Phase-E status

- **E1** — Spec doc shipped (`attestor-spiffe.md`).
- **E2** — *(this commit)* crate scaffold; types declared; `verify()` returns `AttestorError::Internal`.
- **E3** — TrustBundleSource impls (static file + Workload API stream + bounded-staleness watchdog).
- **E4** — `SpiffeAttestor::verify` impl per the spec's 9-step algorithm.
- **E5** — Error mapping (JWT errors → `AttestorError` variants).
- **E6** — Control-plane CLI wiring (replaces the Phase-D `bail!("lands in Phase E")` placeholder).
- **E7** — Unit tests + docker-spire-gated integration test.
- **E8** — Conformance vectors under `/spec/vectors/attestor/spiffe-*`.
- **E9** — Operator runbook `docs/operator/spiffe-attestor.md`.
- **E10** — Workspace verification gate + commit-ready posture.

## See also

- [`yutha-attestor`](../yutha-attestor/) — the trait this crate implements.
- [`yutha-signer-vault`](../yutha-signer-vault/) — the structurally-analogous Phase C external-Signer backend.
- [SPIFFE Concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) — the upstream standard.
