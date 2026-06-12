# Notes for AI coding agents

This file is read by AI coding agents (Cursor, Claude Code, Codex, etc.) working inside this repository. It orients an agent to the codebase, lists the build and test commands, and calls out conventions that the rest of the repo assumes you already know.

If you're a *human* contributor looking for the contribution guide, that lives at [`docs/community/CONTRIBUTING.md`](docs/community/CONTRIBUTING.md). If you're an *AI agent reading the published docs at yutha.ai* (not the code), look at `/llms.txt` and `/llms-full.txt` on the site — they're written for you.

## What Yutha is

Open-source infrastructure for groups of AI agents. Identity, capability, accountability, declarative norms (Cedar+), optional cryptographic verifiability (Sui anchoring). Framework-agnostic — runs in front of agents built in LangGraph, CrewAI, or anything else. The full conceptual overview is at `docs/index.md`.

## Repository layout

```
/spec        — wire & artifact specs (RFC-governed; the contract)
/crates      — Rust workspace: control plane, registry, capability, transport,
               receipts, Cedar+ engine, Signer trait + external Signer backends
               (Vault, GCP KMS, Azure Managed HSM), Attestor trait + external
               Attestor backends (SPIFFE, OIDC), preview tooling (yutha-replay,
               yutha-sim, yutha-diff), ops CLI, proto crate, conformance suite
/backends    — Pluggable backends: postgres-receipt (production receipt
               store), sui-anchor (optional verifiability layer)
/contracts   — Move package for Sui receipt anchoring (sources/, tests/)
/sdks        — Framework adapters (sdks/python/ ships today: LangGraph,
               CrewAI, OpenAI Agents, Microsoft Agent Framework). Latest
               release: yutha 0.1.0a4 on PyPI.
/interop     — Cross-language differential testing (interop/go/)
/docs        — Source for the MkDocs Material site published at yutha.ai.
               docs/internal/ holds engineering reference docs that aren't on
               the published nav (PRD, threat model, build plan, constitution
               design memo, conformance suite, ADRs, per-release notes). The
               canonical release record lives on GitHub Releases.
/scripts     — Repo tooling (e.g. build-llms-full.py)
```

The wire-level contract lives in `/spec/`. The Rust implementation in `/crates/` is the reference, not the spec. When implementation and spec disagree, the spec wins and the implementation is the bug.

## How to build and test

The workspace pins to a local clone of [MystenLabs/sui-rust-sdk](https://github.com/MystenLabs/sui-rust-sdk) at a specific commit (see the comment block in `Cargo.toml`). The clone must sit as a sibling to this repo at `../sui-rust-sdk`. CI clones it automatically; locally you need:

```bash
cd ..
git clone https://github.com/MystenLabs/sui-rust-sdk
git -C sui-rust-sdk checkout $(grep SUI_RUST_SDK_REV yutha/.github/workflows/ci.yml | awk '{print $2}')
cd yutha
```

Then:

```bash
# Rust (workspace).
cargo build --workspace --all-targets
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check
cargo deny check

# Conformance suite (in-memory backend).
cargo test -p yutha-conformance

# Python SDK + adapters.
cd sdks/python
uv sync --extra dev --extra crewai --extra openai-agents --extra maf
uv run pytest                          # unit tests
uv run pytest -m integration -v        # integration (needs control plane up)
uv run ruff check .
uv run mypy src/yutha
cd ../..

# Move package (Sui contracts).
cd contracts/sui/receipt_anchor
sui move test --build-env testnet
cd ../../..

# Docs site.
pip install -r requirements-docs.txt
python3 scripts/build-llms-full.py     # regenerates docs/llms-full.txt
mkdocs serve                            # preview at http://127.0.0.1:8000

# Cross-language interop (Go differential).
cd interop/go && make all
```

For the integration tests, bring the control plane up in a separate terminal first:

```bash
export YUTHA_BOOTSTRAP_SEED=$(openssl rand -hex 32)
export YUTHA_OPERATOR_PUBLIC_KEY=$(cargo run -p yutha-ops --quiet -- print-operator-pubkey)
cargo run -p yutha-control-plane -- \
  --admission-mode open \
  --workload support-queue \
  --operator-public-key "$YUTHA_OPERATOR_PUBLIC_KEY"
```

## Conventions to honor

**Spec-first.** Changes to the wire format, artifact format, or any externally-observable behavior require an RFC. See `docs/community/RFC_PROCESS.md`. Don't ship a wire-format change as an implementation PR; reviewers will bounce it.

**No backcompat ceremony pre-public-launch.** Until the repo flips public for Phase 2, prefer breaking changes over opt-in/fallback paths. The codebase has no shipped consumers yet; carrying compat shims is purely cost.

**Determinism.** Receipts are content-addressed; canonical serialization is bytewise-deterministic. Anywhere you serialize for hashing or signing, use the canonical proto encoding (via the `Canonical` trait) — never `serde_json` or `prost`'s non-canonical encoder. JSON test vectors in `/spec/vectors/` are the conformance signal.

**Capability gating happens at the control plane.** Don't push cap checks into agent code or framework adapters. The `EnvelopeService.Send` handler in `yutha-control-plane` is the single chokepoint, and that's deliberate.

**Receipts are first-class outputs.** Any consequential action (sends, capability checks, admissions, revocations, constitution evaluations, enforcement-loop transitions, anchor commits) MUST emit a receipt. If you find yourself adding a code path that takes a consequential action without emitting one, you're missing a step.

**One-active-subscriber-per-inbox.** `MemoryTransport.subscribe` server-side-evicts the previous subscriber via `subscribe_supersede` Notify. Multi-subscriber-per-agent is intentionally not supported. Don't reintroduce client-side teardown sleeps to work around races; if you're seeing a zombie-subscriber issue, fix the server-side eviction.

**Rust toolchain.** Stable; MSRV is `1.75`. CI tests both stable and 1.75. Don't introduce stdlib API usage that breaks 1.75 without an ADR amendment.

**No emojis in code or docs** unless the user explicitly asks for them. Same for sponsor logos, company branding, etc.

**Private material never enters git.** `*.key`, `Pub.*.toml`, `*.log`, sealer keys, bootstrap seeds — all gitignored. If you generate one of these during a debugging session, double-check it isn't in your staged changes.

**Sui anchoring is optional.** The path through the control plane works fully without any Sui dependency at runtime. Don't tighten this — `--anchor-*` flags are an opt-in surface, not a requirement.

**Signer and Attestor backends are optional.** The default `InProcessSigner` and `NativeAttestor` keep the substrate fully self-contained at runtime — no Vault, no cloud KMS, no SPIRE, no IdP required. `--signer {vault,gcp-kms,azure-kv}` and `--attestor {spiffe,oidc}` are opt-in surfaces, parallel to `--anchor-*`. Don't tighten the defaults — every test, demo, and integration run assumes the zero-config posture holds.

## Where to find what

| Looking for... | Look at... |
|---|---|
| The wire format of an envelope/passport/receipt/capability | `/spec/<thing>/` |
| The Rust types for the above | `/crates/yutha-core/` |
| The control plane gRPC service definitions | `/crates/yutha-proto/proto/` |
| The control plane server | `/crates/yutha-control-plane/` |
| The Cedar+ engine (constitution evaluation, enforcement loop) | `/crates/yutha-cedar-plus/` |
| The preview-rule-changes tools (replay, sim, diff) | `/crates/yutha-replay/`, `/crates/yutha-sim/`, `/crates/yutha-diff/` |
| The receipt store implementations | `/crates/yutha-receipt/`, `/backends/postgres-receipt/` |
| The Python client surface | `/sdks/python/src/yutha/client.py` |
| The LangGraph adapter | `/sdks/python/src/yutha/langgraph/` |
| The CrewAI adapter | `/sdks/python/src/yutha/crewai/` |
| The OpenAI Agents adapter | `/sdks/python/src/yutha/openai_agents/` |
| The Microsoft Agent Framework adapter | `/sdks/python/src/yutha/maf/` |
| The Sui anchoring backend | `/backends/sui-anchor/`, `/contracts/sui/receipt_anchor/` |
| The conformance suite | `/crates/yutha-conformance/` |
| RFCs (proposals + accepted history) | `/spec/rfcs/` |
| Operator end-to-end playbook | `/docs/operator/quickstart.md` |
| Operator preview-before-promote tooling | `/docs/operator/previewing-changes.md` (overview), `shadow-mode.md`, `replay.md`, `constitution-diff.md`, `simulation.md` |
| Developer end-to-end playbook | `/docs/developer/langgraph.md` (LangGraph), `crewai.md` (CrewAI), `/docs/examples/research-crew.md` (OpenAI Agents), `/docs/examples/devops-incident.md` (Microsoft Agent Framework) |
| Internal engineering reference docs (PRD, threat model, build plan, constitution design memo, conformance suite, ADRs, per-release notes) | `/docs/internal/` |
| Latest release notes | `/docs/internal/v0.1.0-alpha.4.md` (canonical: GitHub Releases) |

## What an agent typically gets wrong here

A pattern of recurring confusions, so you can side-step them:

- **Treating Cedar+ as our own language.** It isn't — it's a superset of AWS Cedar with scoring rules, procedures, resource budgets, and memory norms layered on. Read RFCs 0010–0013 before changing the engine.
- **Reaching for crates.io versions of the `sui-*` crates.** They're behind the path-pinned local clone — the `bech32` feature gate we need isn't on crates.io 0.3.0. See `Cargo.toml` for the rationale.
- **Adding cap-check logic to framework adapters.** Don't. The adapter's job is to mint passports, format envelopes, and hand them to the SDK — nothing more. Server-side enforcement is the load-bearing wall.
- **Calling `subscribe()` more than once per agent.** Each call evicts the previous subscriber server-side. Multi-subscription per agent isn't a feature.
- **Trying to bump dependencies that touch the Sui SDK.** Treat the four `sui-*` crates as pinned; bump `SUI_RUST_SDK_REV` in `.github/workflows/ci.yml` deliberately, never via Dependabot or transitive update.

## When in doubt

Open a draft GitHub issue describing the change you want to make. Five minutes of "does this direction make sense?" saves a week of writing something that won't land.
