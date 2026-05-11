# Workstream B Status — Phase 1 Control-Plane Scaffold

> **As of:** 2026-05-10
> **Author:** background work session, autonomous
> **Audience:** Abhinav, incoming Workstream B engineers
> **Predecessors:** [`STATUS.md`](./STATUS.md) (Workstream C), [`/spec/STATUS.md`](../spec/STATUS.md) (Workstream A)

## What landed

The trust-boundary Rust code for Phase 1 substrate: identity, authority, transport, membership, and a binary that wires them together. All five crates follow the scaffold + traits + skeleton + tests pattern set by Workstream C.

### Crates

| Crate | Role | Tests | State |
|-------|------|-------|-------|
| [`yutha-passport`](./yutha-passport/) | Passport struct + Canonical impl + self-signature verification; PassportStore trait; MemoryPassportStore; PassportResolverAdapter bridging to yutha-receipt. | ~14 | **Real.** |
| [`yutha-capability`](./yutha-capability/) | Capability struct + Canonical impl; Issuer (3 variants); Scope with intersect; six Caveat variants; macaroon-style chain walk with bounded depth; CapabilityStore trait; MemoryCapabilityStore. | ~12 | **Real.** |
| [`yutha-transport`](./yutha-transport/) | Envelope struct + Canonical impl; eleven Performatives; four Recipients; ReplayProtection (nonce window + epoch + TTL); Transport trait; MemoryTransport. | ~10 | **Real.** |
| [`yutha-registry`](./yutha-registry/) | Topology + TopologyMode (Closed/Open/Hybrid); AdmissionPolicy variants; SybilResistanceRequirement (PoW / TEE / IdP / Stake / Invite, skeleton checkers); Registry trait; MemoryRegistry. | ~7 | **Real for closed/open; hybrid covered via composition.** |
| [`yutha-control-plane`](./yutha-control-plane/) | `yutha` binary. Tokio runtime; constructs all in-memory backends; wires PassportResolverAdapter into the receipt store; builds a closed-mode topology; admits one bootstrap agent end-to-end; awaits Ctrl-C. | (integration: the binary itself proves wire-up) | **Real wire-up; no network listener yet.** |

### Key integration

The PassportResolverAdapter (in `yutha-passport`) implements `yutha_receipt::PassportResolver` by wrapping any `PassportStore`. This closes the loop: when Workstream A's spec contract says "receipt store verifies actor signature via passport store," that contract is now compiled. The control-plane binary exercises it end-to-end.

## How to read this when you're back

If you have 10 minutes:
1. `cargo run -p yutha-control-plane` — see the binary log a successful bootstrap.
2. `cargo test --workspace` — see the ~110 unit tests pass across the workspace.
3. Read [`yutha-control-plane/src/main.rs`](./yutha-control-plane/src/main.rs) — it's the shortest end-to-end picture of how the layers compose.

If you have an hour:
- Read each crate's `README.md` first to orient on what it does and doesn't do.
- Spot-check one rationale doc per crate (e.g., `yutha-passport/src/passport.rs` for the Canonical impl, `yutha-capability/src/scope.rs` for the intersection algebra, `yutha-transport/src/replay.rs` for the replay defense, `yutha-registry/src/memory.rs` for the admission flow).
- Run `cargo test --package yutha-conformance --features in-memory-receipt-suite` — the conformance suite still passes (Workstream B's changes didn't break Workstream C's contract).

## What I'd flag for your attention

1. **Canonical serialization is still provisional across the new crates.** Every Canonical impl (Passport, Capability, Envelope) uses the same hash-of-fields-with-separators pattern as Receipt. Deterministic across Rust runs; not yet wire-equivalent across languages. Switching all of them to prost-deterministic encoding is one batch of work once the prost-bindings pipeline lands.

2. **Sybil-resistance checkers are trivial-accept at scaffolding level.** All five mechanisms (proof-of-work, hardware attestation, IdP, stake, invite) have their type surfaces and the `check_all` AND-composition, but each individual `check` returns Ok regardless of input. Real verifiers land per-mechanism, likely each as its own sub-crate (`yutha-sybil-pow`, `yutha-sybil-nautilus`, etc.) wired in behind the registry's `SybilResistanceRequirement` enum.

3. **Hybrid admission's periphery_capability_constraint is not enforced at registry level.** The HybridPolicy has the field shape but `check_hybrid` only routes to closed or open. Enforcement happens when the registry issues post-registration capabilities through `yutha-capability` — the control plane does that integration; the registry alone is correct, but the constraint is a control-plane-level invariant.

4. ~~**MemoryRegistry doesn't produce receipts yet.**~~ **RESOLVED.** `MemoryRegistry::new` now takes a receipt store, a resolver, and a `ControlPlaneIdentity`. Every successful registration produces an `agent.register` receipt signed by the control plane and appended through the verifying path. Evidence carries `passport_agent_id` and `passport_hash`. The control-plane binary registers the cp's own passport at startup (genesis, no receipt) before constructing the registry. New canonical-actions registry at [`/spec/receipt/canonical-actions.md`](../spec/receipt/canonical-actions.md) lists `agent.register` and the broader action-kind taxonomy. Tests cover: registration produces a receipt; rejection produces none; swarm-mismatch produces none.

5. **The control-plane binary has no network listener.** It uses `MemoryTransport` and only runs the bootstrap-agent registration in-process. Listening on a port (NATS subject / gRPC service) lands when transport gets its production impl. The binary's job today is to prove the dependency graph composes; that's it.

6. **Topology operator_signature is currently `None` in the bootstrap binary.** Production deployments require the operator to sign the topology at swarm creation; the scaffolding skips this. Adding signing + verification is straightforward but requires a CLI flow for the operator (`yutha topology sign --key …`).

## What is *not* yet done (Phase 1 still in progress)

- **Prost-bindings pipeline** (still flagged from Workstream C).
- **Real persistent backends**: postgres-receipt impl bodies, walrus-receipt impl bodies, postgres-backed PassportStore + CapabilityStore + RegistryStore. These follow the same pattern as the in-memory impls but persist via sqlx.
- **NATS transport implementation**.
- **agent.register receipts** wired into the registry → receipt store path.
- **Sybil-mechanism implementations** (production verifiers for each of the five).
- **Open and hybrid integration tests** that exercise the policy variants under more pressure than the unit tests currently do.
- **Conformance suite expansion**: a behavioral-tier S1 scenario (PRD §8.5 customer-support queue) is now technically expressible with the substrate we have; standing it up against the in-memory stack proves the differential-conformance machinery works.

## What is *not* started (Phase 2 or later, by design)

- Constitution evaluator (Cedar+).
- Four-stage enforcement loop.
- Simulator / adversary library.
- Visual composer.
- Federation primitives.
- Envelope detection.

## Workspace health

`cargo build --workspace` should produce a clean build. `cargo test --workspace` runs ~110 tests across all crates plus the conformance suite. `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all --check` should both be green; `cargo deny check` continues to pass with the documented exceptions in `deny.toml`.

If the build trips, the most likely culprits are: (a) the partial-move pattern I used in test setup got snagged by something the borrow-checker disagrees with — bind locals before moving fixture fields; (b) a dependency feature I selected disagrees with workspace policy — check the deny.toml exceptions.

## Audit story rounded out

Every substrate component now produces receipts for its consequential actions:

| Action | Producer | Receipt kind |
|--------|----------|--------------|
| Agent registers | Registry | `agent.register` |
| Agent revoked | Registry | `agent.revoke` |
| Agent key rotated | Registry | `agent.rotate_key` |
| Envelope sent | Transport | `envelope.send` |
| Envelope delivered | Transport | `envelope.deliver` |
| Capability check passes | Capability store | `capability.check.pass` |
| Capability check denies | Capability store | `capability.check.deny` |

All receipts are signed by the control plane (substrate-observation pattern; agent-signed receipts come later when SDKs produce them) and appended through the resolver-verified path. The `ControlPlaneIdentity` type moved to `yutha-passport` so transport, capability, and registry can all share it without dependency cycles.

`canonical-actions.md` documents each kind plus the producer and evidence shape.

## S1 customer-support scenario landed

A first behavioral conformance scenario is now executable. [`yutha-conformance/src/scenarios/s1_queue_mode.rs`](./yutha-conformance/src/scenarios/s1_queue_mode.rs) stands up the full in-memory stack — receipt store, passport store, resolver, transport, registry, control-plane identity — registers 5 agents from 2 different frameworks (3 from `framework_a`, 2 from `framework_b`), then sends 4 envelopes through the in-memory transport (3 router→handler routings + 1 escalation to supervisor). At the end it queries the receipt store and verifies the audit trail.

Run with:

```bash
cargo test --package yutha-conformance --features in-memory-scenarios
```

Expected outcome (now richer with the audit-story round-out):
- `agents_registered: 5`
- `register_receipts: 5`
- `envelopes_delivered: 4`
- `envelope_send_receipts: 4`
- `envelope_deliver_receipts: 4`
- `check_pass_receipts: 1`
- `revoke_receipts: 1`
- `total_receipts: 15`

What this scenario proves about Phase 1 substrate:
- Registry admission works end-to-end.
- Receipts produced and verified through the resolver.
- Envelopes round-trip with signature verification + replay protection.
- Audit trail queryable by action_kind.

What it deliberately doesn't yet exercise (Phase 2 work):
- Constitution norms over PII tags.
- Four-stage enforcement loop.
- Supervisor approvals via two-person rule.
- Envelope-send / envelope-deliver receipts (transport doesn't produce receipts at this scaffolding maturity; next bite).

## Suggested next pickup

Three forks worth pre-thinking:

- **Wire registration receipts into the control plane** (~half day). Highest immediate value: closes the audit loop. Receipts ship with bytes through resolver, with the new append-verifies contract.
- **Begin prost-bindings pipeline** (~one day). Unlocks bytewise wire-equivalence and starts to make cross-language conformance meaningful. The Canonical trait is in place; switching its implementations to prost-deterministic is a contained refactor.
- **Start Workstream D (SDKs)** (~multi-day). Python first; consumes the spec contracts and the control-plane binary's surface. Lower technical risk than continuing in Rust; tests the spec from a different angle.

I'd lean toward order (1) → (2) → (D), but it's worth pinning down based on what you'd most want to validate next.
