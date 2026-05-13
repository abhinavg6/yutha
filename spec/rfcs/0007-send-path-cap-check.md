# RFC 0007: Send-path capability enforcement

> **Status:** Draft
> **Authors:** Workstream E (substrate hardening)
> **Filed:** 2026-05-13
> **Targets spec:** `/spec/control-plane/` v1.0 → v1.1, `/spec/topology/` v1.0 → v1.1
> **Targets phase:** Phase 1 (substrate hardening before Phase 2)
> **Discussion:** TBD

## 1. Summary

Promotes `EnvelopeService.Send` from a sender-identity-only RPC to a
capability-gated RPC. Adds a `capability_id` field to
`SendEnvelopeRequest` and a `require_capability_for_send` boolean to
`Topology`. When the topology requires it, the server looks up the
referenced capability, walks its parent chain, enforces revocation +
validity window + scope intersection, emits a
`capability.check.pass`/`capability.check.deny` receipt, and rejects
the send on deny.

## 2. Motivation

The current `Send` handler verifies only that
`envelope.from_agent == bearer.agent_id`. Capability enforcement
lives at `CapabilityService.Check`, which is invoked by callers as a
client-side preflight (the `@capability_required` decorator in the
Python SDK does this). That puts capability gating at correctness
level, not security level: a malicious client that skips the
preflight and calls `Send` directly is not blocked by the server.

A3 in the threat model (prompt injection escalating into unauthorized
action) and A1 (bounded blast radius) both assume that capability
checks are unbypassable. Routing the check through Send closes that
assumption to enforcement.

This RFC does not introduce capability semantics — those exist in
[RFC 0005](./0005-capability-v1.md). It moves the existing
mechanism from "available, advisory" to "available, mandatory under
topology declaration."

## 3. Detailed design

### 3.1 `SendEnvelopeRequest` gains `capability_id`

```proto
message SendEnvelopeRequest {
  yutha.envelope.v1.Envelope envelope = 1;

  // NEW: content-address of the capability authorizing this send.
  // Required when topology.require_capability_for_send is true;
  // optional otherwise.
  yutha.common.v1.Hash capability_id = 2;
}
```

Field 2 is a content-address (Hash) referencing a capability already
persisted in the server's store. Inline `Capability` is not accepted
on the wire: the server does not trust client-supplied capability
contents and instead resolves cap_id against the store, which only
contains caps issued through `CapabilityService.Issue` /
`Attenuate`.

### 3.2 `Topology` gains `require_capability_for_send`

```proto
message Topology {
  // ...existing fields...

  // NEW: when true, every authenticated Send must present a
  // capability_id and pass the server-side check.
  bool require_capability_for_send = 12;
}
```

Defaults at registry construction:

- `TopologyMode::CLOSED` → `true` (production posture; explicit caps required)
- `TopologyMode::OPEN` → `false` (demo / dev posture; preserves legacy behavior)
- `TopologyMode::HYBRID` → operator-set explicitly

Operators can override these defaults at startup.

### 3.3 Server-side enforcement

When `require_capability_for_send` is true, the Send handler runs
this sequence:

1. Bearer auth (unchanged).
2. `envelope.from_agent == bearer.agent_id` check (unchanged).
3. Reject with `INVALID_ARGUMENT` if `capability_id` is empty.
4. Build an `ActionDescriptor` from the envelope:
   - `action_kind = "envelope.send"`
   - `evidence` populated with `recipient`, `performative`,
     `payload_schema_id`, and any envelope tags so caveats can
     match on those.
5. Call `CapabilityStore::check(cap_id, descriptor)`.
6. Emit the `capability.check.pass` or `capability.check.deny`
   receipt (the store does this; same path used by gRPC `Check`
   today).
7. On deny: return `PERMISSION_DENIED` with the deny reason. The
   envelope is not sent. The deliver receipt is not emitted.
8. On pass: proceed to `Transport::send(envelope)` as today.

When `require_capability_for_send` is false, the handler skips steps
3–7 entirely; behavior matches v1.0.

### 3.4 Receipt semantics

`capability.check.pass` / `.deny` receipts emitted from the Send
path are the same kind as those emitted from the `Check` RPC. The
descriptor evidence makes the context unambiguous in queries —
filtering `evidence.action_kind == "envelope.send"` selects Send-path
checks specifically.

`envelope.send` receipts remain emitted only on successful sends, as
today.

### 3.5 Client implications

The Python SDK's `client.envelope.send(envelope, capability_id=...)`
gains an optional `capability_id` keyword. The `@capability_required`
decorator in `yutha.langgraph` becomes a thin wrapper: instead of
calling `client.capability.check(...)` and then `client.envelope.send(...)`
(two RPCs), it just supplies the cap_id to the subsequent send (one
RPC). The single Send-path check produces the same receipt the
decorator previously triggered, with strictly stronger semantics
(unbypassable).

## 4. Drawbacks

- **Wire-format change.** Existing clients that pre-date this RFC
  will see `INVALID_ARGUMENT` when sending to a closed-mode swarm
  unless they supply a `capability_id`. Mitigated by the
  `require_capability_for_send` flag: operators that need the v1.0
  ergonomics set it to false. The flag also lets us roll out
  incrementally — a swarm can opt in once its agents are upgraded.
- **Two-stage capability flow.** Senders must hold a cap before
  sending, which means an explicit `CapabilityService.Issue` step in
  setup. This adds a step compared to "send freely" — but it's the
  same step every production deployment would want anyway. Operator
  burden, not user burden.
- **Cap-store lookup on the Send hot path.** Every gated send walks
  the parent chain (bounded by `max_capability_chain_depth`, default
  8). MemoryStore lookup is sub-microsecond; Postgres-backed will
  add a query per send. Mitigation: cap-resolution cache in the
  store (out of scope here; tracked separately).

## 5. Alternatives considered

- **Inline `Capability` on the wire instead of `capability_id`.**
  Lets senders present off-line / federated caps the server hasn't
  seen. Rejected for v1: trust boundary is cleaner when the server
  only honors caps it issued. Federation can ship later as a
  signature-verifying variant; doesn't preclude this RFC.
- **Implicit cap selection (server enumerates caps held by sender
  and picks one matching the action).** Rejected: brittle semantics
  ("which cap got used?" is ambiguous in audits), and adds a server-
  side index nobody asked for.
- **Do nothing, keep enforcement at gRPC `Check`.** Rejected: that's
  the current state and it leaves Send unguarded. The whole point of
  this RFC is to close that gap.
- **Require caps for Send unconditionally, no topology flag.**
  Rejected because it breaks every existing demo / integration test
  on day one. The topology flag is the migration runway.

## 6. Threat-model impact

- **A3 (prompt injection):** Strengthened. The structural defense
  against injected instructions causing unauthorized sends now lands
  at the substrate, not at the agent's client-side check that
  injection could subvert.
- **A1 (bounded blast radius):** Strengthened. A compromised agent
  can still hold its issued caps but cannot send beyond their scope
  even by bypassing client-side checks.
- **A8 (auditability):** Strengthened. Every Send produces a
  capability.check.pass or .deny receipt regardless of whether the
  client tried to log it. The audit trail captures attempted denies
  that v1.0 had no record of (clients could just not call Check).
- **No new attack surface.** The cap_id field is structurally
  validated; the actual cap lookup uses the existing
  `CapabilityStore::check` path which has been in production since
  Stage D-2d.

## 7. Conformance impact

New scenario in `yutha-conformance`: `s2_send_path_cap_check`. Four
sub-cases mirroring the Python integration test in E1d:

1. Send with valid cap in strict topology → permit + check.pass + send receipts.
2. Send without cap in strict topology → INVALID_ARGUMENT, no send receipt, no check receipt.
3. Send with revoked cap in strict topology → PERMISSION_DENIED + check.deny receipt, no send receipt.
4. Send with cap whose scope doesn't match → PERMISSION_DENIED + check.deny receipt, no send receipt.

Existing S1 scenario continues to pass unchanged — it uses
`MemoryTransport` directly (in-process), which is not gated by this
RFC (the gating lives at the gRPC handler, not the transport).

## 8. Migration

- v1.0 clients sending to v1.1 servers in **closed mode** (with
  `require_capability_for_send=true` default): clients see
  `INVALID_ARGUMENT` until upgraded. Migration path: set the
  topology flag to false during the upgrade window, then flip it
  once all senders are on v1.1.
- v1.0 clients sending to v1.1 servers in **open mode** (default
  `require_capability_for_send=false`): no behavior change. Caps
  are accepted but optional.
- v1.1 clients sending to v1.0 servers: the `capability_id` field
  is ignored by older servers (proto field-number compatibility).
  Loses enforcement but maintains compatibility.

Deprecation timeline: clients SHOULD upgrade within 6 months. The
v1.0 wire-compatible behavior (no cap required) is supported in v1.1
indefinitely via the topology flag; there is no hard deprecation
date for the optional-cap mode itself.

## 9. Open questions

- Should `capability.check.pass` receipts from Send-path checks
  carry the resulting `envelope.send` receipt's content-address as
  evidence, so a single audit query can correlate the check with
  what it gated? Currently the evidence carries the envelope itself;
  the receipt-id link would arrive only via the deliver receipt's
  `predecessor` field. Leaning yes — easy to add, makes audits
  cleaner. **(Decided in 3.4 above: include `envelope.send`
  receipt id in evidence on the check.pass case.)**
- How do we handle the case where `capability_id` is supplied but
  the topology doesn't require it? Silently honor it (running the
  check and emitting the receipt) or treat it as an error? Leaning
  honor — gives operators an audit trail even in permissive mode.

## 10. Adoption checklist

- [ ] Spec doc updated and committed
- [ ] `rationale.md` updated for capability, envelope, topology
- [ ] Conformance test S2 added
- [ ] Rust server: Send handler routes through CapabilityStore::check
- [ ] Python SDK: `capability_id` keyword on send + decorator refactor
- [ ] At least two reviewers approved
- [ ] No sustained unresolved objections

## 11. References

- [RFC 0005: Capability v1.0](./0005-capability-v1.md) — establishes the cap mechanism this RFC promotes.
- [RFC 0006: Topology v1.0](./0006-topology-v1.md) — defines the topology this RFC extends with a new field.
- `/spec/capability/rationale.md` §4 — threat-model linkage assumed by this RFC.
- Stage D-4 retrospective: the discovery during the S1 LangGraph demo build that exposed the Send-path gap.
