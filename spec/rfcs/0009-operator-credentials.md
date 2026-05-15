# RFC 0009: Operator credentials and active-stream tear-down

> **Status:** Draft
> **Authors:** Workstream E (substrate hardening)
> **Filed:** 2026-05-14
> **Targets spec:** `/spec/control-plane/` v1.1 → v1.2,
>                   `/spec/passport/` v1.1 (rationale clarification),
>                   `/spec/receipt/canonical-actions.md`
> **Targets phase:** Phase 1 (substrate hardening)
> **Discussion:** TBD

## 1. Summary

Introduces an **operator credential** for the Yutha control plane —
a distinct bearer-token variant signed by an operator key the
server is configured with at startup — and a corresponding
**`AdmissionService.OperatorRevoke`** RPC that lets operators evict
agents from a swarm. On any revocation (self or operator), the
server **proactively tears down the target agent's active subscribe
streams** and rejects future requests carrying the target's bearer
token. Tokens become unusable immediately rather than at their next
natural expiry.

Closes the third gap in the revocation surface noted in
`revocation_posture.md`. Constitution-driven revoke (the Phase-2
four-stage enforcement pipeline) is still out of scope here.

## 2. Motivation

Today, `AdmissionService.Revoke` enforces `target_agent_id ==
bearer.agent_id` at the handler — self-revoke only. A swarm
operator who needs to forcibly evict a misbehaving agent has no
in-band mechanism; the operator's only recourse is to restart the
control plane with the agent missing from the allowlist (closed
mode) or block their passport out-of-band, both of which are
disruptive and unaudited.

The Yutha promise is "every state-changing action produces a
signed receipt." Operator interventions today don't satisfy that.

Three concrete cases this RFC unblocks:

1. **Compromised agent.** Operator detects an agent's private key
   has leaked; needs to revoke immediately.
2. **Misbehaving agent.** An agent is flooding the swarm with
   junk envelopes; operator wants to take it offline without
   restarting the control plane.
3. **Policy violation.** An agent fails an out-of-band compliance
   check; operator wants to record an auditable eviction.

In all three, the **active-stream tear-down** matters: an existing
subscribe stream means the agent keeps receiving envelopes for up
to the token's expiry window (default 5 minutes), and existing
unary RPCs are still authorized for that window. The substrate
needs the revocation to be immediate, not eventually-consistent on
token expiry.

## 3. Detailed design

### 3.1 `OperatorBearerToken` (new)

A dedicated bearer-token variant, sibling to `AgentBearerToken`.
Wire format on the gRPC `authorization` header changes from

```
bearer <hex-of-AgentBearerToken>
```

to a two-variant scheme:

```
bearer agent <hex-of-AgentBearerToken>
bearer operator <hex-of-OperatorBearerToken>
```

The `agent` prefix is the default and matches v1.1 behavior when
absent (back-compat: a server that sees `bearer <hex>` with no
explicit variant treats it as `bearer agent <hex>`). New clients
SHOULD emit the explicit variant.

```proto
message OperatorBearerToken {
  // Free-form identifier for the operator. The server uses this
  // only for audit-trail clarity; trust is rooted in the signature
  // verifying against a configured operator public key.
  string operator_id = 1;

  // The swarm this token authorizes operator actions in. The
  // server rejects tokens with a mismatched swarm_id.
  yutha.common.v1.SwarmId swarm_id = 2;

  // When the token was minted (operator-side wall clock).
  yutha.common.v1.Timestamp issued_at = 3;

  // When the token expires. Same wall-clock semantics as
  // `AgentBearerToken.expires_at` (RFC 0008). Recommended ≤ 5
  // minutes.
  yutha.common.v1.Timestamp expires_at = 4;

  // 16-byte random nonce.
  bytes nonce = 5;

  // Forward-compatibility hatch.
  yutha.common.v1.Extensions extensions = 200;

  // Signature over canonical_bytes(token with signature cleared),
  // made with one of the operator keys the server trusts (see
  // §3.4).
  yutha.common.v1.Signature signature = 250;
}
```

### 3.2 `AdmissionService.OperatorRevoke` (new RPC)

```proto
service AdmissionService {
  // ... existing RPCs ...

  // Operator-level eviction of an agent. The caller MUST present
  // an OperatorBearerToken (§3.1). Produces an
  // `agent.operator_revoke` receipt distinct from the
  // `agent.revoke` kind that self-revoke produces. Triggers
  // active-stream tear-down (§3.3).
  rpc OperatorRevoke(OperatorRevokeRequest) returns (OperatorRevokeResponse);
}

message OperatorRevokeRequest {
  // Target agent to evict.
  yutha.common.v1.AgentId target = 1;

  // Free-form reason; persisted on the receipt.
  string reason = 2;

  // When true, the server also revokes every capability the
  // target holds (issuer == target OR subject == target) and
  // emits a `capability.revoke` receipt per cap. Default false —
  // operators opt in explicitly when they want the audit trail.
  bool cascade_capabilities = 3;
}

message OperatorRevokeResponse {
  // Content-address of the `agent.operator_revoke` receipt.
  yutha.common.v1.Hash revocation_receipt = 1;

  // Content-addresses of any `capability.revoke` receipts
  // produced as part of cascade. Empty when cascade_capabilities
  // was false or the agent held no caps.
  repeated yutha.common.v1.Hash cascade_receipts = 2;
}
```

Self-revoke continues to use the existing `Revoke` RPC; the two
codepaths are deliberately separate so audits can filter by actor
type without parsing reasons.

### 3.3 Active-stream tear-down

On **any** revoke that lands a receipt — self (`agent.revoke`),
operator (`agent.operator_revoke`), and (Phase 2) constitution-
driven — the control plane MUST:

1. **Block future bearer auth for the target.** A revoked agent's
   `AgentBearerToken` is rejected with
   `UNAUTHENTICATED: agent revoked` regardless of remaining
   token-window time. The server maintains a revoked-set populated
   from receipts; bearer verification consults it after passport
   resolution.
2. **Close the target's active subscribe streams.** Any in-flight
   `EnvelopeService.Subscribe` stream from the revoked agent MUST
   be torn down promptly (≤ 1 second; implementations should aim
   for tens of milliseconds). The gRPC stream returns
   `UNAUTHENTICATED: agent revoked` to the client.
3. **In-flight RPCs.** Unary RPCs in flight at the moment of
   revocation MAY complete (operators don't have to chase
   millisecond races); subsequent calls reject.

The tear-down itself does not produce its own receipt — the
revocation receipt already records the actor-driven event; the
stream closure is a consequence, not an action. Audit-log readers
can correlate revocation receipts with the absence of subsequent
`envelope.deliver` receipts for the target.

### 3.4 Operator-key configuration

The server is configured at startup with **one or more operator
public keys**. Phase 1 supports a single key via a CLI flag:

```
yutha-control-plane \
    --operator-public-key <ed25519-public-key-hex>
```

(also readable from `YUTHA_OPERATOR_PUBLIC_KEY`).

When no operator key is configured, `OperatorRevoke` returns
`FAILED_PRECONDITION: operator credentials not enabled`. This is
the default — operator capability is opt-in by the operator (no
pun intended) at the binary's launch.

Operator key rotation is out of scope for this RFC; a future RFC
covers it. Today: stop the control plane, restart with a new key.
The downside (operators can't rotate at runtime) is acceptable for
Phase 1 because operator activity is low-frequency.

The operator's *private* key stays in operator tooling (separate
binary or sealed secret). The control plane only ever sees public
keys + signatures.

### 3.5 Receipt-kind addition

New canonical action kind in `/spec/receipt/canonical-actions.md`:

| Kind | Actor | Description |
|---|---|---|
| `agent.operator_revoke` | Registry (control plane) | Produced when an operator evicts an agent via `AdmissionService.OperatorRevoke`. Evidence: `target_agent_id`, `operator_id`, `reason`, optional `cascade_receipt_ids`. |

`agent.revoke` semantics narrow: from "any revocation" to "self-
revocation only." Existing tooling that queries `agent.revoke`
should additionally query `agent.operator_revoke` to capture all
revocation events.

## 4. Drawbacks

- **New auth surface to audit.** Operator credentials are a powerful
  capability — losing the operator private key compromises the
  whole swarm's eviction layer. Mitigation: operator key lives in
  operator tooling, the control plane only holds public keys, and
  every operator action is a signed receipt the operator (and any
  other observer) can audit.
- **Wire-format break for bearer header.** Existing v1.1 clients
  emit `bearer <hex>` without an explicit variant; v1.2 servers
  treat that as `bearer agent <hex>` for back-compat, but new
  clients should be explicit. No real break, but a subtle
  convention shift.
- **Revoked-set memory.** Maintaining a revoked-set in the control
  plane is O(n) in revoked agents over the swarm's lifetime. For
  the in-memory backend this is trivial; for Postgres-backed
  swarms, the revoked-set is just a passport-store filter (already
  available from the existing `is_revoked` field; no new state).
- **Operator-key rotation deferred.** Stop-and-restart is an
  operational pain. Acceptable for Phase 1; future RFC.

## 5. Alternatives considered

- **Single bearer token with an `operator` boolean field.**
  Rejected — mixes agent and operator semantics in one type, makes
  client parsing harder, and conflicts with the principle that
  every signed message has one clear purpose.
- **Capability-based operator authority.** An operator holds a
  cap scoped to `agent.revoke` and uses it. Rejected — operators
  aren't agents; making them register a passport just to revoke
  others adds ceremony without buying security. Future operator
  workflows (rotate-key, restore, etc.) would inherit the same
  ceremony.
- **No active-stream tear-down; rely on bearer expiry.** Rejected —
  the 5-minute lag between revoke and effective deny is too long
  for the cases this RFC addresses (compromised agent in
  particular).
- **`Unrevoke` / `Restore` operation.** Rejected for Phase 1.
  Permanent revocation is simpler semantics. A revoked agent can
  rejoin via a fresh `Register` if the operator wants — under a
  new passport. The Phase-2 constitution work can revisit if
  norm-driven revoke wants reversibility.

## 6. Threat-model impact

- **A1 (bounded blast radius):** Strengthened. Operators now have
  an in-band, auditable eviction mechanism for compromised agents.
  The blast-radius bound shrinks from "5 minutes until token
  expiry" to "operator's reaction time + sub-second tear-down."
- **A8 (auditability):** Strengthened. Operator interventions are
  now signed receipts rather than out-of-band restarts.
- **New attack: forged operator token.** Attacker who compromises
  the operator private key can revoke any agent. Mitigation: the
  operator key lives in tooling-side secrets, not in the control
  plane. The blast radius is "all agents in this swarm get
  revoked," which is bad but recoverable (operators issue fresh
  passports). No persistent compromise.
- **New attack: revoked-agent replay.** A previously-revoked
  agent reuses its old bearer token. Mitigation: revoked-set
  consulted on every bearer verification; tokens reject
  immediately regardless of remaining wall-clock validity.
- **New attack: DoS via mass operator-revoke.** Compromised
  operator key could mass-revoke every agent. Mitigated by
  operator-key confidentiality; not a new substrate gap.

## 7. Conformance impact

- **AdmissionService conformance.** New
  `operator_revoke_evicts_agent` test: presents an
  `OperatorBearerToken`, calls `OperatorRevoke`, verifies the
  resulting receipt is `agent.operator_revoke`, verifies the
  target's subsequent `AgentBearerToken` requests reject with
  `UNAUTHENTICATED`.
- **Active-stream tear-down conformance.** New
  `revoke_closes_subscribe_stream` test: agent subscribes,
  operator revokes, the stream returns within 1 second with the
  documented error code.
- **Cascade-capability conformance.** Test: operator revokes with
  `cascade_capabilities=true`, response carries the
  `cascade_receipts`, each receipt resolves to `capability.revoke`
  with the right cap_id.
- **Receipt-kind audit.** Any client that queries `agent.revoke`
  must also query `agent.operator_revoke` to cover the full
  revocation history. Existing tooling needs a one-line update.

## 8. Migration

- **Servers without operator-key config.** Default behavior of
  v1.2 servers is identical to v1.1: no operator key, no
  `OperatorRevoke`. Existing deployments are unaffected.
- **Clients on v1.1 wire.** `bearer <hex>` continues to work
  (treated as `bearer agent <hex>`). New clients should emit the
  explicit variant.
- **Audit tooling.** Add `agent.operator_revoke` to any
  query-by-action-kind filter that currently looks for
  `agent.revoke`. Receipts continue to be queryable via the
  existing `ReceiptService.Query` shape.
- **Operator workflow.** Operators install the
  `yutha-operator-cli` (E3b deliverable) with their private key,
  and the control plane is started with `--operator-public-key
  <hex>`. No state migration; revoke is forward-only.

## 9. Open questions

- **Multi-operator support.** Should the server accept multiple
  operator public keys (any-of-N)? Useful for redundancy and
  for handover. Leaning yes but punting to a future RFC — v1.2
  ships single-key.
- **Threshold operator signatures (m-of-n).** Stronger property,
  but adds substantial verification complexity. Defer indefinitely
  unless a real workflow needs it.
- **Operator-revoke quotas.** Should the server rate-limit how
  many revokes a single operator key can issue per hour, to limit
  the blast radius of a compromised operator? Probably yes;
  Phase-2 concern (constitution layer is the natural home for
  rate limits).
- **Tear-down of active capability checks.** Should an in-flight
  `Check` RPC for a revoked agent's cap also abort? Today the
  check is fast (sub-ms) so this matters less than the streaming
  case. Leaning no — let in-flight check complete; subsequent
  checks deny.

## 10. Adoption checklist

- [ ] Spec doc updates (control-plane v1 proto, passport rationale, canonical-actions registry)
- [ ] Rust impl: `OperatorBearerToken` verification, `OperatorRevoke` handler, active-stream tear-down (cap store + transport), revoked-set in bearer auth
- [ ] Rust tests per §7 conformance bullets
- [ ] Python SDK: `YuthaClient.connect_as_operator(...)`, `client.admission.operator_revoke(...)`, demo extension
- [ ] At least two reviewers approved

## 11. References

- [`/spec/control-plane/v1.proto`](../control-plane/v1.proto) — bearer-token and AdmissionService definitions this RFC extends.
- [`/spec/passport/rationale.md`](../passport/rationale.md) §lifetime — the third revocation path this RFC adds.
- [`/spec/receipt/canonical-actions.md`](../receipt/canonical-actions.md) — registry getting the new `agent.operator_revoke` kind.
- [RFC 0008](./0008-wall-clock-bound-checks.md) — `OperatorBearerToken.expires_at` shares the wall-clock semantics established there.
- Memory: `revocation_posture.md` — the gap this RFC closes.
