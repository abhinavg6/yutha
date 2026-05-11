# Envelope Spec — Design Rationale

> **Spec:** [`envelope-v1.proto`](./envelope-v1.proto)
> **Version:** v1.0 draft
> **RFC:** 0003
> **Threat-model linkage:** A3 (prompt injection), A5 (network adversary), A8 (malicious operator partial)

## 1. What is an envelope, in one paragraph

An envelope is the typed wrapper around every agent-to-agent message in Yutha. Untrusted content (LLM output, tool result, customer text, document content) lives inside `payload`; the envelope's other fields — performative, recipient, swarm, causal predecessors, nonce, epoch, signature, tags — are typed, signed by the sender, and authoritative. The envelope is what the control plane reasons about; the payload is what the application reasons about. This split is what makes prompt injection (A3) containable: even if an LLM is convinced to embed instructions in the payload, those instructions cannot synthesize a valid envelope of a forbidden performative because they cannot produce the agent's signature.

## 2. Why this shape

The envelope is the most thoughtfully shaped artifact in Yutha because it is the surface where the platform's two hardest problems meet:

- **Untrusted content has to flow through it.** LLM outputs, tool returns, customer messages — all untrusted. Any of them might contain instructions trying to escape into the control plane.
- **Authority decisions ride on it.** The control plane decides "is this agent allowed to send this performative to this recipient" based on envelope fields. If those fields are forgeable from inside the payload, the substrate is broken.

The defense is structural separation. The envelope is signed by the agent's key over its non-payload fields plus the payload bytes (as opaque). The payload may be any byte string; the envelope's authoritative claims (who, to whom, what kind of message, in what swarm, depending on what causal predecessors) are not affected by what the payload says. An adversary that controls the payload cannot rewrite the envelope without also controlling the agent's private key, which is the trust boundary.

## 3. Field-by-field rationale

**`spec_version`.** First, for the same reason as in passport: version negotiation must precede interpretation.

**`swarm_id`.** Every envelope is single-swarm. Cross-swarm transmission is a federation operation (Phase 4) with explicit handshake, never an envelope-level shortcut. This is what makes A4 (hostile peer swarm) bounded: a passing hostile envelope cannot trivially appear as a same-swarm envelope.

**`envelope_id` (UUID v7) vs. content-address.** Two different identifiers. `envelope_id` is for lookup and idempotency (the receiver can dedup repeated deliveries). The content-address (hash of canonical serialization with signature cleared) is for causal references and for tamper detection. Carrying both pays a small cost in size and yields a much simpler reasoning model: identity ≠ integrity.

**`from_agent`.** Resolves to a passport (and thus a public key) at signature verification time. Receivers MUST verify the signature against the passport's key, not against any inline key.

**`recipient` (oneof).** Four kinds of recipient — agent, role, swarm, external. Role and swarm broadcast are what makes role-based dispatch work at the substrate layer. External endpoints exist because some envelope kinds explicitly target outside systems (e.g., a notification to a webhook); these always require a capability token to authorize, and the topology mode may forbid them entirely.

**`performative`.** Speech-act-theoretic enumeration. The set in v1.0 is intentionally small (eleven values) and additive — new performatives go through RFC. The control plane and the constitution dispatch on this; observability surfaces it. Unknown performatives default to UNKNOWN and are surfaced; **never silently ignored**, which is the difference between an audit trail and a leak.

**`payload` and `payload_schema_id`.** Bytes plus schema identifier. The substrate does not introspect payload bytes (they may be encrypted). Schema identifiers are what SDK adapters use to deserialize on the receiver side; they are also what the constitution can match on (e.g., "any envelope with payload_schema_id starting with 'finance.' requires a capability check").

**`tags`.** Free-form classification tags applied by the SDK adapter at envelope-construction time. Examples: "pii", "external", "high_risk", "customer_data". Tags are part of the signed surface, so they cannot be retroactively altered. Constitution norms can match on tags. Tag *vocabulary* is operator-defined per swarm; canonical schemas (Phase 2 deliverable) ship with conventional tag sets.

**`causal` (CausalRef).** The DAG is emitted, not reconstructed. Empty only for the genesis message of a chain. This is what makes counterfactual replay (Phase 3) tractable — the dependencies are known, not inferred. Every receipt that records an envelope-send action carries the same predecessors.

**`nonce` and `epoch`.** Replay protection has to defeat both same-window replay (use a nonce) and stale replay across windows (use an epoch counter). v1 does both. Rationale: a nonce alone is sufficient if the receiver keeps unbounded state; in practice the nonce window has to be bounded and the epoch is what bounds the cost of that state. A6 (sybil) and A5 (network) are the relevant adversaries.

**`sent_at` and `expires_at`.** TTL on top of replay protection. Defends long-delayed adversarial replay where nonce / epoch state has aged out. Optional; if unset, the swarm's default TTL (declared in topology) applies. Per the threat model's cross-cutting "time" concern, comparison logic uses monotonic_ns, not wall_clock.

**`in_reply_to`.** Conversation linkage. Optional. When set, the payload is scoped to a prior envelope; this is what makes per-conversation memory and constitution rules possible without re-walking the causal DAG.

**`extensions`.** Forward-compatibility hatch.

**`agent_signature`.** Last. Computed over canonical serialization with this field cleared. The trust anchor of the entire envelope.

## 4. Threat-model linkage

| Adversary | How this spec contributes to mitigation |
|-----------|------------------------------------------|
| A3 Prompt injection | The single most important spec for A3. Typed performatives, recipient oneof, schema-tagged payload, signed surface — none of the authoritative envelope fields are derivable from a payload string. An injected instruction cannot synthesize a valid envelope of a forbidden kind. |
| A5 Network adversary | Nonce + epoch + TTL + signature give layered replay protection. Causal predecessors mean reordering is detectable. Identity-bound channels (transport spec) are the encryption layer; envelope signing is the integrity layer; both apply. |
| A8 Malicious operator (partial) | Receipts that reference envelopes by content-address mean a malicious operator cannot silently rewrite envelopes after the fact — the rewrite would change the content-address and break every receipt that referenced it. |

## 5. Conformance hooks

A conformant transport implementation:

- **Verifies envelope signatures** against the sender's passport. Rejects on mismatch with `ENVELOPE_ERROR_SIGNATURE_INVALID`.
- **Enforces nonce + epoch + TTL** with the spec'd default windows, per `/docs/conformance/conformance-suite.md` §3.4. Rejects with `ENVELOPE_ERROR_REPLAY_DETECTED` or `ENVELOPE_ERROR_EXPIRED`.
- **Preserves causal metadata** end-to-end. Tests verify that an envelope with N predecessors arrives at the recipient with the same N predecessors and identical bytes.
- **Routes per recipient.oneof** to exactly one delivery path. Unicast, role-broadcast, swarm-broadcast, external — each has its own conformance test.
- **Surfaces unknown performatives** as `ENVELOPE_ERROR_UNKNOWN_PERFORMATIVE` rather than dropping silently or coercing to a known kind.
- **Produces envelope-send receipts** before delivery confirmation. The receipt is the load-bearing audit trail, not the delivery acknowledgement.

The transport sub-suite at `/conformance/interface/transport/` covers the common requirements (signature, replay, causal, recipient routing), and the per-profile tests (datacenter, WAN, constrained) layer on the latency and partition-tolerance properties.

## 6. Why these performatives, and why only eleven

Speech-act theory gives us a useful taxonomy: assertives (inform, query), commissives (commit, propose, counter), directives (request_action), expressives (confirm, decline), declaratives (release), plus the failure-domain primitives (error, abort).

We resisted the urge to ship a large performative vocabulary. Eleven covers the negotiation patterns named in the PRD (Contract Net, auctions, deadline negotiation, divisible-resource split, mediated dispute) without bloat. New performatives require an RFC for the same reason new HTTP verbs would: they are part of the protocol's reasoning surface.

What is *not* a performative:

- Domain-specific actions ("issue_refund", "fetch_document") — these are payload kinds, not performatives. The performative is REQUEST_ACTION; the payload says what action.
- Control-plane operations ("register", "rotate_key") — these are receipt kinds, not envelope performatives. They are typed at the receipt layer.
- Constitution-engine operations ("propose_amendment", "vote") — these are payload kinds inside REQUEST_ACTION envelopes routed to the constitution role.

This keeps the performative surface stable across phases and avoids the FIPA-ACL trap of shipping forty performatives that nobody can map to their use case.

## 7. Why the payload is opaque to the substrate

The substrate does not introspect payload bytes. Reasons:

- **Encryption.** Memory-norms and selective-disclosure flows may encrypt payloads. The substrate must route them anyway.
- **Trust boundary.** Anything the substrate parses, it has to defend. Keeping payload opaque shrinks the substrate's attack surface.
- **Composability.** Payload schemas are operator-defined; the substrate should not need updates when an operator ships a new payload type.
- **Privacy minimization.** PRD §13.3: receipts and observability should gather only what is necessary. Substrate-level introspection of payloads would tempt feature creep into surveillance.

Constitution norms that need to inspect payloads do so at the SDK boundary, where the agent's runtime has already deserialized them and the norms operate on structured fields. The substrate sees only the envelope shell.

## 8. Alternatives considered

**JSON envelopes instead of protobuf.** Rejected: canonical serialization is harder in JSON; signing is more error-prone; binary efficiency matters in the transport hot path. JSON adapters can be added at the SDK boundary if anyone wants them.

**Embedding the recipient's public key.** Rejected: the receiver looks up the recipient's passport. Embedding would make the envelope larger and would couple delivery to a stale view of identity.

**Implicit causal predecessors derived from envelope_id ordering.** Rejected: ordering ≠ causality. Implicit derivation breaks the moment two messages from different agents arrive at a third agent in either order.

**Per-recipient signatures.** Rejected for v1: the single agent_signature plus per-recipient delivery is sufficient. Multi-recipient signed envelopes are a future multi-sig variant if a use case emerges.

**Stronger anti-replay (e.g., per-recipient sequence numbers).** Rejected: nonce + epoch + TTL is sufficient for a substrate; per-recipient sequencing is a transport-layer concern (implementations may add it as an optimization).

## 9. Open questions for RFC review

- Should `tags` carry structured (key=value) entries instead of bare strings? Bare strings are simpler and match the existing constitution-language design (Cedar+ predicates match on tags as set membership). Lean toward keeping bare strings.
- `expires_at` granularity vs. swarm default: should v1 require explicit expires_at on EXTERNAL recipients? Probably yes — external sends are riskier, default-implicit TTL there is too easy to misconfigure.
- `payload_schema_id` registry: free-form vs. central list. Currently free-form (operator owns); maintaining a public list of canonical schemas is a Phase 2 ship.
- Should `epoch` be operator-tunable per swarm or fixed protocol semantics? Currently fixed (monotonic-per-sender, integer); operator tuning is configuration in topology, not envelope.
- Encrypted-payload metadata: do we need an inline `encryption_scheme` field at v1, or is that an extension? Currently extension; expected to be standardized in v1.1 once the memory-encryption work matures.

## 10. Future evolution

- v1.1 likely standardizes `encryption_scheme` for encrypted payloads.
- v1.x adds REQUEST_INFORMATION (a strict information-only request distinct from QUERY) if the negotiation library demands it.
- v2.0 may move to multi-recipient atomic delivery if Phase 4 federation requires it.
