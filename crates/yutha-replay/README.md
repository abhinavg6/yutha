# yutha-replay

Replay engine for the Yutha control plane. Implements Phase 3c of
[RFC 0018 — Shadow-mode evaluator + replay engine](../../spec/rfcs/0018-shadow-mode-and-replay.md).

A `ReplaySession` previews a candidate constitution against a past
receipt window. Each session owns an isolated `EnforcementEngine`
instance plus a session-scoped `ReceiptStore` handle (obtained via
`ReplayStore::session_store`). Within-session receipts:

- Use the SAME canonical action-kinds as production.
- Carry a `replay_session_id` evidence marker (RFC 0018 §4.3).
- Copy causal predecessor refs from the original receipts.
- Are signed by the control-plane identity.

The two by-construction invariants — replay receipts never reach the
production engine forwarder and never anchor to Sui — hold because
the session-scoped store is a distinct `Arc<dyn ReceiptStore>` that
neither `PublishingReceiptStore` nor the `AnchorDriver`'s
`ReceiptStoreCandidateSource` is wrapped around or bound to.

See the spec for the full design contract.
