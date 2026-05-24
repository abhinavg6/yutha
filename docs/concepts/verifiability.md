# Verifiability

Every Yutha deployment produces a signed, append-only receipt log — a complete trail of every consequential action the swarm took, content-addressed and replayable. For most operators that log is enough. You can hand it to your own auditors, you can replay it to reconstruct an incident, you can prove to your own leadership that a particular agent took a particular action at a particular time.

**Verifiability** is the layer you reach for when "trust the operator" is exactly the assumption you can't make — a regulator who needs independent evidence, a downstream customer who's contractually entitled to non-repudiable proof, a federation partner whose org charter forbids relying on your storage. The mechanism is straightforward: the control plane periodically batches receipts, Merkle-roots them, signs the root with a swarm-specific sealer key, and commits the (root, signature) pair to a public blockchain ([Sui](https://www.sui.io/) today). Anyone holding a copy of the receipt log — your auditor, your customer, you yourself a year after a key compromise — can verify the trail against the on-chain commitment without ever touching your Postgres.

The layer is opt-in. The substrate works without it; there is no Sui dependency at runtime when anchoring is disabled, no startup checks against an RPC node, no shadow code path. If you don't need it, you don't pay for it.

## What the default already gives you

Before talking about anchoring it's worth being precise about what the *non*-anchored deployment already proves.

Every receipt Yutha writes is canonically encoded — there is one and only one byte representation a given receipt can have — and the canonical bytes are hashed to produce the receipt's content address. The control plane signs every receipt; agents that emit receipts sign theirs too. The signatures are over the canonical bytes, so anyone holding a receipt can recompute the canonical encoding, recompute the hash, and verify the signature against the sender's published public key.

The log is also append-only at the schema level: receipts reference each other by content address, so silently rewriting a receipt mid-history breaks every downstream reference. A receipt is a record of a consequential action — an envelope dispatch, a capability check, a constitution evaluation, an enforcement transition — and the catalog of "consequential" is fixed by the canonical action-kinds list in the spec, not by something the operator can quietly redefine.

That is enough for first-party audit and for a large class of external audits. If your auditor is willing to assume your Postgres is intact — because they have read access, or because they trust your storage chain of custody, or because the audit relationship simply isn't adversarial — the default log is everything they need.

What the default doesn't defend against is an operator who *quietly mutates the log itself*. Selective deletion of an embarrassing `constitution.evaluate.deny` receipt, backdated insertion of a fabricated "we knew about this all along" record, silent erasure of a `constitution.activate` that an operator now wants to disclaim — none of these leave a trace in a log the operator controls.

The signatures don't help here because the operator controls the signing identity for the receipts they themselves emit, and the cross-references don't help because the operator can rewrite the whole transitive closure in one go. The defense has to come from outside the operator's perimeter. Verifiability exists for exactly these cases.

## The anchoring scheme

A small background task — the sealer — runs inside the control plane. On a hybrid cadence it gathers the unsealed receipts, sorts them deterministically by `(occurred_at_ns, receipt_id)`, and builds a binary Merkle tree using SHA-256 and the sorted-pair internal-node convention.

"Hybrid cadence" means whichever fires first: N receipts accumulated, or T seconds since the last batch — both knobs operator-tunable, defaulting to 100 receipts and 10 seconds. High-throughput swarms hit the count threshold first and anchor frequently; quiet swarms still anchor every 10 seconds so there's no indefinitely-unsealed window for an attacker to exploit. Zero-traffic swarms idle gracefully — there's nothing to anchor.

The leaf at each tree node is the receipt's existing content address, which means the receipt id and the Merkle leaf hash are the same 32 bytes — one fewer hash per receipt, and verifiers don't have to recompute the leaf. The sorted-pair internal-node rule (each parent hashes the lex-smaller child first) means a verifier doesn't need to carry left/right direction bits along with each path entry; the path is just a sequence of sibling hashes, and walking it is a one-line recurrence.

With the root in hand, the sealer builds a canonical preimage — the swarm id, the root, the receipt count, the min/max `occurred_at_ns` of the batch, and a sorted action-kind histogram, packed in a fixed byte layout that the on-chain Move module reconstructs byte-for-byte. It signs that preimage with the swarm's Ed25519 sealer key.

Then it submits a single Sui transaction calling `commit_batch` on a per-swarm `SwarmAnchor` shared object. The Move module re-derives the same canonical preimage on-chain, runs `ed25519_verify` against the public sealer key it was registered with at swarm-anchor creation time, enforces a monotonic ns-range invariant against the prior batch, and on success advances the on-chain batch counter and emits an `AnchorCommitted` event. That re-derivation is the load-bearing detail — it means the off-chain sealer and the on-chain module have to agree on the preimage *byte for byte*, and conformance vectors in the repo pin the byte layout so any third-party reimplementation can be checked against the same fixtures.

Postgres remains the primary store. Sui-RPC unavailability never blocks a receipt append — unanchored receipts accumulate, and the sealer drains the backlog when the RPC comes back. The send-path latency of the substrate is unaffected by anchoring health, on purpose. The asymmetry is deliberate: receipts-without-anchors is a degraded-but-recoverable state, while anchors-without-receipts would be an integrity violation.

The single-key trust model is worth being explicit about. There's one Ed25519 sealer key per `SwarmAnchor`, and the on-chain check refuses anchors that aren't signed by it.

A compromised Sui RPC node cannot forge anchors — the signature is verified on-chain by the Move runtime, not by the RPC. A compromised Postgres alone is detected — the next external verifier sees the divergence between the on-chain root and the reconstructed root.

The case the v1 model does *not* defend against is an attacker who has both Postgres write access *and* the sealer key; that collusion lets them produce a coherent, internally-consistent forgery. The structural fix is multi-key sealing with supervisor multisig — distinct human or service principals each holding one share, the on-chain check requiring a threshold of them to sign — and it's a known follow-on, not in v1. Until it lands, operators should treat the sealer key with the same operational care they'd give a code-signing key: separate storage from the operator-level bootstrap key, separate rotation policy, separate access list.

The action-kind histogram on every commit is the small piece that's easy to miss the value of. It's not strictly necessary for inclusion proofs — those need the root and the path. But putting it on-chain lets anyone with Sui RPC access answer "is this swarm seeing weird volumes of `enforcement.evict` today" without ever needing read access to Postgres. Operational observability falls out for free, and a downstream party can build dashboards on top of the public event stream using any standard Sui indexer (Suiscan, Suivision, self-hosted) without any Yutha-specific schema.

One small but pleasant property: each successful anchor produces its own `anchor.commit` receipt in the regular log, and that receipt is itself eligible for inclusion in a later batch. The audit trail of "when we anchored" is part of the audit trail. That recursion bottoms out naturally at the cadence boundary and gives an operator (or a verifier) a normal, queryable record of every commit alongside the on-chain event stream.

## Why Sui

This is the question every infrastructure choice has to answer honestly. Sui is the only shipped backend today, and the choice is reasoned, not religious.

Three properties mattered.

First, transaction cost and finality at the cadence we want — anchoring is fundamentally a frequent-small-commit workload (a batch every few seconds in busy swarms), and Sui's gas economics and sub-second finality match that shape. Bitcoin's commit cadence and fee dynamics would have made per-minute anchoring prohibitive; Ethereum L1's would have been workable but expensive enough to push the cadence in the wrong direction.

Second, on-chain Ed25519 verification as a native primitive. The on-chain check that "this anchor was signed by the registered sealer key" is what makes a compromised Sui RPC node untrusted in the threat model, and Sui exposes `ed25519_verify` natively in Move. Rolling our own on a chain that doesn't have it natively was an option we declined; cryptographic primitives belong in the platform layer.

Third, Move's resource model and `UpgradeCap` story matched the operator-owned deployment posture: each operator publishes their own copy of the `receipt_anchor` package, holds the upgrade authority themselves, and can freeze the package post-publish if they want strict immutability. No Yutha-operated canonical mainnet deployment, no shared upgrade authority, no operator forced to trust us with their audit trail.

An Ethereum (or L2) backend would have been a defensible alternative on the first two counts, with different tradeoffs on the third. The sealer trait is backend-agnostic — `seal_batch` doesn't know what chain it's talking to — so a second backend can be added when there's appetite for it. We didn't ship two at once because shipping one well is more useful than shipping two halfway.

The Move package itself lives at [`/contracts/sui/receipt_anchor/`](https://github.com/abhinavg6/yutha/tree/main/contracts/sui/receipt_anchor) in the OSS repo: a few hundred lines of Move, deliberately small, deliberately auditable. Operators publish their own copy; there is no canonical Yutha-operated deployment to defer to. The same source compiled on testnet vs. mainnet produces different package ids and different `SwarmAnchor` objects — both isolated, both equally valid targets, both fully under the operator's control.

## What a verifier actually does

The shape of a verification is concrete enough to pseudo-code in a paragraph.

You receive a receipt — either pulled from the operator's log or handed to you by some other party — along with the Merkle path the sealer recorded for it and the on-chain batch index it was anchored under. You query Sui for the `AnchorCommitted` event at that batch index on the swarm's `SwarmAnchor` shared object. From that event you get the on-chain `batch_root`, the on-chain `swarm_id`, and the on-chain histogram.

You recompute the receipt's content address from its canonical bytes — that's your leaf. You walk the Merkle path leaf-to-root using the sorted-pair hash rule. You compare your computed root against the on-chain `batch_root`. If they match, the receipt was anchored.

If you also want to confirm that the operator who claimed the anchor was the holder of the swarm's sealer key, you reconstruct the canonical preimage from the on-chain fields and run `ed25519_verify` against the `sealer_pubkey` field of the `SwarmAnchor` object — but Sui already did that on-chain at commit time, so any anchor that landed at all has the signature property by construction. The redundant off-chain check is useful only as a defensive sanity step or when you're testing a third-party verifier implementation against the spec.

In Python-ish pseudocode:

```python
def verify_receipt(receipt, merkle_path, batch_index, sui_rpc):
    # 1. Leaf = receipt content address, already in receipt.id.
    leaf = receipt.id  # 32 bytes, SHA-256 of canonical bytes

    # 2. Walk the path with sorted-pair hashing.
    current = leaf
    for sibling in merkle_path:
        a, b = sorted([current, sibling])
        current = sha256(a + b)

    # 3. Fetch the on-chain commitment.
    event = sui_rpc.get_anchor_committed(
        swarm_anchor_id=KNOWN_SWARM_ANCHOR_ID,
        batch_index=batch_index,
    )

    # 4. Compare.
    if current != event.batch_root:
        raise IntegrityError("receipt not in claimed batch")
    if event.swarm_id != KNOWN_SWARM_ID:
        raise IntegrityError("wrong swarm")

    return Verified(
        anchored_at_ms=event.anchored_at_ms,
        on_chain_tx_digest=event.tx_digest,
    )
```

A verifier needs three pieces of public information ahead of time: the swarm id, the `SwarmAnchor` object id on Sui, and the sealer public key registered against that anchor. All three are operator-published — usually in the same place you'd publish the operator's gRPC endpoint or your service's TLS certificate fingerprint. None of them is a secret, and a verifier that holds them does not need any other privileged access to the operator's infrastructure.

Beyond per-receipt inclusion, a verifier that ingests the full on-chain event stream can do more. They can check that batch indexes are gapless (each commit increments by one), that ns-ranges are monotonic and don't overlap (the Move module enforces this on-chain, but external re-checking is cheap), and that the cadence the operator advertises is actually what they're hitting in practice. A sudden silence in the event stream is a signal even before any individual receipt is examined.

The operator playbook for the setup side — generating the sealer key, publishing the Move package, creating the `SwarmAnchor`, wiring the control plane flags — is at [Operator → Sui anchoring](../operator/sui-anchoring.md).

## What verifiability does *not* prove

It's important to be honest about the scope. Anchoring proves a specific, narrow integrity property — and it's worth enumerating what it doesn't carry.

- It doesn't prove an agent took the *right* action. Whether a particular send was actually allowed under policy is a question for the [constitution](constitution.md) and the four-stage enforcement loop; the receipt log just records what the evaluator decided. A constitution that says yes to something you wish it had said no to produces an anchored, perfectly-verifiable receipt of the operator's mistake.
- It doesn't prove an operator hasn't *selectively withheld* receipts. Anchoring shows you what was anchored. If the operator never sealed a particular batch — say, an embarrassing one — there's no anchor to point at and no inclusion proof to walk. A diligent verifier can ask "are there gaps in the anchored ns-ranges that would suggest missing batches" but only for batches the operator chose to seal at all. The defense against pure omission is a separate property — the cadence guarantee itself ("a healthy sealer commits every 10 seconds") is something the verifier observes externally.
- It doesn't prove a model produced sensible reasoning. The audit trail records that a particular agent emitted a particular envelope with a particular payload; whether the LLM behind that agent was hallucinating is outside the substrate's remit and frankly outside what a substrate could verify.
- It doesn't prove exact wall-clock time. The on-chain `anchored_at_ms` is the Sui block clock — a publicly-witnessed timestamp, which is genuinely useful — but the `occurred_at_ns` on each receipt is the substrate's own monotonic counter. The two together bound when a receipt could have been created (no later than the anchor's wall-clock, no earlier than any prior anchor's `last_ns_range_end`), but they don't pin the exact wall-clock moment.

Verifiability is integrity of the audit trail. It is not semantic correctness of the agents above the trail.

It also doesn't replace good operational practice — log retention policies, backup hygiene, access reviews on the operator key and the sealer key. Anchoring makes tampering detectable; it doesn't make a slipshod operation tidy.

## When to opt in

The honest rule of thumb: if you can't already articulate why the default log isn't enough for your situation, you probably don't need anchoring yet.

Most swarms — internal tools, prototype workflows, hobby agents, marketing automation — get everything they need from the signed Postgres log and an honest backup policy. Layering on anchoring before there's a verifier asking for it is premature optimization with real ongoing cost.

Reach for anchoring when one of these is true.

Regulated workflows where the audit trail itself is a deliverable to a regulator who is structurally not your friend — financial reconciliation, healthcare event logs, legal-discovery preservation. The reg-side question is rarely "can we trust your records" so much as "can a successor administrator trust your records," and anchoring answers that without requiring the regulator to model your storage architecture.

Cross-organization federation where two parties' agents collaborate under a shared constitution and neither side's leadership is willing to trust the other's storage. Anchoring on a chain both sides can read collapses the "whose log is canonical" argument before it starts.

Long-horizon deployments where the receipt log might need to outlive the operator — an acquisition where the acquirer wants verifiable continuity of pre-acquisition events, a divestiture where the spun-out business carries proof of its prior governance, organizational collapse where the trail needs to survive bankruptcy of whoever was running the Postgres.

In each case the property that matters is the same: a third party, at a future date, can verify the trail without trusting a custodian who may no longer exist or no longer be incentivized to cooperate.

The cost is real but bounded — a Sui RPC dependency for the sealer (operator-supplied, can be a self-hosted full node), gas costs at the operator's chosen cadence, one extra key to manage (the sealer key, distinct from the operator key), and a one-time Move package publish. None of it changes the substrate's send path; none of it leaks into the agents themselves.

Staged adoption works. The same swarm can run unanchored in development, anchored to localnet in integration, and anchored to mainnet in production — same binary, same code path, only the `--anchor-*` flags change. Operators routinely start by enabling anchoring on testnet for a quarter or two, get comfortable with the operational shape (gas burn, RPC health, sealer-key rotation drills), then flip the RPC URL to mainnet when the rest of the deployment is production-stable. There's no migration of historical receipts implied — anchoring begins forward from the moment it's enabled, and the pre-anchoring portion of the log retains exactly the integrity property it had before.

## Where to go next

The full specification, including the byte-exact canonical preimage layout and the Merkle construction rules, is at [`/spec/verifiability/sui-anchoring.md`](https://github.com/abhinavg6/yutha/blob/main/spec/verifiability/sui-anchoring.md).

The design rationale, threat model, and deferred follow-ons (multi-key sealers, supervisor multisig, multi-chain redundancy) are in [RFC 0014](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0014-sui-receipt-anchoring.md).

For the operator playbook end-to-end — sealer key, Move package publish, `SwarmAnchor` creation, control plane flags — see [Operator → Sui anchoring](../operator/sui-anchoring.md).

The Move package source is at [`/contracts/sui/receipt_anchor/sources/receipt_anchor.move`](https://github.com/abhinavg6/yutha/blob/main/contracts/sui/receipt_anchor/sources/receipt_anchor.move). It's small enough to read in one sitting and that's the recommended way to convince yourself the on-chain check does what this page claims it does.
