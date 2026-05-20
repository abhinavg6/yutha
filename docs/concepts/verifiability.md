# Verifiability

!!! info "Page in progress"
    Full content is being written. The canonical reference until then is [`/spec/verifiability/sui-anchoring.md`](../reference/specs.md) and RFC 0014.

The default deployment of Yutha produces a signed, append-only receipt log. That is sufficient for first-party audit — the operator can prove what happened to themselves and to anyone who trusts the operator.

For situations where a third party should be able to verify the receipt log *without trusting the operator*, Yutha offers optional **on-chain anchoring**. The control plane batches receipts, computes a Merkle root, signs a canonical preimage with the swarm's sealer key, and commits the (root, seal) pair to a public blockchain ([Sui](https://www.sui.io/) today). Anyone holding the receipt log can independently verify against the on-chain commitment.

The verifiability layer is opt-in. It is not required for normal operation and adds no dependency on a blockchain when not used.

For the operator playbook on standing up anchoring, see [Operator → Sui anchoring](../operator/sui-anchoring.md).
