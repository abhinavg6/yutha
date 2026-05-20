# Verifiable AI pipeline

!!! info "Page in progress"
    Full content is being written. The operator setup for the anchoring side lives in [Operator → Sui anchoring](../operator/sui-anchoring.md).

What this example will cover:

- The use case: a regulated AI pipeline whose audit trail must survive operator non-cooperation
- The agents: classifier, action agent, verifier
- The constitution: action-classification rules, escalation thresholds
- The verifiability layer: receipt batching, canonical preimage, Sui anchoring
- Walkthrough: a third party fetches the on-chain commitment and the receipt log, and verifies the seal independently of the operator
- When this is overkill (vs. plain receipts) and when it's necessary
- Cost characteristics: anchoring cadence, Sui gas, latency expectations
