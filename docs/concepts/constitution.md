# Constitution & enforcement

!!! info "Page in progress"
    Full content is being written. The authoritative references are [`/spec/constitution/`](../reference/specs.md) and RFCs 0010–0013.

A **constitution** is a declarative document, written in Cedar+, that governs which actions are permitted in a swarm. Cedar+ extends AWS's [Cedar](https://github.com/cedar-policy) policy language with:

- **Scoring rules** — soft preferences that influence enforcement progression without producing hard denies.
- **Procedures** — declarative state machines for multi-step approvals (e.g., "refund > $100 requires supervisor sign-off").
- **Resource budgets** — wall-clock and quota-bounded permissions.
- **Memory norms** — guards on what an agent may store or surface.

The **four-stage enforcement loop** progresses violations through:

1. **Flag** — record, don't restrict.
2. **Restrict** — narrow capabilities, retain identity.
3. **Quarantine** — block all consequential sends, retain receipts.
4. **Evict** — revoke passport, tear down active streams.

The loop is reversible: good behavior winds the stage back.
