# Examples

Worked end-to-end use cases. Each example shows the problem a team is actually trying to solve, the constitution and topology you'd choose, and the receipts you'd expect to see in the audit log. All four ship as runnable conformance scenarios in the repo.

- **[Customer support with a refund cap](customer-support.md)** — a classifier, an L1 agent, an L2 escalation agent. The constitution caps refunds at $100, requires a supervisor for anything larger, and evicts agents that try to bypass the cap.
- **[Knowledge-base privacy gate](privacy-gate.md)** — a research assistant talks to a KB agent. The constitution enforces that private memos require explicit caller capability; the receipt log proves access was authorized.
- **[Reversible long-running actions](reversible-actions.md)** — an agent makes a state-changing call. On detected misbehavior, the four-stage enforcement loop progresses through flag → restrict → quarantine, and the engine reverses the action without manual rollback.
- **[Verifiable AI pipeline](verifiable-pipeline.md)** — high-stakes batch processing where regulators or downstream systems need to verify the audit trail without trusting the operator. Receipts are anchored to Sui; anyone can independently verify the seal.
