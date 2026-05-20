# Examples

Worked end-to-end use cases. Each one starts from a real-world problem a team is trying to solve, walks through the constitution and topology choices, and shows the receipts you'd expect to see in the audit log.

- **[Customer support with a refund cap](customer-support.md)** — a classifier, an L1 agent, an L2 escalation agent. The constitution caps refunds, requires a supervisor for anything larger, and evicts agents that try to bypass the cap.
- **[Code review crew with security boundaries](code-review.md)** — reviewer + auto-fix agents on every PR. Capability-gated: auto-fix can edit most paths but is denied writes to security-tagged files. Every change leaves a signed receipt that survives audit.
- **[AP & invoice processing with payment caps](ap-invoice.md)** — classifier, extractor, approver. Hard cap per invoice; escalation procedure for high-value invoices; reverse path on duplicate detection. SOX-grade audit trail by default.
- **[Cross-organization agent federation](cross-org-federation.md)** — two operators, two swarms, one shared constitution. Capability tokens cross the org boundary; the receipt log is the contract.
