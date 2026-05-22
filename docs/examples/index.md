# Examples

Worked end-to-end use cases. Each one starts from a real-world problem a team is trying to solve, walks through the constitution and topology choices, and shows the receipts you'd expect to see in the audit log.

- **[Customer support with a refund cap](customer-support.md)** — router, three L1 specialists, an L2 escalation. The simplest example: per-agent identity, capability-gated dispatch, live cap-revoke, self-revoke vs. operator-driven eviction. Layer a refund-cap constitution on top by following the patterns the next two examples use.
- **[Code review crew with security boundaries](code-review.md)** — reviewer + auto-fix + human-approver. A Cedar constitution forbids `patch_applied + security_sensitive` envelopes; two bypass attempts trip the four-stage enforcement loop (detect → coach → quarantine → evict). Every change leaves a signed receipt.
- **[AP & invoice processing with payment caps](ap-invoice.md)** — classifier, auto-approver, supervisor, treasury. Constitution gates over-cap authorizations on the presence of a `supervisor_approved` tag; the approver's bypass attempts trip the same enforcement chain. SOX-grade audit trail by default.
- **[Cross-organization agent federation](cross-org-federation.md)** — two operators, two swarms, one shared constitution. Capability tokens cross the org boundary; the receipt log is the contract. *(Design sketch — runnable demo lands after the Phase 3 federation primitives.)*
