# AP & invoice processing with payment caps

!!! info "Page in progress"
    Full content is being written.

What this example will cover:

- The agents: classifier (parses inbound invoices), extractor (normalizes fields), approver (initiates payment)
- The constitution: hard payment cap at $X per invoice, escalation procedure for invoices above $Y, refund-and-rollback path on duplicate detection
- The topology: closed (only operator-vetted agents touch payments)
- Walkthrough: a $250 invoice — classifier → extractor → approver → payment scheduled, receipts at every step
- Walkthrough: a $50,000 invoice — extractor flags above-threshold; approver agent's capability check denies; procedure routes to human supervisor; supervisor's signed approval becomes the unblocking receipt
- Walkthrough: a duplicate invoice (same vendor, same amount, within 24h) — reverse path triggers, scheduled payment is rolled back, both events recorded
- Audit trail: the full receipt log for one month, structured for SOX-style review
