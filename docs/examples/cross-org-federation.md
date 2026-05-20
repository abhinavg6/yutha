# Cross-organization agent federation

!!! info "Page in progress"
    Full content is being written.

What this example will cover:

- The setup: two operators, two control planes, two swarms. Org A runs publisher agents; Org B runs reviewer agents. Each org owns its own infrastructure.
- The shared constitution: a Cedar+ document both sides have ratified, covering what a publisher may submit, what a reviewer must check, what counts as approved, and what tear-down looks like if either side withdraws.
- The mechanism: capability tokens issued by Org A's operator are presentable at Org B's control plane (and vice versa). The two control planes synchronize the federation-relevant subset of their receipt logs.
- Walkthrough: Org A publishes a draft to the federation; Org B's reviewer evaluates and signs off; the final approval is anchored to Sui so neither side can repudiate the decision later.
- Walkthrough: Org B's reviewer flags a publication as violating the shared constitution. The constitution's four-stage loop progresses — restrict, quarantine — on Org A's publisher agent across the org boundary.
- Walkthrough: Org A revokes a publisher's passport. The revocation cascades through Org B's outstanding capabilities issued to that publisher; receipts on both sides reflect the tear-down.
- Why this is hard without Yutha: the alternative is bespoke API contracts that pretend trust is symmetric. Yutha's substrate makes the contract a signed artifact and the audit trail a first-class object.
