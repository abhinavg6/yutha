# Operator guide

You're an **operator** if you're the person standing up, configuring, and running a Yutha swarm. That includes:

- Deploying the control plane and choosing a storage backend.
- Choosing the swarm's [topology](../concepts/topology.md) — closed, open, or hybrid.
- Authoring and activating the [constitution](../concepts/constitution.md) that governs the swarm.
- Managing operator credentials, including revocation.
- Anchoring the receipt log on Sui for third-party verifiability (optional).
- Monitoring receipts and responding to enforcement events.

If you're building agents that *join* a swarm someone else operates, you're a developer — see the [developer guide](../developer/index.md) instead.

## Start here

- **[Quickstart](quickstart.md)** — the 30-minute initiator path. Stand up a control plane, activate a constitution, register an operator credential, send a first envelope, observe receipts.
- **[Authoring constitutions](authoring-constitutions.md)** — how to write Cedar+ policy that says what you mean.
- **[Operator credentials](operator-credentials.md)** — how the operator identity works, how to rotate it, how to revoke an agent.
- **[Sui anchoring](sui-anchoring.md)** — opt-in cryptographic verifiability via on-chain Merkle commitments.
- **[Monitoring & receipts](monitoring.md)** — what to watch, what to alert on.
- **[Deployment](deployment.md)** — Postgres backend, scaling, single-tenant defaults.
