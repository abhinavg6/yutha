# Canonical action kinds

Every receipt carries an `action_kind` — a short string identifying what kind of consequential action it records. The set of canonical action kinds is fixed at the spec level so the audit trail is interpretable across implementations.

The authoritative registry lives at [`/spec/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/canonical-actions.md) in the repo.

Examples:

- `agent.register` — operator issued a passport to a new agent.
- `agent.revoke` — operator revoked an agent's passport.
- `envelope.send` — an agent sent an envelope.
- `envelope.deliver` — an envelope was delivered to its recipient.
- `capability.mint` — an operator or delegator minted a capability.
- `capability.check.pass` / `capability.check.deny` — a capability check fired during a send.
- `constitution.activate` — a constitution was activated for a swarm.
- `constitution.evaluate.pass` / `constitution.evaluate.deny` — a constitution check fired.
- `enforcement.stage.advance` / `enforcement.stage.regress` — the four-stage loop progressed or rolled back.
- `anchor.batch.committed` — a Merkle root was committed to Sui.

New action kinds are added via RFC, never ad hoc, so the audit log remains forward-compatible.
