# Operator credentials

The operator credential is what the control plane checks against
when an operator-level action lands — activating a constitution,
evicting an agent, cascading capability revocations downstream.
It's a single Ed25519 keypair under v1; the control plane holds
the public half, your operator tooling holds the private half,
and every operator action is a signed receipt the audit log
keeps forever.

This page covers what the credential is, how to generate and
store it, how to rotate it today, and exactly what happens when
you revoke an agent — including the capability cascade and
active-stream tear-down. If you haven't stood up a control
plane before, read the [operator quickstart](quickstart.md)
first; this page expands on the *why* and *what's-deferred*
behind the commands there.

---

## What it is

An operator credential is an Ed25519 signing key, derived
deterministically from the same 32-byte bootstrap seed the rest
of the swarm's genesis identities come from. The control plane
sees only the public counterpart (passed via
`--operator-public-key` at startup); the private half stays on
whatever machine `yutha-ops` runs on, and every operator-bearer
token `yutha-ops` mints is signed with that private key locally.

The derivation is simple and stable. Given the seed:

```text
operator_signing_key = sha256(seed || 0x03)
swarm_id             = sha256(seed || 0x02)[:16]
bootstrap_agent_key  = seed   (raw 32 bytes, Ed25519)
```

So the same seed that derives the bootstrap agent and the
swarm's id also derives the operator key. There's nothing extra
to ferry around — hand the seed to the server's environment, and
`yutha-ops` reconstructs the operator key on demand for every
invocation.

Under v1, **one operator key per swarm**. Multi-operator (any-
of-n trust bundles), threshold (m-of-n) signing, and runtime
rotation are all explicitly deferred — see
[RFC 0009 §9](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0009-operator-credentials.md#9-open-questions)
for the open questions and the rationale for keeping v1 single-
key.

---

## What it authorizes

The credential gates a small, deliberate set of state-changing
operations. Each is one RPC, each emits a signed receipt:

- **Activating a constitution.**
  `ConstitutionService.Activate` requires an operator bearer.
  Without one configured, the call returns `FAILED_PRECONDITION:
  operator credentials not enabled`. The activation lands a
  `constitution.activate` receipt content-addressed against the
  full constitution proto.
- **Operator-revoking an agent.**
  `AdmissionService.OperatorRevoke` is the in-band eviction path
  (RFC 0009 §3.2). Self-revoke remains on `AdmissionService.
  Revoke` under the agent's own bearer; cross-agent revocation
  is operator-only.
- **Cascade-revoking an agent's capabilities.**
  The cascade flag on `OperatorRevoke` walks every capability
  the target currently holds and revokes each — one
  `capability.revoke` receipt per cap, all returned in the
  response's `cascade_receipts` list.
- **Registering agents into closed or hybrid swarms.**
  In closed admission mode, the operator countersigns the
  passport before `AdmissionService.Register` will accept it. In
  open mode, agents self-register and the operator's signature
  isn't on the critical path; in hybrid, the operator gates
  whichever tier the topology pins.
- **Operator-issued capabilities.**
  Where a capability needs the operator as the issuer
  (`Issuer.for_operator(operator_pubkey)`), the signing happens
  with the operator's private key.

What the operator credential explicitly does **not** authorize:
signing as a specific agent (agent passports are self-signed —
the operator key isn't trusted for agent-bearer auth);
rewriting or back-dating receipts (the audit log is append-only
and content-addressed); issuing capabilities outside an agent's
own passport scope (the cap chain-of-issuance rules apply
equally to operator-issued caps); or any special read
privilege on `ReceiptService.Query` (that's agent-bearer-
authenticated and the operator gets no special access).

---

## Generating the credential

The bootstrap-seed pattern from the [quickstart](quickstart.md)
covers the mechanics. Briefly:

```bash
# Mint a 32-byte seed. This single hex string is the only durable
# secret you need to manage.
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

# Derive the operator public key locally — no server connection
# needed; pure sha256 over the seed.
export YUTHA_OPERATOR_PUBLIC_KEY=$(yutha-ops print-operator-pubkey)
```

`print-operator-pubkey` prints the 64-character hex form on
stdout and exits. The control plane consumes it via
`--operator-public-key "$YUTHA_OPERATOR_PUBLIC_KEY"` at
startup; the private key never leaves the machine `yutha-ops`
runs on.

The seed is the durable secret — everything else derives from
it. Never check it in. The repo's `.gitignore` already excludes
`*.key` and `Pub.*.toml` patterns, but the seed has no canonical
filename, so it's on you to keep it out of source control and CI
logs.

---

## Storing the credential

For local development, exporting `YUTHA_BOOTSTRAP_SEED` in your
shell is fine. For production, the seed belongs in a real
secrets manager — KMS, Vault, 1Password, whatever gives you
durability plus access control — and gets injected into the
control plane's environment via your usual mechanism (init
container, sidecar, IAM role).

When you want the seed available to `yutha-ops` interactively
without writing it to durable disk, the tmpfs-symlink pattern
works: drop the seed into a tmpfs-backed file at
`~/.yutha/seed` on session start, source the env from it, and
let it evaporate at logout. The file never hits a persistent
filesystem.

What you should *not* do: pass the seed on the command line as
`--bootstrap-seed <hex>`. `ps aux` would expose it to every
other process on the machine; always go through the env var.

---

## Rotating today

There is no runtime rotation in v1. To rotate the operator
key: mint a fresh seed, derive the new public key with
`yutha-ops print-operator-pubkey`, stop the control plane,
restart it with the new `--operator-public-key`, and update
whatever wraps `yutha-ops` to use the new seed.

What survives the rotation: every agent passport (self-signed
by the agent's own key, not the operator's), every receipt in
the audit log (signed by the control plane's identity), and
every existing agent-bearer token.

What does **not** survive: in-flight operator-bearer tokens
signed with the old key (the control plane no longer trusts the
old public key — re-mint), and operator-issued capabilities
whose signature chains back to the old key (the cap layer's
check path denies them at use time). For compromise-driven
rotations the second point is exactly what you want; for
planned rotations, reissue any operator-signed caps post-
restart.

Plan rotations during a maintenance window — the restart is
seconds, but the gap is a gap in operator-driven enforcement.
Runtime rotation without restart is a Phase-3 follow-on.

---

## Revoking an agent

The shape is straightforward:

```bash
yutha-ops revoke 019e3ce9-8d7d-70ec-9209-e34415ca9477 \
    --reason "scope-creep on PII access"
```

What happens, in order: `yutha-ops` mints an
`OperatorBearerToken`, signs it with the operator key derived
from the seed, and attaches it as `authorization: bearer
operator <hex>`. The control plane verifies against the
configured `--operator-public-key`, then the registry removes
the target's passport from the active set and emits an
`agent.operator_revoke` receipt carrying the reason, operator
id, and target. The control plane adds the target to its in-
process revoked-set so future bearer-auth checks reject with
`UNAUTHENTICATED: agent revoked` regardless of remaining token
validity. Any active `EnvelopeService.Subscribe` stream the
target had open is torn down — the server-side forwarder
watches a per-agent `Notify`; the revoke handler fires
`notify_waiters()` and the forwarder exits within tens of
milliseconds. The gRPC stream closes from the client's
perspective; reconnection attempts fail because the passport
is gone (RFC 0009 §3.3).

Capabilities the target previously issued remain technically
extant on the cap layer's side, but every check against them
denies — the issuer's passport is no longer resolvable. That's
usually what you want for a non-compromise eviction.

### Cascade

For compromise scenarios — leaked private key, hostile takeover,
runaway agent with a tree of downstream delegations — pass
`--cascade`:

```bash
yutha-ops revoke 019e3ce9-... \
    --reason "key compromised" --cascade
```

The cascade enumerates every capability the target currently
holds (`list_for_subject`), revokes each one, and lands a
`capability.revoke` receipt per cap. The response's
`cascade_receipts` field carries the content-addresses of every
receipt the cascade produced, so an auditor can reconstruct the
exact set of revoked caps from the receipt log alone (RFC 0009
§3.2). The cascade is bounded and idempotent —
`list_for_subject` filters out already-revoked caps, so
re-running on the same agent is safe.

If the cascade fails mid-flight, the agent eviction itself has
already landed (`agent.operator_revoke` is emitted before the
cascade walk). Re-running `OperatorRevoke --cascade` against
the same target picks up the remaining caps.

### Irreversibility

Revoke is forward-only under v1. An evicted agent rejoins by
registering a fresh passport with a new agent id, countersigned
by the operator if the swarm is closed-admission. The audit
trail of the prior eviction is permanent; there's no `Unrevoke`
or `Restore` RPC (RFC 0009 §5).

---

## What's deferred

Be explicit about what v1 doesn't ship. RFC 0009 §9 is the
authoritative open-questions list; the short version:

- **Multi-operator keys.** One trusted public key per swarm
  under v1. Multi-key trust bundles (any-of-n) for handover and
  redundancy are a future RFC; until then, hand-off requires a
  coordinated restart with the new key.
- **Threshold (m-of-n) signing.** A stronger property — no
  single key compromise can revoke an agent — but it pulls in
  real verification complexity. Deferred indefinitely unless a
  concrete workflow needs it.
- **Per-operator rate limits.** A compromised operator key
  could mass-revoke every agent before anyone notices. The
  mitigation today is operator-key confidentiality (KMS, HSM,
  sealed secrets); rate-limiting belongs at the constitution
  layer and will land there.
- **Runtime key rotation.** Stop-and-restart is the only path
  to a new operator key under v1. Acceptable while operator
  activity is low-frequency; a future RFC will add the in-band
  protocol.
- **KMS-backed custody for the operator key.** The control
  plane's signing identity can now live in Vault / GCP KMS /
  Azure Managed HSM via `--signer {vault,gcp-kms,azure-kv}`
  (Phase G; see [Enterprise identity](enterprise-identity.md)),
  but `yutha-ops` still derives the operator key in-process
  from the seed and signs every operator-bearer token with an
  in-memory `InProcessSigner`. Extending `yutha-ops` with the
  same `--signer` flag set is a natural follow-on tracked
  alongside this work — until then, protect the seed as the
  load-bearing secret on the operator-tool side.

When you hit a gap that hurts, file it against RFC 0009.

---

## Where to go from here

- **[Operator quickstart](quickstart.md)** — the end-to-end
  walkthrough, including the revoke flow in Step 6.
- **[Monitoring & receipts](monitoring.md)** — how to observe
  operator-attributed receipts (`agent.operator_revoke`,
  `constitution.activate`, cascaded `capability.revoke`) in
  the audit log.
- **[RFC 0009](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0009-operator-credentials.md)**
  — the authoritative spec for the operator credential, the
  `OperatorBearerToken` wire format, the active-stream tear-
  down contract, and the open questions driving Phase-3 work.
