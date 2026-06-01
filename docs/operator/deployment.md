# Deployment

The [quickstart](quickstart.md) gets you a control plane running on
loopback with an in-memory receipt store — perfect for the first
afternoon, not safe to put anything real behind. This page is the
production-grade version: how to pick a backend, where the seed
lives, how to terminate TLS, what scales and what doesn't, and
which knobs are missing in v1 so you don't spend an evening
looking for them.

If you've never started the binary at all, do the quickstart first
and come back. Everything below assumes you're comfortable with the
five flags it introduced.

---

## Single-tenant defaults

Yutha v1 runs **one control-plane process per swarm**. The binary
holds the registry, capability store, receipt store handle,
constitution evaluator, and enforcement engine in a single address
space; agents speak gRPC into it; receipts fan out from it. One
swarm per process, one process per swarm. Multi-tenant control
planes (multiple swarms on one binary) are a future RFC.

A single instance comfortably handles low thousands of registered
agents pushing hundreds of envelopes per second on a modest box (4
vCPU, 8 GB RAM). The gRPC server itself is rarely the bottleneck —
Cedar evaluation is in-process, the enforcement engine is keyed on
sliding-window counters, and the receipt-store decorator just
hands every append to the inner store and an mpsc channel. When
you do feel pressure, it's almost always at the **receipt store** —
specifically, at Postgres write amplification for receipt-heavy
workloads. Plan capacity there first.

---

## Choose a receipt backend

The receipt store is the persistence boundary. Everything else in
the control plane is either in-memory state derived from the
receipt tail or a wrapper around the store. Backend choice is the
single most consequential deployment decision.

**`--receipt-backend memory`** — the default. In-process,
`HashMap`-backed, fast, lost on restart. Use it for local dev,
integration tests, demos, and the quickstart. Never production.
There is no migration path from a memory-store process to a
Postgres-store process.

**`--receipt-backend postgres --postgres-url postgres://…`** — the
production backend. Same `ReceiptStore` trait as the memory
backend; every gRPC handler is unchanged. Schema migrations run
automatically at startup — no manual `psql` step. The connection
pool defaults to 8 connections; bump in source if you're running
unusually fanned-out.

**What lives in Postgres.** Every receipt: the canonical bytes
(for re-verification and bulk export), the parsed columns the
query API indexes against, signature rows, evidence rows, and
seal-status rows. The application database role should be granted
`INSERT` only — append-only enforcement at the trait surface is
belt; the role grant is suspenders.

**What does NOT live in Postgres today.** Yutha v1 ships without a
separate blob-storage backend. Envelope payloads ride inline in
the receipt row alongside metadata. For typical control-plane
workloads — refund decisions, capability checks, policy
evaluations — payloads are bytes-to-low-kilobytes and this is
fine. If your workload routinely produces MB-scale payloads,
reference them out of band by URI in the envelope and keep the
payload itself small. A dedicated blob-storage backend is on the
roadmap but not in v1.

---

## Postgres setup

A minimal production startup, with the database provisioned:

```bash
createdb -h db.internal -U postgres yutha
export YUTHA_POSTGRES_URL=postgres://yutha_user:…@db.internal/yutha

./yutha \
  --grpc-addr 0.0.0.0:50051 \
  --admission-mode closed \
  --receipt-backend postgres \
  --postgres-url "$YUTHA_POSTGRES_URL" \
  --operator-public-key "$YUTHA_OPERATOR_PUBLIC_KEY" \
  --tls-cert /etc/yutha/tls.crt \
  --tls-key /etc/yutha/tls.key
```

**Postgres version.** Anything ≥ 14 works. The schema uses
`BYTEA`, `BIGINT`, `JSONB`, and standard btree indexes.

**What the migration does.** First startup against an empty
database creates the `receipts` table (parsed columns + canonical
bytes), the related rows for predecessors, signatures, evidence,
cost, and seal-status, and the indexes the query API needs.
Subsequent startups run pending migrations idempotently — ordinary
timestamped SQL files under `backends/postgres-receipt/migrations/`.

**Backup strategy.** Standard Postgres point-in-time recovery. The
receipt log is append-only, so restoring to a snapshot gives you
coherent swarm state with no companion log to reconcile. Practice
a restore before you need to do it under pressure.

---

## TLS for gRPC

The control plane listens plaintext by default — fine on loopback,
not fine for anything reachable across hosts. Pair the cert and
key flags:

```bash
./yutha \
  --tls-cert /etc/yutha/tls.crt \
  --tls-key /etc/yutha/tls.key \
  [other flags]
```

Both PEM-encoded. Setting one without the other is a startup
error — the binary refuses to come up. The same applies to the
env-var form (`YUTHA_TLS_CERT` / `YUTHA_TLS_KEY`). Certificates
rotate with a restart; hot reload isn't supported in v1.

---

## mTLS layered on bearer auth

`--client-ca /etc/yutha/client-ca.crt` adds a client-certificate
requirement on top of the bearer-token auth that every handler
already runs. Two independent layers: the TLS handshake fails if
the client doesn't present a cert chained to the configured CA,
and every authenticated handler still verifies the
`authorization: bearer <hex>` metadata against the registered
passport's public key.

Useful when the control plane sits behind a service mesh that
already enforces workload identity and you want belt-and-suspenders
on the gRPC port itself. Optional; omit `--client-ca` to rely on
bearer auth alone.

---

## Operator credential placement

The 32-byte bootstrap seed derives the bootstrap agent's Ed25519
signing key (raw seed bytes), the swarm id
(`sha256(seed || 0x02)`), and the operator signing key
(`sha256(seed || 0x03)`). The
[operator credentials](operator-credentials.md) page covers the
full lifecycle.

In production, the seed lives in your secrets manager — Vault, AWS
Secrets Manager, GCP Secret Manager, 1Password CLI — injected into
the process environment at startup. Never commit it to git; never
bake it into a container image. Three placement notes specific to
Yutha:

- **The seed never has to be on disk for the control plane to
  run.** Only `--operator-public-key` matters server-side — the
  control plane verifies operator-bearer tokens against the public
  key and never sees the private material. The seed itself lives
  wherever `yutha-ops` runs.
- **Pass via env var, not `--bootstrap-seed` on the command
  line.** The flag shows up in `ps aux`; `YUTHA_BOOTSTRAP_SEED`
  doesn't. In production you typically don't pass the seed to the
  server at all — the server generates a random bootstrap identity
  in-process; only the operator public key needs configuring.
- **Rotation requires a restart.** Phase 1 doesn't support
  runtime operator-key rotation. Stop, swap the public key,
  restart.

---

## Admission mode in production

`--admission-mode` defaults to `closed`. For production swarms
with a vetted agent population, stay closed: only the bootstrap
agent is allowlisted on startup; every other agent comes through
`AdmissionService.Register` with the operator's blessing.

`--admission-mode open` is appropriate for public or
community-grade swarms where agents self-register, but only
combined with a restrictive constitution and an enforcement chain
that catches abuse early. Open mode imposes no sybil resistance
beyond a well-formed passport with a future `expires_at`; the
constitution carries the actual policy weight. The
[topology concept page](../concepts/topology.md) walks the
trade-offs.

Hybrid (a closed core surrounded by an open periphery) is a
documented topology in the spec but isn't surfaced on the CLI in
v1. If you want hybrid posture today, run closed and curate the
allowlist by hand.

---

## Workload extensions

`--workload support-queue,code-review,…` (or
`YUTHA_WORKLOADS=support-queue,code-review`) loads workload-schema
extensions alongside the canonical v1.1 schema. Each loaded
extension adds an action-kind namespace the constitution can
reference — `Yutha::SupportQueue::Action::IssueRefund` only
validates if `support-queue` is loaded.

Forgetting to load a workload the active constitution depends on
makes activation fail with `INVALID_ARGUMENT: Cedar validation
failed: unknown action`. That's the point — better to fail at
activation than to silently degrade enforcement at evaluation
time. Treat the workload list as part of your deployment
configuration, not a runtime tunable.

---

## Scaling posture today

Be explicit about what scales and what doesn't.

**Vertical scale only.** One control-plane process per swarm. The
process is stateless beyond the receipt store — restart it and the
in-memory state (registry cache, capability cache, enforcement
counters) re-derives from the receipt tail.

**One active subscriber per inbox.** Each agent's gRPC `Subscribe`
stream is a server-side resource. The second subscription from the
same agent supersedes the first via server-side eviction
(`subscribe_supersede`); the old forwarder shuts down, the new one
takes over. This is intentional — gRPC-aio teardown lag on the
client side makes overlap-tolerant designs prone to ghost
subscribers. If you need fan-out, run one client per logical
consumer, each with its own agent identity.

**Horizontal scale is a future RFC.** Running multiple replicas
behind a load balancer needs coordination on receipt ordering,
subscription routing, and operator-revoke fan-out. None of that
is in v1. The supported scaling answer today is "bigger box,
faster Postgres."

---

## Backup and disaster recovery

Three things to back up:

- **The Postgres receipt store.** Point-in-time recovery via your
  standard tooling. The log is append-only — restoring to a
  snapshot reproduces coherent state with no companion replay.
- **The bootstrap seed.** Lives in your secrets manager. Without
  it you cannot re-derive the operator key — meaning no new
  operator-bearer tokens, no new activations, no revocations.
  Prior history still verifies against the operator's public key;
  you just can't take new operator actions.
- **The sealer key (if Sui anchoring is on).** Backed up
  independently. Without it, you can sign new commits with a fresh
  key but can't prove provenance of previously-sealed batches
  against the on-chain anchor — `ed25519_verify` against the
  original sealer public key no longer matches. See
  [Sui anchoring](sui-anchoring.md) for the sealer-key lifecycle.

**Restoring.** Bring up Postgres from the snapshot, point a fresh
process at it, restart. Subscribers reconnect on their own retry
logic. The enforcement engine re-derives its counters from the
receipt tail. If anchoring is on, the driver reads the on-chain
`SwarmAnchor` state once at startup to recover its watermark, then
resumes the cadence loop.

---

## Verifiable-backend deployment

The default deployment (Postgres + signed receipts +
content-addressed log) is already a strong first-party audit
trail — every consequential action is a receipt, every receipt is
content-addressed, every signature verifies against a registered
passport. For most use cases, this is enough.

When a third party needs to verify the audit trail without
trusting you, opt into Sui anchoring: the receipt log is sealed
into Merkle commitments and anchored on-chain, and any party with
access to the Sui RPC can independently verify that the receipts
you show them are the receipts you committed at the time. The
[Sui anchoring](sui-anchoring.md) page walks the operator
playbook end to end.

---

## Enterprise identity (KMS custody + workload attestation)

The defaults above hold the control plane's signing key in process
memory and accept any well-formed passport at `Register` time.
Enterprises with compliance requirements typically want two things on
top: the bootstrap signing key in a KMS / HSM the operator doesn't
extract from, and every registration verified against an external
workload-identity system before the agent joins the swarm.

Both are opt-in via single CLI flags: `--signer
{vault,gcp-kms,azure-kv}` for custody, `--attestor {spiffe,oidc}` for
attestation. Start with the
[Signer backends](signers.md) and [Attestor backends](attestors.md)
overview pages to decide which backends fit your environment — each
overview links onward to the per-backend runbook for provisioning
and operational specifics. When both seams matter to your deployment,
the [enterprise identity end-to-end](enterprise-identity.md)
walkthrough shows the integrated setup — usually Vault + SPIRE for
on-prem / Kubernetes, or a cloud-KMS + cloud-OIDC pair for the
matching cloud.

---

## What's NOT yet supported

Short list so you don't waste an evening looking:

- **Horizontal scale-out of the control plane.** Vertical scale
  only. Workaround: provision the box generously and watch
  Postgres.
- **Multi-tenant control planes.** One swarm per process.
  Workaround: one process per swarm; orchestrate at the
  container layer.
- **Blob-storage backends for large payloads.** Payloads ride
  inline in the receipt row. Workaround: reference large blobs
  by URI in the envelope.
- **Runtime operator-key rotation.** Restart required. Workaround:
  schedule rotation during a maintenance window; see
  [operator credentials](operator-credentials.md).
- **Read-replica routing for receipt queries.** All reads hit
  the primary. Workaround: provision the primary for combined
  read+write load.
- **Hot TLS-cert reload.** Cert rotation requires restart.
  Workaround: a sidecar that restarts the process on cert change.

Each one is a known gap with a tracked follow-on, not an
oversight.

---

## Where to go from here

- [Operator credentials](operator-credentials.md) — the full
  credential lifecycle.
- [Monitoring & receipts](monitoring.md) — what to watch in
  production and which receipts matter for alerting.
- [Sui anchoring](sui-anchoring.md) — opt-in third-party
  verifiability via on-chain Merkle commitments.
- [Authoring constitutions](authoring-constitutions.md) — how to
  write the Cedar+ policy the deployed control plane will
  evaluate.
- [Concepts: Topology](../concepts/topology.md) — the design
  rationale behind closed / open / hybrid.
