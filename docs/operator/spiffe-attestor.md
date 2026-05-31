# Verifying agents against SPIFFE/SPIRE

A 30-minute walkthrough for the operator who wants to bind Yutha
agent registrations to an existing
[SPIRE](https://spiffe.io/docs/latest/spire-about/) workload-identity
deployment. By the end you'll have:

- The control plane configured with `--attestor spiffe`, pointed at
  either a SPIRE Workload API socket (hot bundle rotation) or a
  static JWKS trust bundle file (air-gapped / edge).
- Every successful agent registration recording the calling
  workload's SPIFFE ID + its SPIRE-projected selectors as receipt
  evidence — auditors can chain Yutha `agent_id`s back to SPIRE-
  attested workloads.
- A clear deny path: any registration without a valid JWT-SVID
  (or with the wrong audience, signature, or trust domain) hits
  `PERMISSION_DENIED` at the gRPC layer plus an `agent.register.deny`
  receipt with operator-actionable evidence.

**What you get for free.** RFC 0016's `Attestor` trait is consulted
on every registration regardless of which flavour the operator
selected. Swapping `--attestor native` for `--attestor spiffe`
changes the verification step; everything downstream of registration
(bearer-token auth, capability checks, constitution evaluation,
receipt anchoring) is unchanged.

**What you write.** The SPIRE workload-attestation policy
(registration entries + selectors), the audience string the SPIRE
workloads will mint SVIDs for, and the Yutha CLI flags that pin
those choices.

If you haven't operated a Yutha swarm before, read the
[operator quickstart](quickstart.md) first — it covers the bootstrap
seed model and the gRPC server flags this doc assumes you're
comfortable with.

This walkthrough implements the SPIFFE Attestor pinned by
[RFC 0016 §3.5](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0016-attestor-interface.md#35-reference-impl-sketch--spiffespire-phase-e)
and detailed in
[`/spec/identity-keys/attestor-spiffe.md`](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-spiffe.md).

---

## Prerequisites

- A running SPIRE deployment (1.10+). Either:
  - A production SPIRE server + agent per the
    [SPIRE quickstart](https://spiffe.io/docs/latest/try/getting-started-linux-macos-x/),
    OR
  - The minimal one-off local setup at
    [`crates/yutha-attestor-spiffe/tests/SPIRE_LOCAL_TESTING.md`](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-attestor-spiffe/tests/SPIRE_LOCAL_TESTING.md)
    for evaluation.
- A Yutha control-plane binary built with `--features` defaults
  (`yutha-attestor-spiffe` is wired in unconditionally; no compile-
  time gate).
- About 5–20 ms of additional admission latency budget per `Register`
  RPC for the SPIFFE verify path. Offline JWS verification is
  CPU-bound; the SDK caches the trust bundle so no network call hits
  the hot path in steady state.
- Workload-attestation policy decided up front: SPIRE issues SVIDs
  based on selectors (Unix uid, k8s namespace, etc.); the registration
  entry you write decides which workloads can claim which SPIFFE IDs.
  See [SPIRE's selector docs](https://spiffe.io/docs/latest/deploying/registering/)
  if you're unfamiliar.

You do **not** need any cloud account, KMS provisioning, or hardware
TPM. SPIRE itself is self-hosted.

---

## 1. Decide: Workload API socket, or static bundle file?

The SPIFFE Attestor reads its trust bundle from exactly one of two
sources. Pick before you start configuring.

| | Workload API socket | Static bundle file |
|---|---|---|
| **CLI flag** | `--attestor-spiffe-socket /path/to/agent.sock` | `--attestor-spiffe-bundle-file /path/to/bundle.json` |
| **Hot rotation** | Yes — SDK streams updates from `spire-agent` | No — operator rotates by replacing file + restarting |
| **SPIRE agent required at runtime** | Yes (on the control-plane node or sidecar) | No |
| **Federation** | Yes — SPIRE federates multiple trust domains via the agent | No — file contains one trust domain |
| **Best fit** | Production K8s, VM fleets, any prod with SPIRE agents already deployed | Air-gapped, edge, dev, anywhere you can't or don't want a SPIRE agent sidecar |

**If in doubt: pick the Workload API socket.** It's the SPIFFE-native
posture and gets hot rotation for free. The static file is the escape
hatch for environments where SPIRE-agent presence is infeasible.

---

## 2. Pick an audience value

The audience is the SVID's `aud` claim that the Attestor enforces.
SPIRE workloads request SVIDs targeting a specific audience; only
SVIDs whose `aud` claim contains your configured value are accepted.
Without audience binding, an SVID minted for some unrelated
SPIRE-protected service could be replayed against your Yutha swarm
(same trust domain, same valid SVID, wrong intent).

**Recommended shape:** `yutha-<swarm-name>-<env>` — e.g.,
`yutha-orders-prod`, `yutha-billing-staging`. Specifically:

- **Don't use generic values** like `yutha-prod`. If you run multiple
  Yutha swarms or any other yutha-shaped consumer on the same trust
  domain, SVIDs cross-replay.
- **Don't use raw hostnames.** Tying audience to a hostname couples
  the policy to deployment topology; the same swarm behind a load
  balancer needs an audience the workload can request without
  knowing every front-end's hostname.
- **Do include region** if you run multi-region:
  `yutha-orders-prod-us-east`.

This value goes into both:

1. Your SPIRE workload code: `fetch_jwt_svid(audiences=["yutha-orders-prod"])`
2. Yutha's `--attestor-spiffe-audience yutha-orders-prod` flag.

See
[`attestor-spiffe.md` §6.1](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-spiffe.md#61-choosing-an-audience-value)
for the security rationale.

---

## 3. Create a SPIRE registration entry

Whichever source flavour you picked, SPIRE needs a registration
entry that lets your workload class mint SVIDs for the audience
above. For a Kubernetes pod:

```bash
kubectl exec -n spire spire-server-0 -- \
  spire-server entry create \
    -spiffeID spiffe://example.org/yutha-agent/orders \
    -parentID spiffe://example.org/k8s/cluster/orders-prod \
    -selector k8s:ns:orders \
    -selector k8s:sa:yutha-agent \
    -jwtSVIDTTL 300
```

For a bare-metal / VM workload:

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/yutha-agent/orders \
  -parentID spiffe://example.org/agent/host-orders-01 \
  -selector unix:user:yutha \
  -jwtSVIDTTL 300
```

The selectors decide which processes can claim this SPIFFE ID;
SPIRE's workload-attestation step matches them against the calling
workload at SVID-mint time. See
[SPIRE's selector docs](https://spiffe.io/docs/latest/deploying/registering/)
for the full taxonomy.

`-jwtSVIDTTL 300` keeps SVIDs to 5 minutes — short enough that a
leaked SVID's replay window is bounded; long enough that the
workload doesn't churn `fetch_jwt_svid` calls. SPIRE's default if
you omit the flag is your server.conf's `default_jwt_svid_ttl`.

---

## 4. Configure the control plane

### Workload-API source (production)

```bash
yutha-control-plane \
  --attestor spiffe \
  --attestor-spiffe-socket /run/spire/sockets/agent.sock \
  --attestor-spiffe-audience yutha-orders-prod
```

Equivalent env-var form for `systemd` / docker-compose / k8s
ConfigMaps:

```bash
export YUTHA_ATTESTOR=spiffe
export YUTHA_ATTESTOR_SPIFFE_SOCKET=/run/spire/sockets/agent.sock
export YUTHA_ATTESTOR_SPIFFE_AUDIENCE=yutha-orders-prod
```

Construction is a single in-process call. At startup the Attestor:

1. Connects to the Workload API socket (bounded by
   `--attestor-spiffe-connect-timeout-secs`, default 10 s).
2. Awaits the initial trust-bundle sync.
3. Spawns the SDK's background reconnect/refresh loop.

A misconfigured `--attestor-spiffe-socket` (path doesn't exist,
SPIRE agent down) makes the control plane exit at startup rather
than at the first registration. Look for `Error: SPIFFE Attestor
construction failed: trust bundle unavailable (workload-api): ...`
in the log.

### Static-file source (air-gapped / edge)

```bash
yutha-control-plane \
  --attestor spiffe \
  --attestor-spiffe-bundle-file /etc/yutha/spiffe-bundle.json \
  --attestor-spiffe-audience yutha-orders-prod
```

The bundle file format is a SPIFFE Trust Bundle — `trust_domain` +
`keys` JWKS array. To dump it from your SPIRE server for offline
distribution:

```bash
spire-server bundle show -format spiffe \
  -socketPath /tmp/spire-server/private/api.sock \
  > /etc/yutha/spiffe-bundle.json
```

Then ship the file to your air-gapped target.

Operators rotate by replacing the file + restarting the control
plane. The Attestor reads the file ONCE at construction; mid-process
changes are not detected.

### Mutually exclusive

Setting both `--attestor-spiffe-socket` AND
`--attestor-spiffe-bundle-file` is a startup-time fatal — there's no
"both" mode, since the SDK's federation semantics differ between the
two paths. The control plane exits with a clear message naming both
flags.

---

## 5. Tune freshness + skew (optional)

Three more flags govern the trust-bundle freshness contract +
clock-skew tolerance. Spec defaults are reasonable for production;
adjust only if you have a specific need.

```bash
yutha-control-plane \
  --attestor spiffe \
  --attestor-spiffe-socket /run/spire/sockets/agent.sock \
  --attestor-spiffe-audience yutha-orders-prod \
  --attestor-spiffe-max-staleness-secs 3600 \
  --attestor-spiffe-clock-skew-secs 60 \
  --attestor-spiffe-connect-timeout-secs 10
```

| Flag | Default | When to change |
|---|---|---|
| `--attestor-spiffe-max-staleness-secs` | Workload API: `2 × spiffe_refresh_hint` of the most-recent bundle (≥ 60 s, ≤ 24 h). Static file: no check. | Set finite for static-file paths if you want a hard "refresh every N hours" cron pattern. Set to `0` for strictest "fail the moment the bundle's TTL expires". |
| `--attestor-spiffe-clock-skew-secs` | 60 | Lower if your fleet's wall clocks are tightly synced (NTP'd, < 1 s drift) and you want stricter `iat`/`nbf` enforcement. Raise if you observe legitimate registrations rejected for clock-skew reasons. |
| `--attestor-spiffe-connect-timeout-secs` | 10 | Raise if the SPIRE agent's cold-start latency is genuinely > 10 s on your platform. |

See
[`attestor-spiffe.md` §5](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-spiffe.md#5-bounded-staleness-policy)
for the bounded-staleness rationale.

---

## 6. Wire the client side

Yutha agents present the JWT-SVID as the `external_credential`
parameter on the `Register` RPC. The Python SDK's
`AdmissionAPI.register()` and each adapter's
`YuthaAgent.register()` take an `external_credential: bytes`
argument (default `b""`, which is what the native Attestor expects).

Typical client code (Python, against a `spiffe.JwtSource`):

```python
import spiffe
from yutha import YuthaClient

# Fetch a fresh SVID from the local SPIRE agent socket.
async with spiffe.JwtSource.builder() \
        .endpoint("unix:/run/spire/sockets/agent.sock") \
        .build() as source:

    svid = await source.get_jwt_svid(["yutha-orders-prod"])
    token_bytes = svid.token().encode("ascii")

    # Register the agent with the SVID as the external credential.
    async with YuthaClient.connect(
        server_addr,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signer=signer,
    ) as client:
        await client.admission.register(
            passport,
            external_credential=token_bytes,
        )
```

The Yutha SDK doesn't bind to a specific SPIFFE library; pass any
bytes-shaped JWT-SVID. If you use the
[`pyspiffe`](https://pypi.org/project/pyspiffe/) or
[`go-spiffe`](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2) APIs
instead, the substrate doesn't care — only `aud` / `exp` / signature
against the trust bundle matters.

---

## 7. Verify the wire-up

Register a test agent and look at the receipt log. Successful
attestation produces an `agent.register` receipt with new evidence
keys:

```bash
yutha-ops query receipts \
  --kind agent.register \
  --limit 1 \
  --json | jq '.[0].evidence'
```

```json
{
  "agent_id":              "0xd2879019…",
  "attested_external_identity": "spiffe://example.org/yutha-agent/orders",
  "attestor_id":           "spiffe",
  "attributes.k8s_ns":     "orders",
  "attributes.k8s_sa":     "yutha-agent",
  "swarm_id":              "0xcbde36a0…",
  "..."
}
```

The `attested_external_identity` + `attestor_id` keys are the
load-bearing audit signal — every Yutha `agent_id` is now chained
to a SPIRE-issued SPIFFE ID. If your audit pipeline filters on
`attestor_id = "spiffe"`, you'll see exactly the registrations that
went through the SPIFFE verify path.

For rejected registrations, look at `agent.register.deny`:

```bash
yutha-ops query receipts \
  --kind agent.register.deny \
  --limit 5 \
  --json | jq '.[].evidence'
```

Each carries `claimed_agent_id`, `attestor_id`, and a `deny_reason`
that maps 1:1 to a spec §9 row (`audience mismatch`,
`credential expired`, `signature verification failed`,
`trust domain not in bundle`, `kid not found in trust bundle`, etc.).
Per the spec's PII rule, no `deny_reason` contains credential bytes
or claim contents — operators investigate via SPIRE-side logs, not
the deny receipt's `deny_reason` field.

---

## 8. Failure modes + monitoring

| Symptom | Likely cause | Where to look |
|---|---|---|
| Server exits at startup with `trust bundle unavailable (workload-api)` | SPIRE agent socket path wrong or agent not running | Verify `ls /run/spire/sockets/agent.sock`; check `spire-agent` logs |
| All registrations reject with `audience mismatch` | Audience value mismatch between client `fetch_jwt_svid` and server `--attestor-spiffe-audience` | Compare both sides; remember audience is case-sensitive |
| Bursts of registrations reject with `trust bundle stale` | SPIRE agent lost connectivity to server past your staleness window | Check SPIRE agent ↔ server health; consider raising `--attestor-spiffe-max-staleness-secs` if outage was legitimate |
| Sporadic registrations reject with `nbf in the future` | Client wall clock running ahead of server | NTP both sides; if persistent, raise `--attestor-spiffe-clock-skew-secs` |
| Registrations reject with `signature verification failed` | Trust bundle on server doesn't include the SVID's signing key | Confirm both server + client see the same SPIRE trust bundle; if you're on the static-file path, regenerate + restart |

For ongoing monitoring, watch the rate of `agent.register.deny`
receipts. A baseline of zero on a healthy fleet is normal; sustained
non-zero suggests either a misconfigured client or active probing.

---

## 9. Security posture

- **The substrate never sees SPIRE private keys.** Yutha only ever
  reads the SPIRE *trust bundle* (public JWKS). The SPIRE-side
  signing keys stay inside SPIRE.
- **SVIDs are short-lived.** With `-jwtSVIDTTL 300` (recommended),
  a leaked SVID is replayable for at most 5 minutes. The Yutha
  passport the registration produces is independent — once the
  agent is registered, its authority depends on its own bearer
  tokens, not the SVID's continued validity. (Re-attestation on a
  per-RPC basis is deferred to the future lifecycle layer; see
  [RFC 0016 §5.3](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0016-attestor-interface.md#53-make-every-operation-re-verify-the-external-credential).)
- **The threat model strengthens against A1 (hostile agent
  participant) and A6 (Sybil attacker).** See
  [`attestor-spiffe.md` §12](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-spiffe.md#12-threat-model-impact)
  for the per-adversary analysis.
- **Operators are still trusted.** A malicious operator can swap
  `--attestor spiffe` for `--attestor native` mid-operation; the
  defence is audit-side, not preventive — `attestor_id` in receipt
  evidence flips, and a post-hoc audit catches the change. See
  RFC 0009 if you want operator-side eviction guarantees on top.

---

## See also

- [`/spec/identity-keys/attestor-spiffe.md`](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-spiffe.md) —
  byte-exact verification contract this Attestor implements.
- [`crates/yutha-attestor-spiffe/tests/SPIRE_LOCAL_TESTING.md`](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-attestor-spiffe/tests/SPIRE_LOCAL_TESTING.md) —
  three-terminal local SPIRE setup for the integration test.
- [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) —
  upstream framing.
- [SPIRE production deployment](https://spiffe.io/docs/latest/deploying/) —
  SPIRE-side setup beyond this walkthrough's scope.
- [RFC 0016 — Attestor interface](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0016-attestor-interface.md) —
  the umbrella RFC.
- [Operator: Monitoring & receipts](monitoring.md) —
  how to surface `agent.register` + `agent.register.deny` receipts
  in your existing audit pipeline.
