# Developer quickstart

A fifteen-minute, framework-neutral walkthrough. By the end you'll have two agents talking through a Yutha control plane: one minting a capability and sending an envelope, the other receiving it through a subscription, and a content-addressed receipt log on the server that proves who did what.

This page uses *only* the core `yutha` Python SDK. No LangGraph, CrewAI, OpenAI Agents, or MAF. The framework adapters layer on top of exactly this surface — once the bare flow makes sense, the [framework walkthroughs](#where-to-go-next) won't surprise you.

!!! info "Already comfortable with the basics?"

    Jump to the [LangGraph walkthrough](langgraph.md), the [CrewAI walkthrough](crewai.md), the [OpenAI Agents walkthrough](openai-agents.md), or the [Microsoft Agent Framework walkthrough](maf.md) — each adapter guide pairs with a runnable end-to-end example.

## What you'll build

```text
        sender agent                 control plane                 receiver agent
        ────────────                 ─────────────                 ──────────────
            │                              │                              │
            │  passport, register          │                              │
            ├─────────────────────────────►│                              │
            │                              │◄─── passport, register ──────┤
            │                              │                              │
            │  capability.issue            │                              │
            ├─────────────────────────────►│                              │
            │                              │                              │
            │                              │◄─── envelope.subscribe ──────┤
            │                              │                              │
            │  envelope.send + cap_id      │                              │
            ├─────────────────────────────►│                              │
            │                              │── deliver ──────────────────►│
            │                              │                              │
```

Every arrow in that diagram lands a receipt in the append-only log. You'll inspect that log at the end.

## Prerequisites

Three things on hand:

**1. The Python SDK in a virtualenv.**

```bash
python -m venv .venv && source .venv/bin/activate
pip install yutha
```

Python 3.11+. The core install pulls in `grpcio`, `protobuf`, `cryptography`, and `pydantic`. No framework deps.

**2. A control plane to talk to.** The reference control plane is a Rust binary in this repo. Clone and build once:

```bash
git clone https://github.com/abhinavg6/yutha
cd yutha
cargo build --release -p yutha-control-plane
```

The full operator playbook lives in [Operator → Quickstart](../operator/quickstart.md); for this developer walkthrough we'll launch in the simplest possible mode (open admission, no constitution, no anchoring).

**3. A 32-byte bootstrap seed.** The seed binds the demo agents and the control plane to the same `swarm_id` without needing a discovery RPC. Mint one:

```bash
export YUTHA_BOOTSTRAP_SEED=$(python -c 'import secrets; print(secrets.token_hex(32))')
```

## Step 1 — bring up the control plane

In one terminal, with the seed exported:

```bash
./target/release/yutha --admission-mode open
```

Open mode lets fresh agents self-register without an operator allowlist. That's the right setting for tutorials and integration tests; production swarms use closed or hybrid.

You should see:

```text
yutha-control-plane listening on 127.0.0.1:50051
admission mode: open
swarm_id: <16-byte hex>
```

Leave it running. Everything below happens in a second terminal.

## Step 2 — derive agent identities from the seed

In a Python file (`quickstart.py`), wire up the same swarm-id derivation the server is using:

```python
import asyncio
import hashlib
import os
import secrets

import yutha

SERVER_ADDR = "127.0.0.1:50051"
FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)


def swarm_id_from_seed(seed_hex: str) -> yutha.SwarmId:
    """sha256(seed || 0x02)[:16] — matches the server's derivation."""
    seed = bytes.fromhex(seed_hex)
    return yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])


SWARM_ID = swarm_id_from_seed(os.environ["YUTHA_BOOTSTRAP_SEED"])
```

The `swarm_id` is how the control plane decides which agents are "in" the same swarm. Cross-swarm passports are rejected at registration.

## Step 3 — mint two passports

A **passport** is the agent's verifiable identity — an Ed25519 public key plus operator/owner metadata, signed by the agent's matching private key.

```python
async def mint_identity(name: str) -> tuple[yutha.InProcessSigner, yutha.AgentId, yutha.Passport]:
    signer = yutha.InProcessSigner.generate()
    agent_id = yutha.AgentId(value=secrets.token_bytes(16))
    passport = await yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=SWARM_ID,
        agent_public_key=signer.public_key(),
        owner=f"quickstart/{name}",
        framework="bare",                        # no framework adapter here
        framework_version="0.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signer)
    return signer, agent_id, passport


# Minted inside `main()` below — `.sign(...)` is async.
```

Three things to notice:

- **Identity is local.** No registry call yet; you generated a keypair, declared an `agent_id`, and signed the passport — the operator never minted these for you. The control plane will accept the passport only if its signature verifies under the embedded public key. That's the trust root.
- **The framework string is informational.** `"bare"` here; framework adapters set `"langgraph"`, `"crewai"`, etc. Constitutions can policy-key on this field, but the substrate doesn't.
- **`expires_at` is mandatory under open mode.** The control plane rejects passports without a wall-clock expiry — that's how revocation has an outer bound even if the operator never explicitly evicts.

## Step 4 — connect, register, mint a capability, send

This is the body of the demo. Comments inline:

```python
async def main() -> None:
    sender_signer, sender_id, sender_pp = await mint_identity("sender")
    receiver_signer, receiver_id, receiver_pp = await mint_identity("receiver")

    # ---- Sender side: connect, register, issue a self-capability ------
    async with yutha.YuthaClient.connect(
        SERVER_ADDR,
        agent_id=sender_id,
        swarm_id=SWARM_ID,
        signer=sender_signer,
    ) as sender:
        # Registering returns a `register` receipt; we ignore it here.
        await sender.admission.register(sender_pp)

        # The sender mints a capability to itself authorising
        # `envelope.send`. In a real deployment, an operator or a
        # supervisor agent typically issues caps to subordinates;
        # for the bare quickstart, self-issuance is enough to show
        # the wire shape.
        cap = yutha.Capability(
            spec_version="1.0.0",
            capability_id=secrets.token_bytes(16),
            swarm_id=SWARM_ID,
            issuer=yutha.Issuer.for_agent(sender_id),
            subject=sender_id,
            scope=yutha.Scope.for_action("envelope.send"),
            valid_from=yutha.Timestamp.now(),
            valid_until=FAR_FUTURE,
        )
        cap_id, _ = await sender.capability.issue(cap)
        print(f"sender minted cap {cap_id.digest.hex()[:16]}…")

        # ---- Receiver side: register + subscribe in the background ----
        async with yutha.YuthaClient.connect(
            SERVER_ADDR,
            agent_id=receiver_id,
            swarm_id=SWARM_ID,
            signer=receiver_signer,
        ) as receiver:
            await receiver.admission.register(receiver_pp)

            # Drain at most one envelope from the inbox.
            async def receive_one() -> None:
                async for envelope, deliver_receipt in await receiver.envelope.subscribe():
                    print(
                        f"receiver got envelope from {envelope.sender.hex()[:16]}… "
                        f"payload={envelope.payload!r} "
                        f"deliver_receipt={deliver_receipt.digest.hex()[:16]}…"
                    )
                    break

            inbox_task = asyncio.create_task(receive_one())
            await asyncio.sleep(0.1)  # let the subscribe land server-side

            # ---- Now send a single envelope, cap-gated --------------
            envelope = await yutha.Envelope(
                spec_version="1.0.0",
                envelope_id=secrets.token_bytes(16),
                swarm_id=SWARM_ID,
                sender=sender_id,
                recipient=yutha.Recipient.for_agent(receiver_id),
                performative=yutha.Performative.INFORM,
                payload=b"hello from sender",
                payload_schema_id="type.yutha.dev/v1/Text",
                tags=["quickstart"],
                sent_at=yutha.Timestamp.now(),
            ).sign(sender_signer)

            send_receipt = await sender.envelope.send(envelope, capability_id=cap_id)
            print(f"sender envelope.send receipt={send_receipt.digest.hex()[:16]}…")

            await inbox_task


asyncio.run(main())
```

Run it (server still up in terminal 1):

```bash
python quickstart.py
```

You should see something like:

```text
sender minted cap a3f1e2c8b04d6f9a…
sender envelope.send receipt=2b8d4c1e6f037b9c…
receiver got envelope from <sender>… payload=b'hello from sender' deliver_receipt=…
```

## Step 5 — inspect the audit trail

A consequential action just landed in the receipt log on the server: `agent.register × 2`, `capability.issue × 1`, `envelope.send × 1`, `envelope.deliver × 1`, `capability.check.pass × 1`. Query for them:

```python
async with yutha.YuthaClient.connect(
    SERVER_ADDR,
    agent_id=sender_id,           # any registered identity works
    swarm_id=SWARM_ID,
    signer=sender_signer,
) as client:
    receipts = await client.receipt.query_by_action_kind("envelope.send", limit=10)
    for r in receipts:
        print(r.action_kind, r.subject_agent_id.hex()[:16], r.digest.hex()[:16])
```

Each receipt is content-addressed: the `digest` is `BLAKE3` over the canonical-bytes encoding of the receipt body. Two replays of the same demo produce different receipts (different envelope ids, different timestamps), but the encoding is bytewise-deterministic — so the same input always produces the same digest. That's how third parties verify the log later.

## What just happened

Five substrate primitives showed up in fifteen minutes of code:

- **Passport** — both agents minted one and registered it. The control plane only accepts envelopes from agents whose passports it has on file.
- **Capability** — the sender issued an `envelope.send` cap to itself. The control plane refused to forward the envelope until the cap was presented and the scope matched.
- **Envelope** — the typed message itself. Signed by the sender, addressed to a specific recipient, tagged for downstream filtering.
- **Receipt** — every consequential action emitted one. The log is append-only and content-addressed; nothing in the protocol forgets.
- **Subscription** — the receiver's inbox is a server-pushed stream, one subscriber per inbox.

The Yutha control plane never owned the agents' reasoning loop, never picked a model, never opened an outbound HTTP call. The substrate's job is identity, authorization, transport, and audit — *what* the agents say to each other and *why* is on you.

## Where to go next

You've seen the bare wire shape. The framework walkthroughs replace the hand-rolled `send_one` / `receive_one` with idiomatic agent abstractions, while keeping the same substrate underneath:

- **[LangGraph](langgraph.md)** — wrap a LangGraph node as a Yutha agent. Deterministic state-graph handler with no LLM dependency at the dispatch level. Paired example: [customer support](../examples/customer-support.md).
- **[CrewAI](crewai.md)** — each `Agent` in a Crew becomes a Yutha agent with its own identity. LLM-driven dispatch via `Crew.kickoff()`. Paired example: [AP/invoice processing](../examples/ap-invoice.md).
- **[OpenAI Agents](openai-agents.md)** — each `agents.Agent` becomes a Yutha agent. Handoff bridging via `RunHooks` so every inter-agent transition produces a signed audit envelope; cap-gating via `@capability_required` on `function_tool` bodies. Paired example: [research crew with citation enforcement](../examples/research-crew.md).
- **[Microsoft Agent Framework](maf.md)** — each `agent_framework.Agent` becomes a Yutha agent. Cap-gating on async-native tool callables (no sync/async bridge); honest v1 scope vs `WorkflowBuilder` / `RequestInfoExecutor` follow-ons. Paired example: [DevOps incident-response](../examples/devops-incident.md).
- **[Writing a new adapter](writing-adapters.md)** — bring your own framework. The contract is small: mint a passport, register, thread `ACTIVE_CAPABILITY_ID` through your tool surface, send envelopes.

Once you want a constitution governing the swarm — declarative norms with four-stage enforcement — read the [Concepts → Constitution & enforcement](../concepts/constitution.md) page, then the [Operator quickstart](../operator/quickstart.md) for how an operator authors and activates one.
