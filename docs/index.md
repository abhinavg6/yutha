---
title: Yutha — a control plane for agent swarms
description: Yutha is a framework-agnostic control plane that gives multi-agent systems identity, capability, accountability, and norms. Works with LangChain, LangGraph, CrewAI, and anything else.
hide:
  - navigation
  - toc
---

# Agents are easy to build. Swarms are not.

You can stand up a single agent in an afternoon. Wiring five of them together, in a way that you'd trust on a customer interaction or a production workflow, is a different problem entirely — and almost every team rebuilds the same scaffolding from scratch: who an agent is, what it's allowed to do, what it actually did, and which norms govern the swarm it lives in. Each framework solves a fragment and stops.

**Yutha is that scaffolding, built once, framework-agnostic.** It runs in front of agents you've already built — in LangChain, LangGraph, CrewAI, or anything else — and gives them passports, signed receipts, attenuated capabilities, declarative constitutions with four-stage enforcement, and an optional cryptographic verification layer for when a third party needs to audit what happened.

<div class="grid cards" markdown>

-   :material-clock-fast:{ .lg .middle } **Run an agent through it in 15 minutes**

    ---

    Bring an existing LangGraph or CrewAI agent. Wrap it. Join an existing swarm. Get a passport, a capability, and a signed audit trail.

    [:octicons-arrow-right-24: Developer quickstart](developer/quickstart.md)

-   :material-server:{ .lg .middle } **Stand up your own swarm in 30 minutes**

    ---

    A control plane, a constitution, and a topology of your choosing — closed, open, or hybrid — on infrastructure you own.

    [:octicons-arrow-right-24: Operator quickstart](operator/quickstart.md)

</div>

## The problem Yutha solves

A multi-agent system makes a lot of small decisions every minute. Each one is *consequential* in the way that database writes are consequential — it touches a customer, spends a budget, ends a session, escalates to a human. When something goes wrong:

- **You can't tell which agent did it.** Identity is implicit or per-framework.
- **You can't prove what was authorized.** Capability checks live in code, not as artifacts.
- **You can't reconstruct what happened.** Logs are best-effort, mutable, often missing the why.
- **You can't enforce norms uniformly.** Each framework's "guardrails" are written differently and trust each other transitively.
- **You can't prove any of the above to a third party.** Internal logs don't survive an audit.

These are not framework problems. They're substrate problems. They show up no matter which framework you build the agents in, and trying to solve them inside the framework leaks them across systems the moment you compose two different frameworks together. Yutha is the layer underneath the frameworks, so the substrate looks the same regardless of how the agents above were built.

## What Yutha gives you

**Identity that's portable.** Every agent carries an Ed25519-backed *passport*: a verifiable identity that doesn't depend on which framework or runtime built the agent. Passports are issued by an operator, revocable, and traceable.

**Typed messaging with audit.** Agents talk through *envelopes* — structured messages with a sender, a recipient (or role, or swarm-wide broadcast), a typed action, and a payload. Every consequential send produces an append-only *receipt*: signed, content-addressed, deterministic. Receipts are the source of truth.

**Capabilities, not permissions.** Authority is granted as bounded, attenuable *capabilities* — first-class tokens that say *who* may do *what* for *how long* on *which targets*. Capabilities can be narrowed (never widened) when delegated, revoked atomically, and cascaded across delegation chains. Cap checks happen at the control plane, not in each agent's code.

**Constitutions, declaratively.** Norms governing a swarm are written in Cedar+, a declarative policy language extended with soft scoring rules and procedural state machines. The control plane evaluates every consequential action against the active constitution. Violations progress through a four-stage enforcement loop — flag, restrict, quarantine, evict — never as a single all-or-nothing decision.

**Optional cryptographic verification.** When the operator needs to prove the audit trail to a third party — a regulator, a customer, a downstream system — Yutha can anchor Merkle roots of receipt batches to a public blockchain (Sui today). Anyone can independently verify the seal without trusting the operator.

**Pluggable backends.** Receipt storage in Postgres or in-memory for development, blob storage on S3 or Walrus, anchoring on Sui — same APIs, swap the implementation behind the spec.

## Who it's for

<div class="grid cards" markdown>

-   :material-shield-account:{ .lg .middle } **Operators**

    ---

    Stand up the control plane, set the topology (closed / open / hybrid), author and activate constitutions, manage operator credentials, monitor receipts, anchor for verifiability. You own the swarm.

    [:octicons-arrow-right-24: Operator guide](operator/index.md)

-   :material-code-braces:{ .lg .middle } **Developers**

    ---

    Build agents in the framework you already like — LangChain, LangGraph, CrewAI — and bring them to a Yutha-governed swarm. Adapters handle the passport, the cap-checking, the receipt emission.

    [:octicons-arrow-right-24: Developer guide](developer/index.md)

</div>

## What Yutha is *not*

Yutha is intentionally not a lot of things. Drawing the boundary explicitly is part of how it stays focused.

**Not a platform for building or hosting agents.** You build the agents in your framework of choice. Yutha never owns the agent's reasoning loop, prompt, or model. It governs how agents interact, not what they think.

**Not a model service.** No model hosting, no inference layer, no opinion on which LLM you use. Bring your own.

**Not a chat product or assistant.** Yutha is infrastructure. Humans interact with the swarm through whatever UI the operator builds on top.

**Not a token, payment, or settlement layer.** There is no Yutha token. There is no on-chain settlement of agent actions. The optional verifiability backend uses a blockchain only as an immutable timestamp + Merkle commitment store.

**Not a single-vendor cloud.** Default deployment is self-hosted on infrastructure you already use (Postgres, object storage, your cloud of choice). Verifiable backends are opt-in.

**Not framework-opinionated.** LangChain and LangGraph adapters ship in v1. CrewAI ships in v1. Anyone can write an adapter for a new framework against the spec; no permission required.

**Not a reputation engine.** Yutha tracks a reputation scalar per agent, but it is never the sole basis for a permission decision. Reputation informs; capabilities and the constitution decide.

## Where the project is

Yutha is open-source, Apache 2.0, stewarded by a single maintainer right now. The reference implementation runs end-to-end across the Rust control plane and Python SDK; the LangChain/LangGraph and CrewAI adapters are functional; the conformance suite covers the receipt log, send-path enforcement, operator revocation, constitution evaluation, the four-stage enforcement loop, and the verifiability anchor.

What's intentionally not in scope yet: pre-production simulation (Phase 3 of the build plan), cross-swarm federation (Phase 4). The build plan and the RFC archive on [GitHub](https://github.com/abhinavg6/yutha) document the trajectory.

## Read next

- [Concepts → Primitives](concepts/primitives.md) — passports, envelopes, receipts, capabilities, in fifteen minutes.
- [Operator → Quickstart](operator/quickstart.md) — stand up a swarm of your own.
- [Developer → Quickstart](developer/quickstart.md) — join one with an existing agent.
- [Examples → Customer support with refund cap](examples/customer-support.md) — a worked end-to-end use case.
