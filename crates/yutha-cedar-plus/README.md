# yutha-cedar-plus

> Phase 2 constitution stack — stock Cedar gating + engine-side scoring, procedures, enforcement.

This crate is the reference implementation of the Yutha constitution layer specified in **RFCs 0010–0013**:

- [RFC 0010](../../spec/rfcs/0010-constitution-language-v1.md) — base Cedar+ schema and constitution artifact shape.
- [RFC 0011](../../spec/rfcs/0011-cedar-plus-extensions.md) — four v1.1 capabilities: `prefer` scoring and `procedure` state machines (engine-construct), resource budgets and memory norms (schema-pattern).
- [RFC 0012](../../spec/rfcs/0012-evaluation-model-and-sandbox.md) — two-layer evaluation contract, determinism guarantees, per-evaluation sandbox bounds.
- [RFC 0013](../../spec/rfcs/0013-four-stage-enforcement-loop.md) — detect → coach → quarantine → evict enforcement loop with reverse semantics, reputation dynamics, supervisor-tier countersign.

## Architecture

Constitution evaluation is two layers:

1. **Layer A** — stock [`cedar-policy`](https://crates.io/crates/cedar-policy). Gating decisions (permit/forbid) over the Cedar policy file. We delegate to upstream; we do **not** extend Cedar's language.
2. **Layer B** — the constitution engine (this crate). Runs after Layer A returns permit. Evaluates scoring rules, fires procedure transitions, drives the enforcement loop.

The engine reads from a separate **engine-config** artifact (YAML / protobuf) declaring scoring rules, procedures, and enforcement rules. Cedar source stays pure stock Cedar; engine configs reference Cedar predicates by name via the `@<name>` convention.

## Status

**Scaffold.** Public surface compiles, types are defined, sandbox bounds match RFC 0012 §3.3, engine-config YAML round-trips. The Layer A delegate, the engine eval logic, the procedure state-machine implementation, and the enforcement-engine receipt subscriber are all stubbed (`todo!()` or empty bodies) and land in subsequent F-code stages:

- **F6** — engine-config loader + validators (parse YAML/protobuf, run schema validation, refuse out-of-bound constitutions at load time).
- **F7** — Layer A evaluator wiring stock cedar-policy.
- **F8** — Layer B engine eval (scoring + procedure).
- **F9** — enforcement engine (receipt subscriber, pattern matcher, cap-layer + registry integration).

## Layout

| Module | Role |
|--------|------|
| `constitution` | The signed, versioned constitution artifact. |
| `engine_config` | Scoring rules, procedures, enforcement rules, named predicates. |
| `eval` | Request/response types + `ConstitutionEvaluator` trait. |
| `sandbox` | Per-evaluation resource bounds + bound-exceeded reasons. |
| `scoring` | Engine-side scoring evaluator (stub). |
| `procedure` | Engine-side state-machine evaluator (stub). |
| `enforcement` | Receipt-stream-driven enforcement engine (stub). |
| `error` | Crate `Result` and error type. |

## Dependency note

We depend on `cedar-policy` as a black box. As long as `Authorizer::is_authorized` returns the same decision for the same inputs (which the published Cedar semantics guarantee), Yutha is free to use whatever Cedar version is current. The pinned version in workspace `Cargo.toml` may be bumped without spec amendment so long as Yutha's surface (the evaluator's external contract) remains identical.
