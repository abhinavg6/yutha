# ADR 0001: Language Choice for Core Control Plane

> **Repo location:** `/docs/internal/0001-language-choice.md`
> **Status:** Proposed
> **Date:** TBD (proposed during PRD v0.4 review)
> **Deciders:** Workstream B (Control Plane), Workstream L (Security), foundation governance once established
> **Supersedes:** N/A

## Context

Concord must select implementation languages for its core components. The choice has long-term consequences for security, performance, contributor pool, and ecosystem fit. Because Concord is the trust boundary for every multi-agent system that uses it, language-level safety properties matter more than they would in a typical project.

Components requiring language decisions:

| Component | Trust level | Performance sensitivity |
|-----------|-------------|-------------------------|
| Control plane (membership, transport, identity) | High | High |
| Constitution evaluator | High | Medium |
| Receipt store core | High | High |
| Memory layer core | High | Medium |
| Backend adapters (Postgres, Redis, vector stores) | Medium | Medium |
| SDK adapters (per agent runtime) | Low (runs in agent's environment) | Low |
| Observability fabric | Medium | Medium |
| Visual composer | Low | Low |
| Documentation tooling | Low | Low |

Trust-boundary components are the primary subject of this decision. Peripheral components follow a more permissive policy.

## Decision

**Use Rust for the core control plane and all security-critical paths.** Specifically: control plane, constitution evaluator, receipt store core, memory layer core, capability evaluation, identity verification, cryptographic operations.

**Use the agent runtime's native language for SDK adapters:** Python and TypeScript at launch, with adapters in additional languages following the same pattern. SDK adapters do not hold privileged state and are explicitly outside the memory-safety guarantees of the core.

**Use Rust or Go for backend adapters, observability components, and tooling**, with Rust preferred for components that touch security-critical paths and Go acceptable for components that are operationally simpler. Visual composer uses TypeScript (web-native).

## Alternatives considered

### Rust (selected)

**Pros:**

- Memory safety without garbage collection. Eliminates the buffer-overflow / use-after-free / double-free vulnerability classes by construction.
- Strong type system catches significant bug classes at compile time.
- No data races in safe code (Send / Sync discipline).
- Mature async ecosystem (tokio, hyper, tonic for gRPC).
- Mature cryptography libraries (ring, rustls, age) audited and widely deployed.
- Mature serialization (prost for protobuf, serde for general).
- Strong package management (cargo); reproducible builds practical.
- Wasm compilation target supports sandboxing the constitution evaluator if needed.
- Predictable performance — no GC pauses, no JIT warmup.

**Cons:**

- Steep learning curve. Smaller contributor pool than Go or TypeScript.
- Compile times are long, especially for large workspaces.
- Borrow checker requires upfront design discipline; iteration speed is lower in early development.
- Async Rust has known complexity (lifetimes, `Send` bounds, pinning).
- Some specialty libraries less mature than in older ecosystems.

### Go (rejected as core; acceptable for observability and some adapters)

**Pros:**

- Easier learning curve, larger contributor pool.
- Mature concurrency model (goroutines, channels) suits some patterns.
- Fast compilation.
- Strong standard library, mature gRPC support.
- Simple deployment (single binary).

**Cons:**

- Garbage collected. GC pauses, even short ones, are unacceptable in latency-sensitive transport paths and constitution evaluation.
- Memory safety guarantees weaker than Rust (race detection is runtime-only).
- Type system lacks sum types, pattern matching, expressive generics (until recently).
- Error handling is verbose and error-prone.
- Less expressive type system means more bugs reach runtime.

**Why rejected for core:** GC and weaker type system are dealbreakers for trust-boundary code. We accept Go for observability and certain adapters where the operational simplicity is worth the tradeoff.

### TypeScript / Node.js (rejected as core)

**Pros:**

- Largest ecosystem of AI builders. Lowest contribution barrier.
- Same language as the visual composer and many SDK adapters.
- Mature async ecosystem.

**Cons:**

- Not memory-safe in the deep sense (V8 is C++).
- Garbage collected, single-threaded by default, performance concerns at scale.
- Dynamic typing (even with TS layered on JS) means runtime type errors are common.
- Supply-chain history (event-stream, colors.js, left-pad) is a cautionary tale.

**Why rejected:** unsuitable for trust-boundary code. Acceptable for SDK adapters where the runtime is the agent's own and Concord-the-platform is not relying on it for security guarantees.

### Java / Kotlin (rejected)

**Pros:**

- Mature, stable, excellent tooling.
- Memory-safe with managed runtime.
- Strong type system, especially Kotlin.

**Cons:**

- JVM warmup, GC pauses, heavier deployment.
- Larger memory footprint per process.
- Cultural fit for OSS infrastructure projects has weakened.

**Why rejected:** not a clear advantage over Rust for the core, and a clear disadvantage on deployment weight and GC characteristics.

### C++ (rejected)

**Pros:**

- Maximum performance.
- Mature, ubiquitous.

**Cons:**

- Memory safety is the developer's responsibility. Heartbleed-class vulnerabilities are a recurring pattern in C++ code at this trust level.
- Modern C++ is safer than older C++, but the failure mode is severe.
- Large contributor pool, but skill distribution is bimodal; safe C++ requires expertise.

**Why rejected:** memory safety is the headline reason we need a careful language choice. C++ does not provide it without heroic developer discipline.

### Zig (rejected, reconsider later)

**Pros:**

- Fast, low overhead.
- Manual memory management with safety improvements over C.
- Compile-time programming is powerful.

**Cons:**

- Pre-1.0; ABI and language not yet stable.
- Smaller ecosystem.
- Smaller contributor pool than Rust.

**Why rejected:** too young for a project that needs to be a long-term standard. Reconsider in 5+ years if the language matures.

## Consequences

### Positive

- Entire classes of memory-safety bugs are impossible by construction in core code (the largest single category of security vulnerabilities historically).
- Type-level guarantees catch significant classes of logic bugs at compile time.
- Performance characteristics are predictable; no GC tail latency in the transport hot path.
- Cryptographic operations use audited Rust libraries (ring) widely vetted.
- Wasm compilation target opens future options for sandboxing user-provided policy code.
- Strong package management and reproducible builds support the supply-chain commitments in PRD Section 18.

### Negative

- Smaller contributor pool for the core. **Mitigation:** invest in onboarding documentation, mentorship, clear contribution paths. Make the security-critical code unusually well-documented to lower the entry barrier.
- Slower iteration in early development. **Mitigation:** scope Phase 1 carefully; the substrate is stable in concept and benefits from upfront design rigor.
- Compile times. **Mitigation:** workspace organization, incremental compilation, mold linker, sccache.
- Async Rust complexity. **Mitigation:** project conventions for async patterns documented early; dedicated review attention on async code.

### Neutral

- Hiring for Concord core requires Rust experience, but the broader project is multi-language and offers paths in for non-Rust contributors.
- The decision aligns Concord with other modern infrastructure projects (Solana, TiKV, Linkerd2 data plane, much of the CNCF Rust ecosystem) which both signals seriousness and reduces cultural friction.

## Open questions

These are confirmed before Phase 1 freezes:

- **Async runtime.** tokio is the obvious choice. Confirm explicitly.
- **Web framework for control plane HTTP surfaces** (admin endpoints, dashboards): axum vs. actix-web. Defer.
- **Database driver pattern.** sqlx vs. diesel vs. sea-orm. Defer.
- **FFI strategy for Python and TypeScript SDKs.** PyO3 / napi-rs vs. wire-protocol-only. Wire-protocol-only is the strong default; FFI is a special-case escape hatch where performance demands it.
- **MSRV (minimum supported Rust version) policy.** Default proposal: latest stable minus three releases.

## How this decision evolves

If a future major language change becomes necessary (a Rust-stagnation scenario, a successor language reaching maturity), it will be proposed via the same RFC process as any other foundational change. Migration would be incremental, component by component, with security review at every step. The decision log preserves history; the most recent superseding ADR is canonical.
