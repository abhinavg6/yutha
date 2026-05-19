# Canonical schema extensions — v1.1.0

Workload-specific Cedar+ schema extensions that compose with the base
[`/spec/constitution/schema.cedarschema`](../../schema.cedarschema).
Operators activate one or more of these alongside the base schema when
their swarm's policies need domain-specific entities and actions
(refund approvals, code review, etc.).

## Extension model

Cedar 3.x schemas are namespaced. The base schema declares everything
under `namespace Yutha { ... }`. Each workload extension lives in its
own sibling namespace — `Yutha::SupportQueue`, `Yutha::CodeReview`,
etc. — and references the base namespace's entity types (`Yutha::Agent`,
`Yutha::Swarm`) by their fully-qualified names. The evaluator loads
the base schema and any opted-in extensions as a **single concatenated
Cedar source string**; Cedar 3.x's parser handles multiple namespaces
natively.

Concretely:

```rust
use yutha_cedar_plus::{
    canonical_schema_v1_1_with_extensions,
    WORKLOAD_SUPPORT_QUEUE_V1_1,
};

let schema = canonical_schema_v1_1_with_extensions(&[
    WORKLOAD_SUPPORT_QUEUE_V1_1,
])?;
```

Constitution policies authored against this schema can now reference
support-queue entities and actions:

```cedar
@id("refund-cap")
forbid (
    principal,
    action == Yutha::SupportQueue::Action::"IssueRefund",
    resource
) when {
    context.refund_amount_cents > 10000
};
```

## Constraints on extensions

Per [`/spec/constitution/rationale.md`](../../rationale.md) §4:

* Extensions **add**, never modify or remove. They MAY introduce new
  entity types, actions, or attribute fields; they MUST NOT redefine
  anything from the base schema.
* Each extension is content-addressed in its own right. A constitution
  references its extensions by name (the file stem) and pins the
  schema version (`1.1.0`). The evaluator resolves the name to the
  shipped extension source at load time.
* The combined effective schema (base + extensions) is what Cedar's
  Strict-mode validator runs against. A policy that names an action
  not in any of the loaded namespaces is rejected.

## Shipped workloads

| File | Namespace | Purpose |
|------|-----------|---------|
| [`support-queue.cedarschema`](./support-queue.cedarschema) | `Yutha::SupportQueue` | Customer-support ticket flow with `Ticket` entity + `IssueRefund` / `EscalateToSupervisor` actions. Companion to conformance scenario S1. |
| [`code-review.cedarschema`](./code-review.cedarschema) | `Yutha::CodeReview` | Code-review approval flow with `PullRequest` entity + `ApproveMerge` / `BlockMerge` actions. Demonstrates the pattern is reusable across domains. |

## Versioning

Extensions live under a version-namespaced directory (`v1.1.0/` here)
matching the base schema's pinned `schema_version`. A future v1.2.0
base bump would create `v1.2.0/` alongside, and operators migrate
each constitution as they bump its pinned version. Extensions
themselves don't carry independent semver — they're additive deltas
on top of the base schema's contract.
