# yutha-diff

Structural + behavioural diff for Yutha constitutions.

Phase 3d / Pillar 1 (simulation + observability) of the Yutha workstream. Given two `yutha_cedar_plus::Constitution` artifacts, this crate produces a `ConstitutionDiff` value that names every section-level change between them: Cedar policies added / removed / modified, named-predicate / scoring-rule / procedure / enforcement-rule deltas, and schema-version pin changes.

The crate also defines the data model for the **behavioural** diff (`BehaviouralDiff` — receipt counts + enforcement chain divergences over a replay window), but populating that struct requires running a replay session and is the call site's responsibility (see `yutha-ops diff --against-window`).

Three output formats are shipped:

| Format | Use |
|--------|-----|
| JSON | Machine consumption — CI gates, audit pipelines, OpenTelemetry attributes. |
| Markdown | PR review threads, human-readable diffs. |
| HTML | Standalone document for stakeholder review. |

The crate is **pure compute** — no async, no I/O, no Postgres, no gRPC. Drops cleanly into any tool that has two `Constitution` values in hand.

## Cedar policy matching

Per the 3d-A scope-lock, Cedar policies match across left/right by `@id` annotation when present; un-annotated policies match by a structural fingerprint (`effect:scope_shape:body_hash`) so reorderings of un-annotated policies don't false-positive as add/remove pairs. Renderers surface a soft "consider annotating with @id" hint when un-annotated policies are encountered.

## What this crate is NOT

- Not a Cedar policy linter. Both sides must parse + load successfully through `ConstitutionLoader`.
- Not a behavioural-diff engine. `BehaviouralDiff` is data only; populating it lives at the call site.
- Not a stable output format. JSON consumers should pin the `yutha-diff` version they parse against; the shape is internal tooling.

## Stability

Pre-1.0 alpha. The data model + JSON schema marker `yutha-diff/v1` are subject to change before first public release.
