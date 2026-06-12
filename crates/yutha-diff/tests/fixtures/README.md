# yutha-diff fixtures

Sample (Cedar source, engine-config YAML) pairs for smoke-testing
`yutha-ops diff` and for the integration test in
`../fixtures.rs`.

Each pair is a self-contained constitution that loads cleanly
through `yutha_cedar_plus::ConstitutionLoader`. The pairs are
designed to demonstrate the load-bearing diff shapes operators care
about: Cedar policy added/removed/modified, engine-config item
added/removed/modified, schema-version pin change.

## Fixtures

| File | What it represents |
|------|--------------------|
| `baseline.cedar` + `baseline.engine.yaml` | A minimal swarm constitution: one `@id("permit-routine-actions")` permit policy, no engine-config items beyond the schema-version pin. The "before" side of every smoke test. |
| `tightened.cedar` + `tightened.engine.yaml` | The baseline plus one new `@id("forbid-large-refunds")` Cedar forbid rule gating refunds above $500, plus a matching `large_refund_detector` enforcement rule (detect → coach → quarantine → evict at increasing cooldowns). The "after" side. |

## Expected diff (baseline → tightened)

```bash
yutha-ops diff \
    --left-cedar crates/yutha-diff/tests/fixtures/baseline.cedar \
    --left-engine-config crates/yutha-diff/tests/fixtures/baseline.engine.yaml \
    --right-cedar crates/yutha-diff/tests/fixtures/tightened.cedar \
    --right-engine-config crates/yutha-diff/tests/fixtures/tightened.engine.yaml \
    --left-version baseline \
    --right-version tightened \
    --format markdown
```

Surface deltas:

- **Schema version**: no change (`1.1.0` on both sides).
- **Cedar policies**: 1 added (`forbid-large-refunds`).
- **Named predicates / Scoring rules / Procedures**: no change.
- **Enforcement rules**: 1 added (`large_refund_detector`).

The reverse direction (tightened → baseline) surfaces the symmetric
removals.

## Regenerating the expected output

```bash
# Run the integration test that pins the diff shape.
cargo test -p yutha-diff --test fixtures

# Or render the diff freshly to compare against the spec above.
cargo run -p yutha-ops -- diff \
    --left-cedar  crates/yutha-diff/tests/fixtures/baseline.cedar \
    --left-engine-config  crates/yutha-diff/tests/fixtures/baseline.engine.yaml \
    --right-cedar crates/yutha-diff/tests/fixtures/tightened.cedar \
    --right-engine-config crates/yutha-diff/tests/fixtures/tightened.engine.yaml \
    --left-version baseline --right-version tightened \
    --format markdown
```
