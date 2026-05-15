# RFC 0008: Wall-clock bound checks

> **Status:** Draft
> **Authors:** Workstream E (substrate hardening)
> **Filed:** 2026-05-13
> **Targets spec:** `/spec/common.proto` v1.0 → v1.1 (semantics clarification),
>                   `/spec/capability/` v1.0 → v1.1,
>                   `/spec/passport/` v1.0 → v1.1,
>                   `/spec/envelope/` v1.0 → v1.1
> **Targets phase:** Phase 1 (substrate hardening)
> **Discussion:** TBD

## 1. Summary

Switch every **cross-process time-bound check** from
`Timestamp.monotonic_ns` to `Timestamp.wall_clock` (parsed as RFC
3339). `monotonic_ns` becomes informational-only on the wire; it
remains load-bearing for intra-process ordering (e.g. causal
predecessors, receipt sequence). Concretely, four call sites change:

- `Capability::is_within_window` (cap validity window)
- `Passport::is_expired_at` (passport expiry)
- `Envelope::is_expired_at` (envelope TTL)
- `AgentBearerToken` expiry in `require_bearer_auth` (bearer token
  expiry)

No wire-format changes. No new fields. The change is purely in the
**semantics** of how implementations evaluate `Timestamp.valid_*`,
`Timestamp.expires_at`, and equivalent cross-process bounds.

## 2. Motivation

`Timestamp` carries both `wall_clock` (RFC 3339 string) and
`monotonic_ns` (process-local nanoseconds since boot/start). The
v1.0 spec says "spec-mandated comparison logic uses `monotonic_ns`,"
which is correct for *intra-process* ordering: monotonic clocks
guarantee strictly-increasing values regardless of NTP adjustments,
so causal event sequencing inside a single process is safe.

But the same comparison breaks **across processes**: each process's
monotonic clock has its own origin (typically boot time or process
start), so a Python SDK that mints a capability with
`valid_from = Timestamp.now()` produces a `monotonic_ns` that's not
meaningfully comparable to a Rust server's later
`Timestamp::now().monotonic_ns`. The capability either reads as
"future" or "ancient past" depending on the relative clock readings
— which is the bug Stage D-4 hit during the LangGraph S1 demo and
worked around with the `EPOCH_ZERO` anchor (memory entry
`cross_process_monotonic.md`).

The same wart bites every other cross-process bound check.
`auth.rs::require_bearer_auth` already acknowledges this in a
comment:

> for remote deployments the SDK and CP necessarily share the
> wall_clock timeline which is what mints set expires_at against in
> practice.

The fix is to make that informal "share the wall_clock timeline"
the *normative* rule for cross-process bounds.

## 3. Detailed design

### 3.1 New rule

For any time-bound check that compares a `Timestamp` produced in
process A against a `Timestamp` produced in process B (the common
case: client mints, server enforces), the check uses
`wall_clock` parsed as RFC 3339. `monotonic_ns` is informational
context; comparing it across processes is undefined behavior.

For intra-process ordering — i.e. comparing two `Timestamp` values
both produced in the same process — `monotonic_ns` remains
authoritative (`Timestamp::precedes` and its callers don't change).

### 3.2 Affected check sites

Four functions change. All four have the same shape — replace a
numeric comparison of `monotonic_ns` with an RFC 3339 parse of
`wall_clock`, compared as `OffsetDateTime`:

```rust
// Before (Capability::is_within_window):
pub fn is_within_window(&self, now: &Timestamp) -> bool {
    now.monotonic_ns >= self.valid_from.monotonic_ns
        && now.monotonic_ns <= self.valid_until.monotonic_ns
}

// After:
pub fn is_within_window(&self, now: &Timestamp) -> bool {
    let parse = |t: &Timestamp| OffsetDateTime::parse(&t.wall_clock, &Rfc3339);
    match (parse(now), parse(&self.valid_from), parse(&self.valid_until)) {
        (Ok(now), Ok(from), Ok(until)) => now >= from && now <= until,
        _ => false,  // malformed bound → deny
    }
}
```

Symmetric changes for `Passport::is_expired_at`,
`Envelope::is_expired_at`, and the bearer-token expiry check.

### 3.3 Malformed bounds

A `Timestamp` whose `wall_clock` doesn't parse as RFC 3339 produces
a **deny** for every cross-process bound check. This is consistent
with the spec's default-deny posture: empty fields and ambiguous
matches refuse rather than permit.

The `Timestamp::new` constructor already validates RFC 3339 at
construction time, so this branch should only fire for hand-crafted
proto messages bypassing the constructor — a hostile input case the
server should reject.

### 3.4 Clock-skew tolerance

This RFC does **not** add clock-skew tolerance to either bound. Two
reasons:

1. **Demo workflows don't need it.** The use cases we're closing —
   capability windows, passport/envelope expiry — all involve human
   timescales (seconds-to-days) where the typical NTP-synced clock
   skew of <100ms is irrelevant.
2. **Operator concern, not substrate concern.** A future RFC can add
   `Topology.max_clock_skew_seconds` if a workload actually needs
   it. Adding it preemptively risks the substrate masking real
   clock bugs.

Operators worried about clock skew today can mint bounds with a
safety margin (e.g. `valid_from = now - 30s`); the substrate
honors them.

### 3.5 The `Timestamp` doc comment

`yutha-core/src/time.rs` and `/spec/common.proto`'s `Timestamp`
comment block update to reflect the split:

- `wall_clock` — authoritative for cross-process time-bound checks
  (validity windows, expiry). MUST be valid RFC 3339.
- `monotonic_ns` — authoritative for intra-process ordering (causal
  predecessors, receipt sequence). Cross-process comparison is
  undefined.

`Timestamp::precedes` keeps its monotonic_ns semantics; it's
documented as an intra-process helper.

## 4. Drawbacks

- **No structured drift detection.** With monotonic_ns no longer
  load-bearing for bounds, a buggy SDK that emits skewed
  `wall_clock` values won't be caught by the substrate. The cap or
  passport will either accept or deny based on the bad clock, and
  the audit trail will reflect what the server saw. Mitigation:
  the bearer-token + signature chain means an operator investigating
  an audit anomaly can correlate against their own clock; the wall-
  clock issuance time on the receipt is informational ground truth.
- **RFC 3339 parsing cost on every check.** Negligible in practice
  (microseconds per cap check) but worth a note. The `time` crate
  is already in `yutha-core`'s deps; no new dependency.
- **Implementations must handle malformed wall_clock gracefully.**
  Default-deny is unambiguous but a defensive coding requirement.

## 5. Alternatives considered

- **Keep monotonic_ns, share a process-anchored epoch out-of-band.**
  Workarounds like the `EPOCH_ZERO` constant in the LangGraph demo
  do this implicitly (anchor at 0; every clock's "now" is later).
  Works for the trivial case but doesn't help with real bounded
  windows. Rejected — escapes the problem rather than solving it.
- **Use Unix epoch nanoseconds.** Would let us keep a numeric type
  and avoid string parsing. But Unix epoch values need careful
  serialization (timezone-free) and lose the human-readable benefit
  RFC 3339 already gives us. Rejected — the existing wall_clock
  string is already the canonical representation.
- **Add `Topology.max_clock_skew_seconds` in this RFC.** Rejected
  for now per §3.4. Decoupling concerns.
- **Switch ALL Timestamp comparisons, including `precedes`.** Would
  make causal-event ordering also use wall_clock. Rejected:
  intra-process monotonic is strictly correct for that use case and
  unaffected by the cross-process clock issue. Don't fix what isn't
  broken.

## 6. Threat-model impact

- **No new attack surface.** RFC 3339 parsing of operator/client-
  supplied strings is the same parsing already done in
  `Timestamp::new`; we're just extending where the result is used.
- **A1 (bounded blast radius):** Strengthened slightly. Cap and
  passport expiry now reflect real time, so a stolen-cap window of
  damage genuinely bounds at the documented duration instead of
  potentially permitting/denying based on clock drift.
- **A8 (auditability):** Unchanged. Receipts continue to record
  both `wall_clock` and `monotonic_ns` on every action.
- **Adversary supplies a bad wall_clock.** Default-deny under
  malformed parse means the worst-case outcome is the substrate
  refusing to act, which is the safe direction.

## 7. Conformance impact

- **Capability conformance.** Existing `is_within_window` tests
  need a `wall_clock` field populated on test fixtures (they
  already do — `Timestamp::new` requires it). The unit tests in
  `yutha-capability/src/capability.rs` already construct
  timestamps with valid RFC 3339 strings; expected behavior is
  preserved.
- **Conformance vectors.** No regen required. The vectors test
  canonical serialization of message bytes; `Timestamp` fields are
  both serialized identically regardless of which one is
  load-bearing for window checks. The S2 conformance scenario
  (RFC 0007) gets a new assertion: cap window evaluated under
  wall-clock semantics still permits the demo path.
- **New negative tests:** at least one per affected site verifying
  that a malformed `wall_clock` results in deny.

## 8. Migration

The change is a **semantics-only** clarification on existing wire
fields. Old clients and old servers interoperate identically — both
parse `wall_clock` and `monotonic_ns`; the change is in which one
the bound checks consult.

**The only client-visible effect** is the retirement of the
cross-process workaround pattern (the `EPOCH_ZERO` anchor in the
LangGraph S1 demo): clients can now mint `valid_from =
Timestamp.now()` and have it work correctly against a remote
server's clock.

**SDK authors:** when minting tokens / caps / passports with a
future `expires_at` or `valid_until`, advance the `wall_clock`
field by the same interval as `monotonic_ns`. The pre-RFC SDK
practice of copying `now.wall_clock` verbatim and only incrementing
`monotonic_ns` produces a token whose wall-clock expires at mint
time — the server reads it as already-expired under wall-clock
semantics. The Python SDK's `_advance_wall_clock` helper
(`sdks/python/src/yutha/auth.py`) shows the pattern; other SDKs
should do the equivalent in their bearer-mint paths.

No deprecation window needed — the change strictly relaxes a
constraint that callers were already working around.

## 9. Open questions

- **Should this RFC also update the `Timestamp::precedes` doc** to
  call out explicitly that it's intra-process-only? Leaning yes —
  cheap clarification.
- **Hybrid: should the bearer-token expiry check (auth.rs) honor
  monotonic_ns for SDK/CP loopback** (where both run in the same
  process) **and wall_clock for remote?** Probably not — adds
  complexity for marginal benefit. Wall-clock universally is
  cleaner.

## 10. Adoption checklist

- [ ] Spec doc updates (capability §8 lifetime, passport §expiry,
      envelope §TTL, common.proto Timestamp comment)
- [ ] Rust impl: four `is_within_window` / `is_expired_at` /
      bearer-expiry call sites
- [ ] Rust tests: per-site happy-path + malformed-wall_clock deny
- [ ] Python SDK: retire `EPOCH_ZERO` constant in S1 demo + cap
      tests, restore `Timestamp.now()` on `valid_from`
- [ ] Retire `cross_process_monotonic.md` memory entry
- [ ] At least two reviewers approved

## 11. References

- [`/spec/common.proto`](../common.proto) — `Timestamp` definition.
- [`/spec/capability/`](../capability/) — `valid_from`,
  `valid_until` semantics.
- [`/spec/passport/`](../passport/) — `expires_at`.
- [`/spec/envelope/`](../envelope/) — `expires_at`.
- [`/spec/control-plane/v1.proto`](../control-plane/v1.proto) —
  `AgentBearerToken.expires_at`.
- Stage D-4 retrospective: the LangGraph S1 demo's discovery of the
  cross-process monotonic wart.
- RFC 0007 (Send-path capability enforcement) — exposed the bug at
  the gRPC layer where it became user-visible.
