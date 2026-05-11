# yutha-capability

Macaroon-style attenuable authority tokens. Mirrors [`/spec/capability/capability-v1.proto`](../../spec/capability/capability-v1.proto).

## What's here

- **`Capability`** struct with `Canonical` impl, content-addressable.
- **`Issuer`** (oneof: agent / operator / control-plane), **`Scope`**, six **`Caveat`** variants from the spec.
- **Attenuation**: `Scope::intersect` for narrowing; chain walk with bounded depth (default 8 per topology); refuses to broaden.
- **`CapabilityStore`** trait: issue / attenuate / revoke / check.
- **`MemoryCapabilityStore`**: in-memory reference impl.
- **Check evaluation**: walks the parent chain, intersects scopes, evaluates caveats, produces a check result that the receipt store can record.

## What's NOT here

- Receipts for issue/attenuate/check/revoke — those are produced by the registry or control plane consuming this crate plus `yutha-receipt`.
- Revocation propagation over a network — Phase 1 ships single-node; cross-node revocation propagation is part of transport/federation work.
- Persistent storage — `MemoryCapabilityStore` is reference; persistent backend ships when Phase 1 substrate matures.

## Threat-model linkage

A3 (prompt injection) is the primary defense — no ambient authority; every action requires explicit capability check. A1 (hostile agent — quotas via RateLimitCaveat), A6 (sybil — periphery scope ceilings), A8 (operator — every mint/revoke produces a receipt), A9 (compromised supervisor — SupervisorRequiredCaveat enforces two-person rule).

## Reference

- [`/spec/capability/`](../../spec/capability/)
- [`/spec/capability/rationale.md`](../../spec/capability/rationale.md)
- [RFC 0005](../../spec/rfcs/0005-capability-v1.md)
