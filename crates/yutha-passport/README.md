# yutha-passport

Agent identity for Yutha. Mirrors [`/spec/passport/passport-v1.proto`](../../spec/passport/passport-v1.proto).

## What's here

- **`Passport`**: signed identity manifest. Construct via `PassportBuilder`; the agent's private key self-signs at issuance. Implements `Canonical` so it can be content-addressed by `yutha-crypto`.
- **`PassportTier`**: MINIMAL / STANDARD / VERIFIABLE — mirrors conformance tiers.
- **`CapabilityDeclaration`** / **`ResourceDeclaration`**: what the agent claims it can do (declaration ≠ authority; see capability spec).
- **`PassportStore`** trait: register / lookup / revoke / rotate operations.
- **`MemoryPassportStore`**: in-memory reference implementation. Thread-safe; not durable.
- **`PassportResolverAdapter`**: bridges the passport store into `yutha_receipt::PassportResolver` so the receipt store can verify signatures against registered passports.

## What's NOT here

- Admission policy (closed / open / hybrid) — that lives in `yutha-registry`, which consumes this crate.
- SPIFFE / OIDC IdP adapters — Phase 1 ships UUID v7 IDs (per ADR-pending decision); IdP attestation is the registry's domain.
- Cross-org passport federation — Phase 4.

## Threat-model linkage

A1 (hostile agent attribution), A3 (prompt injection — capability declaration ≠ authority), A6 (sybil — re-registration cost), A8 (malicious operator — passport is self-signed). Per CODEOWNERS, every change requires Workstream L review.

## Reference

- [`/spec/passport/`](../../spec/passport/)
- [`/spec/passport/rationale.md`](../../spec/passport/rationale.md)
- [RFC 0002](../../spec/rfcs/0002-passport-v1.md)
