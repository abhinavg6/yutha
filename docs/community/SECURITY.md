# Security Policy

Yutha is the trust boundary for every multi-agent system that uses it. Vulnerability reports are handled with that responsibility in mind.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Send reports to **security@yutha.dev** (or the equivalent contact in [MAINTAINERS.md](./MAINTAINERS.md) until the dedicated address is provisioned).

Optionally encrypt with the project's PGP key, available at:

- `https://yutha.dev/.well-known/pgp-key.txt` (forthcoming)
- Fingerprint: TBD until first key generation

What to include:

- A description of the vulnerability and its impact.
- Affected components (specify spec version and reference-implementation crate version where possible).
- Reproduction steps or proof of concept.
- Suggested mitigation if you have one (welcome but not required).
- Your name and contact details, or "anonymous" if you prefer.

## What we commit to

- **Acknowledgement within 72 hours.** A real human reads your report.
- **Initial assessment within 7 days.** We will tell you whether we consider it a vulnerability, the severity rating, and the rough remediation plan.
- **Coordinated disclosure.** We work with you on a disclosure timeline that gives users time to upgrade. Default window is 90 days from confirmation; we extend for unusually severe issues if patching requires it.
- **Credit.** If you want it, you get it (in the advisory and in the changelog). If you want anonymity, you get that.
- **No legal action against good-faith researchers.** Researchers who follow the policy in this document have nothing to fear from the project.

## Severity rating

We use a CVSS-flavored rough scale, calibrated to Yutha's threat model:

- **Critical.** Compromise of the trust boundary at the substrate layer (passport forgery, capability bypass, receipt tampering, signature forgery, sandbox escape from Cedar+ evaluator). Defaults to 7-day patch window.
- **High.** Defeat of one of the documented threat-model adversaries' mitigations (A1–A9). 30-day patch window.
- **Medium.** Information disclosure, DoS against a single component, defense-in-depth weakening that does not by itself enable substrate compromise. 60-day patch window.
- **Low.** Best-practice deviation, hardening opportunity, theoretical issue without practical impact. Patched in normal release cadence.

These windows are commitments to the reporter and to users. They do not cap the project's right to release a patch sooner.

## What is in scope

- Yutha specs (this directory and `/spec/`).
- The Yutha reference implementation (`/crates/`).
- The reference backends (`/backends/postgres-receipt/`, etc.).
- The reference SDKs (`/sdk/python/`, `/sdk/typescript/`).
- Conformance suite (`/conformance/`).

## What is out of scope

- Third-party backend implementations not maintained in this repo (report to those projects).
- Operator deployments (operator-side misconfiguration; the conformance suite tests for it).
- The user's underlying infrastructure (host, network, IdP).
- LLM model behavior (Yutha contains the impact of model misbehavior; the model itself is out of scope).
- Issues already publicly disclosed elsewhere (we'll prioritize fixing but not credit a "report" of an already-public issue).

## Threat model

The full threat model is at [`/docs/security/threat-model.md`](../security/threat-model.md). If your report is about a documented adversary (A1–A9), reference the adversary in your report — it helps us assess severity quickly.

## Acknowledgements

We maintain a hall of fame at `/docs/security/hall-of-fame.md` (forthcoming) listing researchers who have responsibly disclosed vulnerabilities. Inclusion is opt-in.

## Bug bounty

We do not have a bug bounty program in v1.0 of the project. The project may add one once it has the funding shape to support it; this is a Phase 3+ governance question (build-plan.md §13).

## Coordinated disclosure with backend implementers

Yutha specs are public; backend implementations may exist that we are not aware of. If your vulnerability affects multiple implementations of the same spec, we will coordinate disclosure across implementers known to us. If you know of additional implementers, tell us — we will reach out to them under the same disclosure timeline.

## Pre-disclosure list

Backend operators and verifiable-tier implementers may apply for pre-disclosure (early notice of advisories before public release) by emailing security@yutha.dev with proof of operator status. The list is small, vetted, and audited; pre-disclosed material is under embargo until public release.

## What this policy is not

- It is not legal advice.
- It does not waive any rights of the project or contributors.
- It is not a substitute for the operator's own security responsibilities (host security, IdP security, key management).

## Updates to this policy

This document is itself under RFC governance for major changes. Minor edits (clarifications, contact updates) happen via normal PR.
