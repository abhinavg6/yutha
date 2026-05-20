# Security Policy

Yutha sits on the trust boundary of the multi-agent systems that use it. Vulnerability reports are handled with that responsibility in mind.

This is an early-stage open-source project, stewarded by a single maintainer ([@abhinavg6](https://github.com/abhinavg6)) for now. It is actively developed and openly welcoming additional reviewers, security researchers, and contributors — see [Contributing](./CONTRIBUTING.md) if you'd like to help shape how this evolves.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://github.com/abhinavg6/yutha/security/advisories/new) — it routes directly to the maintainer and keeps the report private until coordinated disclosure.

What to include:

- A description of the vulnerability and its impact.
- Affected components (spec version and reference-implementation crate version where possible).
- Reproduction steps or proof of concept.
- Suggested mitigation if you have one (welcome but not required).
- Your name and contact details, or "anonymous" if you prefer.

## What you can expect

Yutha is stewarded by one person with a full-time job. The commitments below are calibrated to that reality — generous on purpose so they're actually honored. If anything is going to take longer than the stated window, you'll get a status update inside it.

- **Acknowledgement within 14 days.** A real human reads your report.
- **Initial assessment within 30 days.** You'll get an answer on whether it's a confirmed vulnerability, the rough severity, and a remediation plan.
- **Coordinated disclosure.** We agree on a timeline together. Default window is 120 days from confirmation; longer for unusually severe issues that need user upgrade time, or for issues where the fix is intricate.
- **Credit.** If you want it, you get it (in the advisory). If you want anonymity, you get that.
- **Good-faith protection.** Researchers who follow this policy have nothing to fear from the project.

## Severity rating

Calibrated to Yutha's threat model:

- **Critical.** Compromise of the trust boundary at the substrate layer (passport forgery, capability bypass, receipt tampering, signature forgery, constitution-engine sandbox escape).
- **High.** Defeat of a documented threat-model mitigation.
- **Medium.** Information disclosure, DoS against a single component, defense-in-depth weakening that does not by itself enable substrate compromise.
- **Low.** Best-practice deviation, hardening opportunity, theoretical issue without practical impact.

## What is in scope

- Yutha specs (`/spec/`).
- The reference implementation (`/crates/`, `/backends/`).
- The reference SDKs (`/sdks/`).
- The conformance suite (`/crates/yutha-conformance/`).

## What is out of scope

- Third-party backend implementations not maintained in this repo (report to those projects).
- Operator deployment misconfiguration (the conformance suite tests for it).
- The user's underlying infrastructure (host, network, IdP, KMS).
- LLM model behavior (Yutha contains the impact of model misbehavior; the model itself is out of scope).
- Issues already publicly disclosed elsewhere.

## What this policy is not

- It is not legal advice.
- It does not waive any rights of the project or contributors.
- It is not a substitute for the operator's own security responsibilities (host security, IdP security, key management).
