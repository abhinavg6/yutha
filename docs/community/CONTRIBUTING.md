# Contributing to Yutha

Thanks for thinking about contributing. This document is the operational guide; the philosophical orientation lives in [`/docs/build-plan.md`](../build-plan.md) §13 (governance posture) and [`/spec/rfcs/0001-rfc-process.md`](../../spec/rfcs/0001-rfc-process.md) (the RFC process).

## What kind of contribution are you bringing?

| Kind | Where to start |
|------|----------------|
| Bug report | Open an issue. Include version, reproduction, expected vs. actual. |
| Documentation fix | Open a PR. No issue needed. |
| Quickstart improvement | Open a PR. Test it on a fresh machine if possible. |
| New feature in an existing spec (minor change) | File an RFC. See [RFC 0001](../../spec/rfcs/0001-rfc-process.md). |
| New spec or breaking change | File an RFC. See [RFC 0001](../../spec/rfcs/0001-rfc-process.md). |
| New backend implementation | Read the relevant interface spec; pass the conformance suite at the level you're claiming; open a PR adding the backend under `/backends/`. |
| New SDK adapter for a new framework | Read [`/sdk/README.md`](../../sdk/README.md); follow the adapter pattern; open a PR adding the adapter under `/sdk/<lang>/`. |
| Security disclosure | Do **not** open a public issue. See [SECURITY.md](./SECURITY.md). |

## Before you start

- For non-trivial work (more than a docs fix), it's almost always faster to ask in the project forum first whether the direction makes sense. Maintainers can flag overlap with in-flight work.
- For RFC-bearing work, file the RFC before writing the implementation. The RFC discussion frequently changes the implementation. Doing implementation first wastes your time.
- Read the relevant spec doc and rationale before opening a PR that touches an interface. The spec is the contract; the rationale tells you why it's shaped that way.

## Your first PR

The classic starter contributions:

- **Documentation gap.** If you tried something and the docs were unclear, fix that. The build plan flags doc-gap-issue-frequency as a tracked metric — your fix is genuinely useful.
- **Quickstart improvement.** The 15-minute joiner path and 30-minute initiator path are phase-exit gates. If you found a friction point, smoothing it is high-value.
- **Conformance test gap.** If you find an interface property the spec mandates but no test exercises, write the test.
- **Adversary scenario.** Phase 3 work; if you can write a drop-in adversary agent for one of A1–A9 that reveals a gap, that's a strong contribution.

We do not maintain a "good first issue" list yet (the project is too young). The above is the moral equivalent.

## Pull request flow

1. Fork. Branch from `main`. Branch names are unprestructured — call it whatever makes sense to you.
2. Make the change. Keep PRs small and focused. One conceptual change per PR is the rule; split if you find yourself titling the PR with "and."
3. Run the relevant conformance tests. CI runs them too, but local runs save round-trips.
4. Open the PR with a description that explains *what* and *why*. The diff explains *how*; the description explains *why* the diff exists.
5. Tag relevant CODEOWNERS. CI tags suggested reviewers automatically.
6. Address review comments. Push more commits; we squash on merge.

PRs touching security-critical paths (`yutha-cedar-plus`, `yutha-crypto`, `yutha-passport`, `yutha-capability`, `yutha-receipt`) require **two-person review**, with at least one reviewer from Workstream L. CI enforces via CODEOWNERS.

PRs that change spec semantics require an accepted RFC. CI flags spec-touching PRs that don't reference an RFC; if you genuinely don't need one (clarification, doc fix), say so in the PR description.

## Local development

The full setup lives in `/docs/development/getting-started.md` (forthcoming as the reference implementation lands). For now:

- Rust toolchain: stable; MSRV is current stable minus three releases.
- `cargo workspace` for the monorepo.
- Recommended: `mold` linker, `sccache` to keep build times reasonable.
- Conformance suite runs via `cargo test --workspace --features conformance`.

## Writing style

We aim for prose that respects the reader's time. Short paragraphs. Concrete examples. No jargon without definition. The build-plan.md and spec rationales are the calibration; if your prose feels heavier than those, simplify.

We do not use emojis in code or docs unless explicitly requested.

## Code of conduct

The [Contributor Covenant](./CODE_OF_CONDUCT.md) applies to every interaction in project spaces.

## Reviewing other people's PRs

Reviewing is a contribution. Useful reviews:

- Look for what the PR doesn't say. What edge case isn't handled? What test isn't written?
- Distinguish "I would have done this differently" (a preference, often not actionable) from "this has a bug" (always actionable). Lead with the latter; share the former only if it materially matters.
- For RFC-touching PRs, check the RFC was actually referenced and the change matches what the RFC proposed.
- Be honest. "LGTM" without reading the diff is worse than no review.

## Maintainership

Active maintainers are listed in [`MAINTAINERS.md`](./MAINTAINERS.md) (forthcoming as the project grows). Becoming a maintainer is a function of sustained, substantive contribution; there is no formal application. A current maintainer proposes you; lazy consensus among the rest decides.

## Decision-making

The RFC process (RFC 0001) governs changes to specs, conformance suite, and protocol-relevant behaviors. Other decisions (implementation patterns, library choices internal to a crate, refactors) are made by the workstream maintainers via normal PR review.

For disputes that can't be resolved through discussion, the project lead (currently the original author, see [MAINTAINERS.md](./MAINTAINERS.md)) is the tiebreaker.

We deliberately do not have a foundation, council, or governing board in v1.0. The decision is documented in [`/docs/build-plan.md`](../build-plan.md) §13. We will revisit at Phase 3 entry.

## License

Yutha is released under the [Apache License 2.0](../../LICENSE) (subject to confirmation in the LICENSE file as it lands). Contributions are accepted under the same license. We do not require a CLA at this time; the project may revisit if license-clarity demands warrant.

## What if I'm here for the wrong reasons

Reasonable concerns:

- "I want to add my company's logo to the README." We don't accept these. The project does not accept logos, sponsor placements, or other promotional content. Sustained contribution is the only attribution mechanism.
- "I want to submit AI-generated PRs at scale." Please don't. Tool-assisted contribution is fine; spammy noise is not. We will close low-quality PRs without extensive feedback.
- "I want to add a feature that's already been rejected via RFC." Read the rejection RFC first. If you have new arguments or evidence, file a new RFC referencing the old one. If you're just hoping nobody notices, we will notice.
- "I want my PR merged urgently." Open-source project; nobody is on the hook for your timeline. Sustained contributors get faster review by virtue of being known. New contributors get good-faith review at the project's pace.

Welcome. Looking forward to your contribution.
