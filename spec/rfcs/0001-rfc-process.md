# RFC 0001: The RFC Process

> **Status:** Draft (the meta-RFC)
> **Authors:** Workstream A (Specs), Workstream H (Community)
> **Filed:** 2026-05-10
> **Targets:** the RFC process itself

## 1. Summary

This RFC defines how Yutha makes changes to its specs, conformance suite, and protocol-relevant behaviors. Every spec change goes through an RFC. Every RFC is filed in this directory, reviewed publicly, and either accepted, rejected, or withdrawn. Conversation happens in the open. Decisions are documented with their rationale. This is RFC 0001 because the process itself is the first thing the community needs to agree on.

## 2. Why we have an RFC process

Specs are the product (build-plan.md §2). If specs evolve through unilateral commits, the credibility argument for backend neutrality, framework neutrality, and the conformance suite collapses. If specs evolve through a heavy committee process, contribution slows to a halt and Yutha ceases to be a working open-source project.

The RFC process is the smallest possible apparatus that gives spec evolution three properties:

- **Visibility.** Every meaningful protocol change is observable. No private decisions about public artifacts.
- **Reviewability.** Authors articulate rationale, alternatives, drawbacks, and threat-model impact. Reviewers respond on the record. The artifact survives the conversation.
- **Pace.** Lazy consensus over committee voting. Sustained objections block; silence is approval. Authors who do their homework can ship; reviewers who care must show up.

It is also the apparatus that lets the project defer the foundation question (build-plan.md §13). Until there is a foundation, the RFC process is the institution. After a foundation, the RFC process is what the foundation oversees.

## 3. What requires an RFC

| Change kind | Requires RFC? |
|-------------|---------------|
| New spec at any version | Yes |
| Breaking change to an existing spec (major version bump) | Yes |
| Backwards-compatible addition to a spec (minor version bump) | Yes |
| Clarifications, doc fixes, examples, test-vector corrections (patch) | No — normal PR is sufficient |
| New conformance test that exercises an existing spec property | No — normal PR; flagged for reviewer attention |
| New conformance test that requires changing existing test results for conformant backends | Yes |
| New canonical schema (Phase 2+) | Yes |
| Changes to canonical action-kind taxonomy | Yes |
| Changes to architectural commitments in build-plan.md §4 | Yes |
| Cosmetic changes to docs | No |

When in doubt, file the RFC. The process is light enough that filing and discovering it is unnecessary is cheaper than landing a change that gets reverted because it should have been an RFC.

## 4. RFC lifecycle

**Filing.** Author drafts the RFC using `template.md`. RFC number is the next available integer in `/spec/rfcs/`. Filename is `NNNN-short-name.md` (kebab-case, fewer than five words). Author opens a PR adding the RFC document with status "Draft."

**Public review window.**
- **Minor changes**: 14 days minimum.
- **Major changes**: 30 days minimum.
- **Sensitive changes** (changes to security boundaries, the RFC process itself, or conformance-mark policy): 60 days minimum.

The window starts when the RFC is announced on the project forum. Reviewers may request extensions; authors may extend; the active maintainers can extend at any time.

**Discussion.** Happens on the forum thread linked from the RFC. Discussion that significantly changes the proposal results in updates to the RFC document; reviewers are notified of substantive changes.

**Decision.** Authors and the active maintainers reach a decision via lazy consensus:

- **Accepted** if the public window has expired AND no sustained objection from a maintainer remains unresolved AND at least two maintainers have explicitly approved.
- **Rejected** if a sustained objection from a maintainer remains unresolved at window expiry, or if the authors withdraw.
- **Superseded** if a later RFC explicitly replaces this one.

The decision is recorded in the RFC's status field and a concluding paragraph explaining the rationale. Rejected RFCs remain in the directory — the rejection rationale is itself a useful document.

**Adoption.** Accepted RFCs are landed: spec docs updated, rationale documents updated to reference the RFC, conformance tests updated, reference implementation updated. Adoption is tracked via the RFC's adoption checklist (template §10).

## 5. Who decides

The active maintainers of the relevant workstream(s). For RFCs touching multiple workstreams, all touched workstreams must have at least one maintainer approve.

The project lead is the tiebreaker on disputes that maintainers cannot resolve through discussion. The lead is identified in `/docs/community/MAINTAINERS.md`. The lead role is currently held by the project's original author and changes only by an RFC of its own.

We deliberately do not constitute a separate RFC committee, voting body, or council in v1.0. The project is small; adding institutional layers ahead of need creates more friction than legitimacy. If contributor base size grows enough to warrant a council (build-plan.md §5 Workstream H Phase 2), a future RFC will define one.

## 6. Reviewer guidance

If you are reviewing an RFC, the questions to answer:

- **Does it actually solve the stated problem?** Map the design back to the motivation; is there a coupling?
- **Are the alternatives genuinely considered?** "Do nothing" should be one of them most of the time.
- **What does it make worse?** A drawback section that says "none" is almost always wrong.
- **Threat-model impact.** Anything that touches a security boundary should have an explicit assessment, ideally with Workstream L sign-off.
- **Conformance.** If the spec changes, the suite changes. Is the test plan in the RFC?
- **Migration.** If this is a breaking change, is the migration story plausible?

If you object, state the objection clearly and what would resolve it. "I don't like it" is not actionable; "this regresses A3 mitigation because X" is. Sustained objections without resolution path are themselves a failure mode the project lead can intervene on.

## 7. Withdrawal and supersession

Authors may withdraw an RFC at any time before adoption. The status changes to "Withdrawn"; the document remains.

A later RFC may supersede an earlier one. The earlier RFC's status changes to "Superseded by RFC NNNN." The earlier document remains accessible.

## 8. Out of scope of the RFC process

- **Reference-implementation internals.** How a Rust crate is structured, what library it uses for hashing, how it handles error propagation — normal code review, not RFC.
- **Documentation tone or organization.** Improvements happen via PR.
- **Backend-implementation choices.** Backends conform to the spec; their internals are the implementer's choice.
- **Operational concerns of specific deployments.** Operators choose their own constitutions, topologies, and configurations; RFCs do not bind those choices.

## 9. Open questions

- Should we adopt a structured form for objections (e.g., GitHub-Reaction-style "block" or "concern") or keep it free-form? Currently free-form; revisit if discussion threads become unmanageable.
- How do we handle RFCs from non-maintainer contributors? Currently the same process; the contributor finds a maintainer co-author or sponsor for the adoption checklist. May formalize as a "champion" role later.
- Anonymity vs. attribution of reviewers. Currently fully attributed (real names on the record). Should we permit pseudonymous review for security-sensitive RFCs? Defer.

## 10. Adoption checklist

- [ ] This RFC document committed to `/spec/rfcs/0001-rfc-process.md`
- [ ] `/spec/README.md` §8 references this RFC
- [ ] `/docs/community/RFC_PROCESS.md` is the operator-facing version of this content
- [ ] At least two maintainers approved
- [ ] Public review window (60 days, sensitive) expired

## 11. References

- [`/spec/README.md`](../README.md) — versioning and RFC pointer
- [`/docs/internal/build-plan.md`](../../docs/internal/build-plan.md) — §13 governance posture; defers foundation
- [`/docs/community/CONTRIBUTING.md`](../../docs/community/CONTRIBUTING.md)
- Prior art: Rust RFCs (rust-lang/rfcs), IETF RFCs, Python PEPs, Go proposals
