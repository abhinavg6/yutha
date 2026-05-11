# RFC NNNN: <title>

> **Status:** Draft | Open for review | Accepted | Rejected | Superseded
> **Authors:** name <email>, name <email>
> **Reviewers:** initially empty; populated as the RFC opens for review
> **Filed:** YYYY-MM-DD
> **Targets spec:** e.g. `/spec/passport/` at v1.0 → v1.1
> **Targets phase:** Phase N
> **Discussion:** link to forum thread / issue

## 1. Summary

One paragraph. What is being proposed and why does it matter? A reader who skims only this section should understand whether they need to read further.

## 2. Motivation

Why is this RFC being filed? What problem does it solve, what gap does it close, what risk does it address? Cite the source documents (PRD section, threat-model adversary, build-plan workstream) that motivate the change.

If this is a response to an incident or a discovered bug, link the post-mortem.

## 3. Detailed design

The substance of the proposal. Wire-format changes if any (with proto diffs). Behavioral changes. New conformance test cases. Backwards-compatibility impact.

If the change touches multiple specs, walk through each one.

## 4. Drawbacks

Honest accounting of what this proposal makes worse. Performance cost. Implementation complexity. Documentation burden. Migration burden. Loss of optionality.

A drawback section that says "none" is almost always wrong. Reviewers will push back.

## 5. Alternatives considered

What other designs were considered, and why was this one chosen? At least two alternatives, even if you considered them briefly. Include "do nothing" if it is a real option.

## 6. Threat-model impact

Does this change strengthen or weaken any of the documented adversary mitigations (A1–A9)? Does it open any new attack surface? If yes, what mitigates it? Workstream L review required for any RFC that affects this section non-trivially.

## 7. Conformance impact

What changes in the conformance suite? Which sub-suites get new tests? Which existing tests change? What is the migration story for backends that pass the current suite but not the proposed one?

## 8. Migration

If this RFC introduces a breaking change, what is the migration path? Default deprecation window for major version bumps is 12 months (`/spec/README.md` §3); this section justifies any deviation.

## 9. Open questions

Anything the authors are not yet sure about. Reviewers can help resolve these in the discussion.

## 10. Adoption checklist

Concrete items required to land this RFC:

- [ ] Spec doc updated and committed
- [ ] `rationale.md` updated to reference this RFC
- [ ] Conformance tests updated
- [ ] Reference implementation updated to pass new tests
- [ ] Build plan reviewed for impact
- [ ] At least two reviewers approved
- [ ] Public review window expired (14 days minor / 30 days major)
- [ ] No sustained unresolved objections

## 11. References

Link the source documents, prior RFCs that this builds on or supersedes, related discussion threads, prior art in other systems.
