# RFC Process — Operator-Facing Guide

This is the practical, step-by-step guide for filing an RFC. The full policy lives in [RFC 0001](../../spec/rfcs/0001-rfc-process.md); this document is the orientation for someone about to write their first one.

## When do I need an RFC?

| You are about to... | RFC needed? |
|---------------------|-------------|
| Add a new spec | Yes |
| Add a field to an existing spec | Yes (minor) |
| Change a field's semantics | Yes (major) |
| Add a new performative, action_kind, caveat type, or other enumerated value | Yes (minor) |
| Fix a typo in a spec doc | No |
| Add a test that exercises an existing spec property | No |
| Add a test that requires existing conformant backends to change behavior | Yes |
| Improve documentation, examples, or rationale prose | No |
| Refactor reference-implementation internals without changing behavior | No |

When in doubt, ask in the project forum. If two people on the project look at the question and disagree, file the RFC — the cost is low.

## Step by step

### 1. Pick a number

Look in [`/spec/rfcs/`](../../spec/rfcs/). Use the next available integer. Numbers are not reserved; first PR opened wins. If you race someone, take the next number.

### 2. Pick a name

Filename: `NNNN-short-name.md`. The short name is kebab-case, ideally fewer than five words. Examples: `0007-passport-key-rotation`, `0023-add-vector-memory-tier`.

### 3. Copy the template

```bash
cp spec/rfcs/template.md spec/rfcs/0007-your-short-name.md
```

Fill it out. The template's section headers are a checklist — don't delete them, but you can write "N/A" if a section genuinely doesn't apply.

### 4. Write the substance

The hardest section is **§3 Detailed design**. The most often-skipped (and most valuable) section is **§4 Drawbacks**. Reviewers will push back hard on RFCs whose drawbacks section says "none" — almost every change has a cost.

**§5 Alternatives considered** wants at least two alternatives. "Do nothing" counts and is often the most important alternative to engage with.

**§6 Threat-model impact** is required for any RFC that touches a security boundary. If unsure, include a brief assessment; Workstream L will review.

**§7 Conformance impact** says what changes in `/conformance/`. If your RFC adds a spec field, it almost certainly adds a conformance test.

### 5. Open the PR

PR title: `RFC NNNN: <title>`. PR description: a short pointer ("This RFC proposes adding X. See the document for the full design.") and any context not in the document.

Tag suggested reviewers via CODEOWNERS or by name. CI will tag automatically based on what files you touched.

### 6. Announce on the forum

Open a discussion thread on the project forum titled `[RFC NNNN] <title>`. Link the PR. The thread is where most discussion happens; the PR is for the document itself.

### 7. Public review window

- Minor changes: 14 days minimum.
- Major changes: 30 days minimum.
- Sensitive changes (security boundary, RFC process itself, conformance mark policy): 60 days minimum.

The window starts when the announcement goes up. Reviewers may request extensions. You may extend.

### 8. Discussion

- Update the RFC document in response to substantive feedback. Push commits to the PR.
- Notify reviewers when you make non-trivial changes. They may want to re-review.
- Don't take silence as opposition. Lazy consensus is the model — silence at the end of the window is approval.
- Sustained objection from a maintainer blocks merge until resolved. "Resolved" means addressed in the document, the objector withdraws, or the project lead overrides on the record.

### 9. Decision

When the window expires:

- Two maintainers approve, no sustained objections → status changes to **Accepted**. Maintainer merges the PR.
- Sustained objection unresolved → status changes to **Blocked**. The PR stays open until the objection is resolved or the author withdraws.
- Author withdraws → status changes to **Withdrawn**. PR is closed.
- A later RFC supersedes → original status changes to **Superseded by RFC NNNN**.

### 10. Adoption

Accepted RFCs go through the adoption checklist (template §10):

- [ ] Spec doc updated and committed
- [ ] Rationale.md updated to reference this RFC
- [ ] Conformance tests updated
- [ ] Reference implementation updated
- [ ] Build plan reviewed for impact (if applicable)

Adoption may be a separate PR (often is, especially if the RFC author isn't the implementer). The RFC stays as the canonical statement of intent; the spec doc evolves from there.

## Anti-patterns

- **Filing the implementation as the RFC.** The RFC is the design document. The implementation comes after. Filing them together is fine; filing the implementation alone is not an RFC.
- **Skipping the alternatives section.** Reviewers can almost always think of an alternative. If you can't, you haven't thought about it long enough.
- **"This is obviously the right answer."** Maybe. The RFC asks you to make the obviousness inspectable.
- **Bundling unrelated changes.** One conceptual change per RFC. If you find yourself titling it with "and," split it.
- **Asking for the window to be skipped.** Don't. Even for trivial changes, 14 days is the floor. If something genuinely cannot wait, the project lead can call an emergency exception — but emergencies are rare.

## Examples

The launch-spec RFCs (0002–0006) are full examples of what an RFC looks like at landing. Read them; they're the calibration.

## Help

If you've never written an RFC before:

- Read [RFC 0001](../../spec/rfcs/0001-rfc-process.md) for the policy framing.
- Read one of the launch RFCs (0002–0006) for the shape.
- Ask in the project forum before you write a long document, especially for major or sensitive changes. A 10-minute orientation conversation often saves a 10-day RFC rewrite.
