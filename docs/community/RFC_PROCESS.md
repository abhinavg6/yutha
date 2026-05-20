# RFC Process — Practical Guide

This is the practical, step-by-step guide for filing an RFC. The full policy lives in [RFC 0001](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0001-rfc-process.md); this document is the orientation for someone about to write their first one.

Yutha is stewarded by one maintainer right now. The RFC process exists because spec changes need to be inspectable, not because the process is itself a goal. Timelines below are intentionally generous — they reflect a one-person-with-a-day-job cadence, not a target.

## When do I need an RFC?

| You are about to... | RFC needed? |
|---------------------|-------------|
| Add a new spec | Yes |
| Add a field to an existing spec | Yes |
| Change a field's semantics | Yes |
| Add a new performative, action_kind, caveat type, or other enumerated value | Yes |
| Fix a typo in a spec doc | No |
| Add a test that exercises an existing spec property | No |
| Add a test that requires existing conformant backends to change behavior | Yes |
| Improve documentation, examples, or rationale prose | No |
| Refactor reference-implementation internals without changing behavior | No |

When in doubt, open a draft issue and ask. The cost of asking is low; the cost of writing a 10-page document for something that didn't need one is high.

## Step by step

### 1. Pick a number

Look in [`/spec/rfcs/`](https://github.com/abhinavg6/yutha/tree/main/spec/rfcs/). Use the next available integer. Numbers are not reserved; first PR opened wins. If you race someone, take the next number.

### 2. Pick a name

Filename: `NNNN-short-name.md`. The short name is kebab-case, ideally fewer than five words. Examples: `0007-passport-key-rotation`, `0023-add-vector-memory-tier`.

### 3. Copy the template

```bash
cp spec/rfcs/template.md spec/rfcs/NNNN-your-short-name.md
```

Fill it out. The template's section headers are a checklist — don't delete them, but you can write "N/A" if a section genuinely doesn't apply.

### 4. Write the substance

The hardest section is **§3 Detailed design**. The most often-skipped (and most valuable) section is **§4 Drawbacks**. Almost every change has a cost; "none" is rarely an honest answer.

**§5 Alternatives considered** wants at least two alternatives. "Do nothing" counts and is often the most important alternative to engage with.

**§6 Threat-model impact** is required for any RFC that touches a security boundary. If unsure, include a brief assessment anyway.

**§7 Conformance impact** says what changes in the conformance suite. If your RFC adds a spec field, it almost certainly adds a conformance test.

### 5. Open the PR

PR title: `RFC NNNN: <title>`. PR description: a short pointer ("This RFC proposes adding X. See the document for the full design.") and any context not in the document.

### 6. Review window

The window is a *minimum* — it's the floor under which a decision will not be made. There is no maximum; RFCs can sit open for as long as needed.

- **Most RFCs:** 30 days minimum.
- **Security-boundary, conformance-mark, or RFC-process-itself changes:** 60 days minimum.

The window starts when the PR is opened.

### 7. Discussion

- Update the RFC document in response to feedback. Push commits to the PR.
- Don't take silence as opposition; equally, don't take silence as approval. Decisions land in writing, on the PR.
- Substantive disagreement keeps the RFC open. If you and the maintainer can't converge in the PR thread, that's fine — most RFCs eventually converge or get withdrawn; very few stay stuck.

### 8. Decision

When the window has passed and discussion has settled, one of:

- **Accepted** — the maintainer approves, merges the PR. Status changes to Accepted.
- **Withdrawn** — the author closes the PR. Status changes to Withdrawn.
- **Blocked** — substantive disagreement unresolved. PR stays open until the disagreement is addressed.
- **Superseded** — a later RFC replaces this one. Status changes to Superseded by RFC NNNN.

### 9. Adoption

Accepted RFCs go through the adoption checklist (template §10):

- [ ] Spec doc updated and committed
- [ ] Rationale.md updated to reference this RFC
- [ ] Conformance tests updated
- [ ] Reference implementation updated
- [ ] Build plan reviewed for impact (if applicable)

Adoption may be a separate PR (often is, especially if the RFC author isn't the implementer). The RFC stays as the canonical statement of intent; the spec doc evolves from there.

## Anti-patterns

- **Filing the implementation as the RFC.** The RFC is the design document. The implementation comes after. Filing them together is fine; filing the implementation alone is not an RFC.
- **Skipping the alternatives section.** There's almost always an alternative. If you can't think of one, you haven't thought about it long enough.
- **"This is obviously the right answer."** Maybe. The RFC asks you to make the obviousness inspectable.
- **Bundling unrelated changes.** One conceptual change per RFC. If you find yourself titling it with "and," split it.
- **Asking for the window to be skipped.** Don't. Even for trivial changes, 30 days is the floor.

## Examples

The launch RFCs (0002–0006) are full examples of what an RFC looks like at landing. Read them; they're the calibration.

## Help

If you've never written an RFC before:

- Read [RFC 0001](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0001-rfc-process.md) for the policy framing.
- Read one of the launch RFCs (0002–0006) for the shape.
- Open a draft issue describing what you want to propose before writing a long document — especially for security-boundary or RFC-process-itself changes. A short conversation up front often saves a long rewrite later.
