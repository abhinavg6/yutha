# Code review crew with security boundaries

!!! info "Page in progress"
    Full content is being written.

What this example will cover:

- The agents: reviewer (reads PRs), auto-fix (proposes patches), security-tag enforcer
- The capability: auto-fix gets a write capability scoped to file paths NOT tagged `@security` in the codebase; security-tagged files require human review
- The topology: closed (operator-vetted agents only)
- Walkthrough: a PR with a typo in `README.md` — auto-fix patches and merges, receipt recorded
- Walkthrough: a PR touching `crates/yutha-crypto/` — auto-fix's capability check fails, escalates to human review, both attempts logged
- Walkthrough: an auto-fix agent that tries to bypass the security tag — three attempts inside a minute trip the four-stage enforcement loop, agent is restricted then quarantined
- Audit trail: every receipt with annotations
