# Authoring constitutions

!!! info "Page in progress"
    Full content is being written. Until then, the [operator quickstart](quickstart.md) covers the basic activation flow and the [constitution spec](../reference/specs.md) is the authoritative reference for the Cedar+ surface.

Cedar+ is Yutha's extension of AWS's [Cedar](https://github.com/cedar-policy) policy language, augmented with the soft scoring rules, procedural state machines, resource budgets, and memory norms documented in RFCs 0010–0013.

Topics this page will cover:

- The plain-English authoring DSL and how it compiles to Cedar+
- Scoring rules: when to use a soft preference vs. a hard policy
- Procedures: encoding multi-step approval flows
- Resource budgets: wall-clock and quota bounds
- Memory norms: what agents can store and surface
- Testing a constitution before activation (`yutha-ops constitution test`)
- Versioning, rollback, and deactivation
