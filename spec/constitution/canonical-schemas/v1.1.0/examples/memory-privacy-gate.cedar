// Example constitution policy — memory privacy gate (v1.1.0)
//
// Demonstrates gating one of the v1.1 memory-norm actions
// (`ReadMemory`) using a resource attribute (`memory.scope`) combined
// with an entity reference (`memory.owner`).
//
// Policy semantics:
//   1. A read of a `private`-scoped memory denies unless the
//      principal IS the memory's owner. Cross-agent reads of private
//      memories produce `constitution.evaluate.deny` with this rule
//      id; the owner reading their own private memory passes.
//   2. Reads of any non-private scope hit the trailing permit-all
//      rule and succeed.
//
// Pair with `memory-privacy-gate.yaml` for the engine config.

@id("private-memory-read-gate")
forbid (
    principal,
    action == Yutha::Action::"ReadMemory",
    resource
) when {
    resource.scope == "private" && principal != resource.owner
};

permit (principal, action, resource);
