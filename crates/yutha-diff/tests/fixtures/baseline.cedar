// Baseline constitution — minimal permit-all for `SendEnvelope`.
// Single annotated policy keyed on `@id("permit-routine-actions")`
// so diffs against later versions match by name.

@id("permit-routine-actions")
permit (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
);
