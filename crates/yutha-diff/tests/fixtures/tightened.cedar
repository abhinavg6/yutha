// Tightened constitution — baseline plus one new forbid policy
// gating large refund envelopes. Demonstrates an "added cedar
// policy" diff entry.

@id("permit-routine-actions")
permit (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
);

@id("forbid-large-refunds")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
)
when {
    context.payload_schema_id == "type.yutha.dev/v1/Refund" &&
    context.estimated_cost_usd_cents > 50000
};
