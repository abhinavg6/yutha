// 3e-G example constitution — refund-attacker probe.
//
// One @id-annotated forbid rule denies SendEnvelope when the
// estimated USD cost is at or above the cap threshold. Paired with
// the enforcement rule in refund-cap.engine.yaml, this gives a
// deterministic detect → coach → quarantine → evict chain when the
// refund_attacker persona's escalating probe crosses the cap.
//
// The catch-all `permit` keeps SupportAgent traffic flowing, since
// it never sets estimated_cost_usd_cents >= 1000.

@id("refund-cap")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.estimated_cost_usd_cents >= 1000
};

permit (principal, action, resource);
