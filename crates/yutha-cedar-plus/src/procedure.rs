//! Engine-side bounded state-machine evaluator (RFC 0011 §3 / extensions.md §3).
//!
//! Has two responsibilities at evaluation time:
//!
//! 1. **Trigger matching.** For every procedure declaration, the
//!    synthesized trigger PolicySet (see [`crate::layer_b`]) is run via
//!    `Authorizer::is_authorized`. A matched trigger AND the absence of
//!    an open instance with the same triggering-action-descriptor digest
//!    stages a `procedure.enter` effect.
//!
//! 2. **Transition matching.** For every open instance in the
//!    [`ProcedureIndex`], the synthesized transition PolicySet is run.
//!    Matched policies whose `from_state` matches the instance's
//!    current state stage `procedure.transition` effects; if the
//!    target state is terminal, the instance is marked closed.
//!
//! The procedure-state index is reconstructable from receipts per
//! evaluation.md §6 — F8 builds the index access surface; receipt-
//! driven reconstruction is F9's contract.

use std::collections::HashMap;

use yutha_core::Hash;

use crate::eval::ProcedureEffect;
use crate::layer_b::{LayerBArtifacts, TransitionHandle};
use crate::loader::ActivatedConstitution;

/// In-memory procedure-state index. Maps `instance_id` to its current
/// state plus the metadata needed to fire transitions.
///
/// Per evaluation.md §6, this is advisory — the receipt log is the
/// source of truth. F8 populates it via [`Self::record_enter`] /
/// [`Self::record_transition`] which the evaluator calls when it
/// stages an effect; F9 wires the receipt-stream subscriber that
/// performs cold-start reconstruction over historic
/// `procedure.{enter,transition}` receipts.
#[derive(Debug, Default)]
pub struct ProcedureIndex {
    instances: HashMap<String, ProcedureInstance>,
}

impl ProcedureIndex {
    /// Construct an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage 1 of receipt reconstruction: record a fresh instance.
    /// Called when a `procedure.enter` effect fires.
    pub fn record_enter(&mut self, instance: ProcedureInstance) {
        self.instances
            .insert(instance.instance_id.clone(), instance);
    }

    /// Stage 2 of receipt reconstruction: advance an instance's state.
    /// Called when a `procedure.transition` effect fires.
    pub fn record_transition(&mut self, instance_id: &str, new_state: &str, terminal: bool) {
        if let Some(inst) = self.instances.get_mut(instance_id) {
            inst.current_state = new_state.to_string();
            inst.closed = terminal;
        }
    }

    /// True iff an open (non-closed) instance exists with the given
    /// instance_id. F8 uses this for idempotency on `procedure.enter`
    /// (same triggering action descriptor → same instance_id → at most
    /// one enter ever fires).
    pub fn has_open_instance(&self, instance_id: &str) -> bool {
        self.instances.get(instance_id).is_some_and(|i| !i.closed)
    }

    /// Iterate open instances whose procedure name matches the given
    /// name. Used by transition matching.
    pub fn open_instances_for(&self, procedure_name: &str) -> Vec<&ProcedureInstance> {
        self.instances
            .values()
            .filter(|i| !i.closed && i.procedure_name == procedure_name)
            .collect()
    }
}

/// One open procedure instance.
#[derive(Debug, Clone)]
pub struct ProcedureInstance {
    /// Content-addressed over `(procedure_name,
    /// triggering_action_descriptor_digest, swarm_id,
    /// entry_wall_clock)` per RFC 0011 §3.3.
    pub instance_id: String,
    /// The procedure this instance belongs to.
    pub procedure_name: String,
    /// Current state. Updated as transitions fire.
    pub current_state: String,
    /// Wall-clock at instance entry (for timeout scheduling).
    pub entry_wall_clock: String,
    /// Closed flag — true once the instance hits a terminal state or
    /// has been escalated.
    pub closed: bool,
}

/// Result of a Layer B procedure pass.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcedureOutcome {
    /// Effects to emit as receipts (enter / transition).
    pub(crate) effects: Vec<ProcedureEffect>,
}

/// Per-evaluation context the procedure evaluator needs in addition to
/// the cedar `Request` + `Entities` + activated constitution. Bundled
/// to keep the function-arg count manageable and to make the
/// dependency surface explicit at call sites.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcedureEvalContext<'a> {
    /// Content-address of the request's action descriptor. Used as
    /// part of the content-addressed instance_id (RFC 0011 §3.2 — the
    /// idempotency key for procedure entries).
    pub(crate) triggering_descriptor_digest: &'a Hash,
    /// String form of the swarm id (`SwarmId::Display`). Included in
    /// the instance_id digest so two swarms running the same
    /// constitution produce distinct instances.
    pub(crate) swarm_id_str: &'a str,
    /// The request's action kind. Used by transition matching to
    /// filter candidate transitions (defense-in-depth alongside the
    /// Cedar policy's action constraint).
    pub(crate) request_action_kind: &'a str,
    /// Wall-clock at evaluation time (RFC 3339). Included in
    /// instance_id digest + recorded on freshly-entered instances
    /// for timeout scheduling.
    pub(crate) current_wall_clock: &'a str,
}

/// Run trigger + transition matching for the given request. Mutates
/// the index optimistically so callers can stage receipt emission.
pub(crate) fn evaluate_procedures(
    request: &cedar_policy::Request,
    entities: &cedar_policy::Entities,
    activated: &ActivatedConstitution,
    index: &mut ProcedureIndex,
    ctx: ProcedureEvalContext<'_>,
) -> ProcedureOutcome {
    let mut effects = Vec::new();
    triggers(request, entities, activated, index, ctx, &mut effects);
    transitions(request, entities, activated, index, ctx, &mut effects);
    ProcedureOutcome { effects }
}

fn triggers(
    request: &cedar_policy::Request,
    entities: &cedar_policy::Entities,
    activated: &ActivatedConstitution,
    index: &mut ProcedureIndex,
    ctx: ProcedureEvalContext<'_>,
    effects: &mut Vec<ProcedureEffect>,
) {
    let LayerBArtifacts {
        procedure_trigger_policy_set,
        trigger_by_policy_id,
        ..
    } = &activated.layer_b;

    if procedure_trigger_policy_set.policies().count() == 0 {
        return;
    }

    let authorizer = cedar_policy::Authorizer::new();
    let response = authorizer.is_authorized(request, procedure_trigger_policy_set, entities);

    let mut matched: Vec<String> = response
        .diagnostics()
        .reason()
        .map(|p| p.to_string())
        .collect();
    matched.sort();

    for policy_id in &matched {
        let Some(procedure_name) = trigger_by_policy_id.get(policy_id) else {
            continue;
        };
        // RFC 0011 §3.2: instance_id is content-addressed over
        // (procedure_name || triggering_descriptor_digest || swarm_id ||
        // entry_wall_clock).
        let mut to_hash: Vec<u8> = Vec::new();
        to_hash.extend_from_slice(procedure_name.as_bytes());
        to_hash.extend_from_slice(&ctx.triggering_descriptor_digest.digest);
        to_hash.extend_from_slice(ctx.swarm_id_str.as_bytes());
        to_hash.extend_from_slice(ctx.current_wall_clock.as_bytes());
        let instance_hash = yutha_crypto::sha256(&to_hash);
        let instance_id = hex::encode(&instance_hash.digest);

        if index.has_open_instance(&instance_id) {
            // Idempotency — same triggering action descriptor → no
            // duplicate enter.
            continue;
        }

        // Look up the procedure's initial state.
        let Some(procedure) = activated
            .resolved_engine_config
            .procedures
            .iter()
            .find(|p| &p.name == procedure_name)
        else {
            continue;
        };

        let instance = ProcedureInstance {
            instance_id: instance_id.clone(),
            procedure_name: procedure_name.clone(),
            current_state: procedure.initial_state.clone(),
            entry_wall_clock: ctx.current_wall_clock.to_string(),
            closed: false,
        };
        index.record_enter(instance);
        effects.push(ProcedureEffect {
            action_kind: "procedure.enter".into(),
            instance_id,
        });
    }
}

fn transitions(
    request: &cedar_policy::Request,
    entities: &cedar_policy::Entities,
    activated: &ActivatedConstitution,
    index: &mut ProcedureIndex,
    ctx: ProcedureEvalContext<'_>,
    effects: &mut Vec<ProcedureEffect>,
) {
    let LayerBArtifacts {
        procedure_transition_policy_set,
        transition_by_policy_id,
        ..
    } = &activated.layer_b;

    if procedure_transition_policy_set.policies().count() == 0 {
        return;
    }

    let authorizer = cedar_policy::Authorizer::new();
    let response = authorizer.is_authorized(request, procedure_transition_policy_set, entities);

    let mut matched: Vec<String> = response
        .diagnostics()
        .reason()
        .map(|p| p.to_string())
        .collect();
    matched.sort();

    for policy_id in &matched {
        let Some(handle) = transition_by_policy_id.get(policy_id) else {
            continue;
        };
        // Filter: this policy's action must match the request's
        // action kind. (Cedar already enforces this in the policy's
        // head, but defense-in-depth — the policy id encodes the
        // action and we double-check.)
        if handle.action != ctx.request_action_kind {
            continue;
        }
        fire_transition(activated, index, handle, effects);
    }
}

fn fire_transition(
    activated: &ActivatedConstitution,
    index: &mut ProcedureIndex,
    handle: &TransitionHandle,
    effects: &mut Vec<ProcedureEffect>,
) {
    let open: Vec<String> = index
        .open_instances_for(&handle.procedure_name)
        .iter()
        .filter(|i| i.current_state == handle.from_state)
        .map(|i| i.instance_id.clone())
        .collect();

    let procedure = match activated
        .resolved_engine_config
        .procedures
        .iter()
        .find(|p| p.name == handle.procedure_name)
    {
        Some(p) => p,
        None => return,
    };

    let terminal = procedure.terminal_states.contains(&handle.to_state);

    for instance_id in open {
        index.record_transition(&instance_id, &handle.to_state, terminal);
        effects.push(ProcedureEffect {
            action_kind: "procedure.transition".into(),
            instance_id,
        });
    }
}
