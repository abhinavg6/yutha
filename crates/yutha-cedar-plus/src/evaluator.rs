//! `CedarPlusEvaluator` — the Layer A evaluator that delegates gating
//! to stock `cedar-policy::Authorizer::is_authorized`.
//!
//! Per [evaluation.md](../../../spec/constitution/evaluation.md) §1.3
//! steps 4 and 5: this module covers Layer A (Cedar gating) only.
//! Layer B (scoring + procedure transitions) is wired in F8; the
//! enforcement subsystem lands in F9.
//!
//! ## Posture
//!
//! Constitution evaluation is two layers (RFC 0012 §3.1). F7 implements
//! Layer A and leaves Layer B's contributions as empty values in the
//! [`EvaluationOutcome`] (no `score_contributions`, no
//! `procedure_effects`). F8 / F9 fill in the engine-side work without
//! changing the request/response shapes; existing callers stay
//! source-compatible.
//!
//! ## Threading / interior mutability
//!
//! The evaluator holds the active [`ActivatedConstitution`] behind a
//! [`tokio::sync::RwLock`] so [`ConstitutionEvaluator::activate`] (which
//! takes `&self`) can swap the constitution atomically while concurrent
//! evaluators read the previous one. Evaluation is read-only access;
//! activation takes a brief write lock at the swap.
//!
//! ## cedar-policy 3.x API surface
//!
//! This module touches the public cedar-policy 3.x API in four places:
//!
//! 1. [`cedar_policy::Entities::from_json_value`] to build the entity
//!    store from our typed [`EntitySnapshot`].
//! 2. [`cedar_policy::EntityUid::from_type_name_and_id`] to construct
//!    principal / action / resource UIDs.
//! 3. [`cedar_policy::Context::from_json_value`] to build the eval
//!    context from `context_attrs`.
//! 4. [`cedar_policy::Authorizer::is_authorized`] for the gating
//!    decision.
//!
//! If any of those API names shift in a future cedar bump, surgical
//! fixes land here.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use yutha_core::{Hash, Timestamp};

use crate::constitution::Constitution;
use crate::error::{CedarPlusError, EvalBoundReason, Result};
use crate::eval::{
    ConstitutionEvaluator, Decision, EntitySnapshot, EntityUid, EvaluationOutcome,
    EvaluationRequest, ProcedureEffect, ScoreContribution,
};
use crate::loader::{ActivatedConstitution, ConstitutionLoader};
use crate::procedure::{evaluate_procedures, ProcedureEvalContext, ProcedureIndex};
use crate::sandbox::SandboxConfig;
use crate::scoring::evaluate_scoring;

/// The concrete evaluator. Construct once with a [`ConstitutionLoader`]
/// and [`SandboxConfig`]; reuse across many activations + evaluations.
pub struct CedarPlusEvaluator {
    loader: ConstitutionLoader,
    sandbox: SandboxConfig,
    current: RwLock<Option<Arc<ActivatedConstitution>>>,
    /// In-memory procedure-state index. Held under a `Mutex` because
    /// procedure trigger / transition evaluation mutates the index
    /// optimistically and we don't want two concurrent evaluations
    /// to race on the same instance. Per evaluation.md §6, the
    /// receipt log is authoritative — F9 wires the receipt-driven
    /// reconstruction path that rebuilds this index on cold start
    /// or after a detected divergence.
    procedure_index: Mutex<ProcedureIndex>,
}

impl CedarPlusEvaluator {
    /// Construct an evaluator with explicit loader + bounds.
    pub fn new(loader: ConstitutionLoader, sandbox: SandboxConfig) -> Self {
        Self {
            loader,
            sandbox,
            current: RwLock::new(None),
            procedure_index: Mutex::new(ProcedureIndex::new()),
        }
    }

    /// Construct an evaluator with the default sandbox config.
    pub fn with_default_bounds(loader: ConstitutionLoader) -> Self {
        Self::new(loader, SandboxConfig::default())
    }

    /// Read access to the currently-activated constitution, if any.
    /// Returns the same `Arc` to all concurrent readers.
    pub async fn current(&self) -> Option<Arc<ActivatedConstitution>> {
        self.current.read().await.as_ref().map(Arc::clone)
    }
}

#[async_trait]
impl ConstitutionEvaluator for CedarPlusEvaluator {
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationOutcome> {
        // -- Stage 1: resolve the currently-active constitution. ----------
        let active = {
            let guard = self.current.read().await;
            guard.as_ref().cloned().ok_or_else(|| {
                CedarPlusError::ConstitutionUnresolved(
                    "no active constitution; call activate() first".into(),
                )
            })?
        };

        // Verify the request's constitution_hash matches the active
        // one. A mismatch means the caller is racing an amendment;
        // we deny with `constitution_unresolved` rather than evaluating
        // against the wrong constitution.
        if request.constitution_hash != active.constitution.constitution_hash {
            return Err(CedarPlusError::ConstitutionUnresolved(format!(
                "request pinned to constitution {}, active is {}",
                hex::encode(&request.constitution_hash.digest),
                hex::encode(&active.constitution.constitution_hash.digest),
            )));
        }

        // -- Stage 2: sandbox bound checks. ------------------------------
        if request.entity_snapshot.entity_count() > self.sandbox.max_entity_count {
            return Err(CedarPlusError::EvaluationBoundExceeded(
                EvalBoundReason::EntityStoreSize,
            ));
        }

        // -- Stage 3: build cedar Request + Entities. ---------------------
        let principal_uid = build_cedar_uid(&EntityUid::new(
            "Yutha::Agent",
            request.principal_id.to_string(),
        ))?;
        // The evaluator used to hardcode the action entity-type as
        // "Yutha::Action", which broke any action declared in a
        // workload-extension namespace (e.g.
        // `Yutha::SupportQueue::Action::"IssueRefund"`). F14
        // generalizes: if `action_kind` carries a `::` separator,
        // treat the substring before the LAST `::` as the entity
        // type and the trailing substring as the entity id. Bare
        // names continue to land in `Yutha::Action`.
        let (action_type, action_id) = match request.action_kind.rfind("::") {
            Some(idx) => (&request.action_kind[..idx], &request.action_kind[idx + 2..]),
            None => ("Yutha::Action", request.action_kind.as_str()),
        };
        let action_uid = build_cedar_uid(&EntityUid::new(action_type, action_id.to_string()))?;
        let resource_uid = build_cedar_uid(&request.resource_uid)?;

        let entities = build_cedar_entities(&request.entity_snapshot, schema_ref(&active))?;
        let context = build_context(&request.context_attrs, &action_uid)?;

        let cedar_request = cedar_policy::Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            context,
            Some(schema_ref(&active)),
        )
        .map_err(|e| CedarPlusError::RequestShapeInvalid(format!("Cedar Request rejected: {e}")))?;

        // -- Stage 4: Layer A — Authorizer. -------------------------------
        let authorizer = cedar_policy::Authorizer::new();
        let response = authorizer.is_authorized(&cedar_request, &active.policy_set, &entities);

        // -- Stage 5: Layer B — scoring + procedures (only on Permit). ----
        let (score_contributions, total_score, procedure_effects) =
            if matches!(response.decision(), cedar_policy::Decision::Allow) {
                let scoring = evaluate_scoring(&cedar_request, &entities, &active);
                let total = scoring.total_score();

                // The procedure subsystem mutates the index, so we
                // take the lock for the duration of the eval. F9
                // refines this with finer-grained locking if hot-
                // path contention becomes measurable.
                let mut index = self.procedure_index.lock().await;
                let triggering_descriptor_digest =
                    hash_input_attributes(&request, &request.entity_snapshot);
                let swarm_id_str = active.constitution.swarm_id.to_string();
                let proc_ctx = ProcedureEvalContext {
                    triggering_descriptor_digest: &triggering_descriptor_digest,
                    swarm_id_str: &swarm_id_str,
                    request_action_kind: &request.action_kind,
                    current_wall_clock: &request.current_wall_clock,
                };
                let procedures =
                    evaluate_procedures(&cedar_request, &entities, &active, &mut index, proc_ctx);
                drop(index);

                (scoring.contributions, total, procedures.effects)
            } else {
                (Vec::new(), None, Vec::new())
            };

        // -- Stage 6: assemble the outcome. -------------------------------
        let outcome = map_cedar_response(
            &response,
            &request,
            &request.entity_snapshot,
            score_contributions,
            total_score,
            procedure_effects,
        );
        Ok(outcome)
    }

    async fn activate(&self, constitution: Constitution) -> Result<Hash> {
        let activated = self.loader.load(constitution)?;
        let constitution_hash = activated.constitution.constitution_hash.clone();
        let mut guard = self.current.write().await;
        *guard = Some(Arc::new(activated));
        Ok(constitution_hash)
    }
}

// =============================================================================
// Helpers — cedar conversions
// =============================================================================

/// Borrow the schema out of an `ActivatedConstitution`. The schema is
/// stored as `Arc<Schema>` on activation (the loader clones the Arc
/// from its own schema reference) so concurrent evaluations share the
/// same parsed Schema without per-call work.
fn schema_ref(active: &ActivatedConstitution) -> &cedar_policy::Schema {
    &active.schema
}

/// Convert our typed [`EntityUid`] to cedar's `EntityUid`. Errors map
/// to [`CedarPlusError::EntityUnresolved`] / `RequestShapeInvalid`
/// depending on which part of the name failed to parse.
fn build_cedar_uid(uid: &EntityUid) -> Result<cedar_policy::EntityUid> {
    let type_name = cedar_policy::EntityTypeName::from_str(&uid.entity_type).map_err(|e| {
        CedarPlusError::RequestShapeInvalid(format!(
            "invalid entity type name {:?}: {e}",
            uid.entity_type
        ))
    })?;
    let id = cedar_policy::EntityId::from_str(&uid.entity_id).map_err(|e| {
        CedarPlusError::EntityUnresolved(format!("invalid entity id {:?}: {e}", uid.entity_id))
    })?;
    Ok(cedar_policy::EntityUid::from_type_name_and_id(
        type_name, id,
    ))
}

/// Convert our [`EntitySnapshot`] to cedar's `Entities`. The snapshot
/// is serialized to cedar's documented JSON entity format, then parsed
/// by cedar against the schema. JSON is the cross-version-stable wire
/// for entity construction.
fn build_cedar_entities(
    snapshot: &EntitySnapshot,
    schema: &cedar_policy::Schema,
) -> Result<cedar_policy::Entities> {
    let json_entities: Vec<serde_json::Value> = snapshot
        .entities
        .iter()
        .map(|e| {
            json!({
                "uid": {
                    "type": e.uid.entity_type,
                    "id": e.uid.entity_id,
                },
                "attrs": e.attrs,
                "parents": e
                    .parents
                    .iter()
                    .map(|p| json!({ "type": p.entity_type, "id": p.entity_id }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let json_value = serde_json::Value::Array(json_entities);
    cedar_policy::Entities::from_json_value(json_value, Some(schema)).map_err(|e| {
        CedarPlusError::EntityUnresolved(format!("entity snapshot rejected by Cedar: {e}"))
    })
}

/// Build cedar's `Context` from our context_attrs map.
///
/// Cedar's Context wants action-bound shape for strict validation; we
/// pass the action UID so the schema check can verify each attribute
/// is declared in the action's `appliesTo.context`.
fn build_context(
    attrs: &HashMap<String, serde_json::Value>,
    _action_uid: &cedar_policy::EntityUid,
) -> Result<cedar_policy::Context> {
    let value = serde_json::Value::Object(
        attrs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<serde_json::Map<_, _>>(),
    );
    cedar_policy::Context::from_json_value(value, None)
        .map_err(|e| CedarPlusError::RequestShapeInvalid(format!("Cedar Context rejected: {e}")))
}

/// Map cedar's [`cedar_policy::Response`] to our [`EvaluationOutcome`],
/// folding in the Layer B contributions (scoring + procedures) the
/// caller already computed.
fn map_cedar_response(
    response: &cedar_policy::Response,
    request: &EvaluationRequest,
    snapshot: &EntitySnapshot,
    score_contributions: Vec<ScoreContribution>,
    total_score: Option<crate::eval::Score>,
    procedure_effects: Vec<ProcedureEffect>,
) -> EvaluationOutcome {
    let matched_rule_ids: Vec<String> = response
        .diagnostics()
        .reason()
        .map(|pid| pid.to_string())
        .collect();

    let (decision, deny_reason) = match response.decision() {
        cedar_policy::Decision::Allow => (Decision::Permit, None),
        cedar_policy::Decision::Deny => {
            // Cedar populates `reason` with the forbid policies that
            // matched. If reason is empty on a Deny, no permit rule
            // applied (default-deny). If non-empty, an explicit
            // forbid matched.
            let reason = if matched_rule_ids.is_empty() {
                "no_permit_rule".to_string()
            } else {
                "forbid_rule_matched".to_string()
            };
            (Decision::Deny, Some(reason))
        }
    };

    // Evidence digest per evaluation.md §9. Canonical bytes hash over
    // (matched_rule_ids sorted, score_contributions in declaration
    // order, procedure_effects in emission order, input_attribute_digest).
    let mut matched_sorted = matched_rule_ids.clone();
    matched_sorted.sort();
    let input_attribute_digest = hash_input_attributes(request, snapshot);
    let evidence_digest = compute_evidence_digest(
        &matched_sorted,
        &score_contributions,
        &procedure_effects,
        &input_attribute_digest,
    );

    EvaluationOutcome {
        decision,
        deny_reason,
        matched_rule_ids,
        score_contributions,
        total_score,
        procedure_effects,
        evidence_digest,
        decided_at: Timestamp::now(),
    }
}

/// Hash the input attributes the evaluator saw: principal + action +
/// resource + context + entity snapshot. The digest goes into
/// `evidence_digest` so receipts are content-addressed over inputs.
///
/// Canonical form: BTreeMap-backed JSON with sorted keys at every
/// nesting level. `context_attrs` is converted from `HashMap` to a
/// sorted `BTreeMap` before serialization so byte-equivalence holds
/// across runs and implementations per evaluation.md §4.
fn hash_input_attributes(request: &EvaluationRequest, snapshot: &EntitySnapshot) -> Hash {
    let context_sorted: BTreeMap<&String, &serde_json::Value> =
        request.context_attrs.iter().collect();
    let canonical = json!({
        "action_kind": request.action_kind,
        "principal_id": request.principal_id.to_string(),
        "resource_uid": {
            "type": request.resource_uid.entity_type,
            "id": request.resource_uid.entity_id,
        },
        "context_attrs": context_sorted,
        "entity_count": snapshot.entity_count(),
        "current_wall_clock": &request.current_wall_clock,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    yutha_crypto::sha256(&bytes)
}

/// Compute the evidence digest per evaluation.md §9: hash over
/// (matched_rule_ids sorted, score_contributions in declaration order,
/// procedure_effects in emission order, input_attribute_digest hex).
///
/// `score_contributions` and `procedure_effects` are emitted as
/// pre-built JSON arrays so canonical serialization is unambiguous;
/// the caller is responsible for the in-array ordering being
/// deterministic.
fn compute_evidence_digest(
    matched_rule_ids: &[String],
    score_contributions: &[ScoreContribution],
    procedure_effects: &[ProcedureEffect],
    input_attribute_digest: &Hash,
) -> Hash {
    let score_payload: Vec<serde_json::Value> = score_contributions
        .iter()
        .map(|c| {
            json!({
                "rule_id": &c.rule_id,
                "score": &c.score.0,
            })
        })
        .collect();
    let procedure_payload: Vec<serde_json::Value> = procedure_effects
        .iter()
        .map(|e| {
            json!({
                "action_kind": &e.action_kind,
                "instance_id": &e.instance_id,
            })
        })
        .collect();
    let canonical = json!({
        "matched_rule_ids": matched_rule_ids,
        "score_contributions": score_payload,
        "procedure_effects": procedure_payload,
        "input_attribute_digest": hex::encode(&input_attribute_digest.digest),
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    yutha_crypto::sha256(&bytes)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_config::EngineConfig;
    use crate::loader::canonical_schema_v1_1;
    use yutha_core::{AgentId, HashAlgorithm, SpecVersion, SwarmId};

    fn placeholder_hash() -> Hash {
        Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).expect("placeholder hash")
    }

    fn make_constitution(cedar_source: &str) -> Constitution {
        Constitution {
            constitution_hash: placeholder_hash(),
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            schema_version: "1.1.0".into(),
            constitution_version: "1.0.0".into(),
            parent_version: None,
            swarm_id: SwarmId::new(),
            cedar_source: cedar_source.into(),
            engine_config: EngineConfig::default(),
            issued_at: Timestamp::now(),
        }
    }

    fn make_evaluator() -> CedarPlusEvaluator {
        let schema = canonical_schema_v1_1().expect("canonical schema");
        let loader = ConstitutionLoader::with_default_bounds(schema);
        CedarPlusEvaluator::with_default_bounds(loader)
    }

    fn make_request(
        action_kind: &str,
        principal: AgentId,
        resource: EntityUid,
    ) -> EvaluationRequest {
        EvaluationRequest {
            constitution_hash: placeholder_hash(),
            schema_version: "1.1.0".into(),
            action_kind: action_kind.into(),
            principal_id: principal,
            resource_uid: resource,
            context_attrs: HashMap::new(),
            entity_snapshot: EntitySnapshot::default(),
            current_wall_clock: "2026-05-15T00:00:00Z".into(),
            current_time_unix_ns: 0,
        }
    }

    #[tokio::test]
    async fn evaluate_without_activation_errors() {
        let evaluator = make_evaluator();
        let request = make_request(
            "SendEnvelope",
            AgentId::new(),
            EntityUid::new("Yutha::Agent", "00000000000000000000000000000000"),
        );
        let err = evaluator.evaluate(request).await.unwrap_err();
        assert!(matches!(err, CedarPlusError::ConstitutionUnresolved(_)));
    }

    #[tokio::test]
    async fn entity_count_bound_exceeded() {
        let evaluator = make_evaluator();
        let constitution = make_constitution("permit (principal, action, resource);");
        evaluator.activate(constitution).await.expect("activates");

        let mut snapshot = EntitySnapshot::default();
        for i in 0..1001 {
            snapshot.entities.push(crate::eval::EntityRecord {
                uid: EntityUid::new("Yutha::Agent", format!("agent-{i}")),
                attrs: HashMap::new(),
                parents: Vec::new(),
            });
        }
        let request = EvaluationRequest {
            entity_snapshot: snapshot,
            ..make_request(
                "SendEnvelope",
                AgentId::new(),
                EntityUid::new("Yutha::Agent", "00000000000000000000000000000000"),
            )
        };
        let err = evaluator.evaluate(request).await.unwrap_err();
        assert!(matches!(
            err,
            CedarPlusError::EvaluationBoundExceeded(EvalBoundReason::EntityStoreSize)
        ));
    }

    #[tokio::test]
    async fn constitution_hash_mismatch_unresolved() {
        let evaluator = make_evaluator();
        let constitution = make_constitution("permit (principal, action, resource);");
        evaluator.activate(constitution).await.expect("activates");

        let other_hash = Hash::new(HashAlgorithm::Sha256, vec![0xFFu8; 32]).unwrap();
        let request = EvaluationRequest {
            constitution_hash: other_hash,
            ..make_request(
                "SendEnvelope",
                AgentId::new(),
                EntityUid::new("Yutha::Agent", "00000000000000000000000000000000"),
            )
        };
        let err = evaluator.evaluate(request).await.unwrap_err();
        assert!(matches!(err, CedarPlusError::ConstitutionUnresolved(_)));
    }

    // NOTE(F8): a full Layer A round-trip test (permit / forbid /
    // no-permit) requires a request that satisfies the schema's
    // entity-existence rules. v1.1 schema requires the principal's
    // Swarm to exist in the entity store (because Agent is declared
    // `in [Swarm]`), so a minimal valid request needs at least a
    // synthetic Swarm entity. F8 builds the test fixtures alongside
    // the engine-eval layer; F7's coverage stops at the structural
    // paths (activation, sandbox bounds, constitution-hash matching).
}
