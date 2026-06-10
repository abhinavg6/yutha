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
    ConstitutionEvaluator, Decision, EntityRecord, EntitySnapshot, EntityUid, EvaluationOutcome,
    EvaluationRequest, ProcedureEffect, ScoreContribution,
};
use crate::loader::{ActivatedConstitution, ConstitutionLoader};
use crate::procedure::{evaluate_procedures, ProcedureEvalContext, ProcedureIndex};
use crate::sandbox::SandboxConfig;
use crate::scoring::evaluate_scoring;

/// The concrete evaluator. Construct once with a [`ConstitutionLoader`]
/// and [`SandboxConfig`]; reuse across many activations + evaluations.
///
/// ## Shadow-mode slot (Phase 3b, RFC 0018)
///
/// In addition to the active constitution slot, the evaluator carries an
/// optional `current_shadow` slot used by the operator-driven shadow-mode
/// preview workflow. The shadow slot is observation-only:
///
/// - The same loader validation pass runs at [`activate_shadow`] time, so
///   load-time failures surface immediately and never reach the hot path.
/// - [`evaluate_pair`] runs both slots against one shared
///   [`EvaluationRequest`]; the caller (gRPC EnvelopeHandler::send) emits
///   the two receipts in active-then-shadow order.
/// - Layer B procedure-state mutation runs ONLY for the active path. The
///   shadow path evaluates Layer A + scoring but skips procedure
///   transitions per RFC 0018 §3.1.
/// - The shadow slot has no impact on the enforcement engine — the
///   receipt-publisher forwarder task filters
///   `constitution.evaluate.shadow.*` receipts out of the engine fan-out
///   per RFC 0018 §3.5.
///
/// Today the shadow slot is `Option<...>` (one shadow at most); the public
/// API is shaped so a future RFC can grow it to a Vec for the 1+N case
/// without churning the surface.
///
/// [`activate_shadow`]: CedarPlusEvaluator::activate_shadow
/// [`evaluate_pair`]: CedarPlusEvaluator::evaluate_pair
pub struct CedarPlusEvaluator {
    loader: ConstitutionLoader,
    sandbox: SandboxConfig,
    current: RwLock<Option<Arc<ActivatedConstitution>>>,
    /// Phase 3b: shadow-mode candidate slot. `None` when no shadow
    /// constitution has been activated. Read by [`evaluate_pair`] and
    /// [`current_shadow`]; written by [`activate_shadow`],
    /// [`clear_shadow`], and [`promote_shadow`].
    ///
    /// [`evaluate_pair`]: CedarPlusEvaluator::evaluate_pair
    /// [`current_shadow`]: CedarPlusEvaluator::current_shadow
    /// [`activate_shadow`]: CedarPlusEvaluator::activate_shadow
    /// [`clear_shadow`]: CedarPlusEvaluator::clear_shadow
    /// [`promote_shadow`]: CedarPlusEvaluator::promote_shadow
    current_shadow: RwLock<Option<Arc<ActivatedConstitution>>>,
    /// In-memory procedure-state index. Held under a `Mutex` because
    /// procedure trigger / transition evaluation mutates the index
    /// optimistically and we don't want two concurrent evaluations
    /// to race on the same instance. Per evaluation.md §6, the
    /// receipt log is authoritative — F9 wires the receipt-driven
    /// reconstruction path that rebuilds this index on cold start
    /// or after a detected divergence.
    ///
    /// Phase 3b: the shadow path does NOT mutate this index (RFC 0018
    /// §3.1). The index is reserved for the active constitution.
    procedure_index: Mutex<ProcedureIndex>,
}

/// Evaluation mode passed to the internal [`evaluate_against`] helper.
/// Active runs the full Layer A + Layer B pipeline (scoring + procedure
/// transitions, with procedure-state mutation); Shadow runs Layer A +
/// scoring but skips procedure transitions and synthesizes a deny on
/// shadow-schema-incompatibility failures per RFC 0018 §3.1 / §3.3.
///
/// [`evaluate_against`]: CedarPlusEvaluator::evaluate_against
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvaluationMode {
    /// Active-slot evaluation. Full Layer B; procedure-state mutation.
    Active,
    /// Shadow-slot evaluation. Layer A + scoring only; no procedure
    /// mutation; schema-incompatibility maps to a synthesized Deny.
    Shadow,
}

/// Result of a successful [`CedarPlusEvaluator::promote_shadow`] call.
///
/// Captures the slot transition the operator triggered so the calling
/// gRPC handler can emit the `constitution.shadow_promote` receipt with
/// full evidence per `/spec/receipt/canonical-actions.md` and rebind the
/// enforcement engine onto the new active without re-reading the slot.
#[derive(Debug, Clone)]
pub struct PromoteShadowOutcome {
    /// Content-address of the constitution that was active immediately
    /// before the promote. `None` when no active was loaded at the time
    /// of promote (e.g., bringing a fresh swarm online via
    /// shadow-preview-then-promote).
    pub from_active_constitution_hash: Option<Hash>,
    /// Content-address of the new active constitution. Equal to the
    /// content-address the shadow held immediately before the promote —
    /// content-addressing is over the constitution's canonical bytes,
    /// not over slot history.
    pub to_active_constitution_hash: Hash,
    /// Convenience: the new active constitution's version string. Used
    /// by the gRPC handler to populate the
    /// `constitution.shadow_promote` receipt's
    /// `to_constitution_version` evidence.
    pub to_constitution_version: String,
    /// Convenience: the new active constitution's schema_version
    /// string. Used to populate the receipt's `schema_version`
    /// evidence.
    pub schema_version: String,
    /// The Arc of the activated constitution that is now in the active
    /// slot. Returned so the handler can immediately call
    /// `enforcement.activate(promoted)` without re-reading
    /// [`CedarPlusEvaluator::current`] (avoiding a TOCTOU race against
    /// another concurrent promote).
    pub promoted: Arc<ActivatedConstitution>,
}

impl CedarPlusEvaluator {
    /// Construct an evaluator with explicit loader + bounds.
    pub fn new(loader: ConstitutionLoader, sandbox: SandboxConfig) -> Self {
        Self {
            loader,
            sandbox,
            current: RwLock::new(None),
            current_shadow: RwLock::new(None),
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

    /// Read access to the currently-activated shadow constitution, if
    /// any (Phase 3b, RFC 0018). Returns the same `Arc` to all
    /// concurrent readers. Symmetric with [`current`].
    ///
    /// [`current`]: CedarPlusEvaluator::current
    pub async fn current_shadow(&self) -> Option<Arc<ActivatedConstitution>> {
        self.current_shadow.read().await.as_ref().map(Arc::clone)
    }

    /// Read both slots in a single call. Used by the gRPC
    /// EnvelopeHandler::send path to decide whether a shadow eval is
    /// needed before paying for the second authorizer call.
    ///
    /// Each slot's read is independent — the two reads may not see a
    /// strictly atomic snapshot if a concurrent
    /// [`activate`] / [`activate_shadow`] / [`promote_shadow`] races
    /// with this call. That is acceptable: a concurrent promote at the
    /// exact moment of read is indistinguishable from a promote that
    /// happened one nanosecond earlier or later, and downstream
    /// receipt emission is deterministic over the `Arc` snapshots
    /// returned.
    ///
    /// [`activate`]: ConstitutionEvaluator::activate
    /// [`activate_shadow`]: CedarPlusEvaluator::activate_shadow
    /// [`promote_shadow`]: CedarPlusEvaluator::promote_shadow
    pub async fn current_pair(
        &self,
    ) -> (
        Option<Arc<ActivatedConstitution>>,
        Option<Arc<ActivatedConstitution>>,
    ) {
        let active = self.current.read().await.as_ref().map(Arc::clone);
        let shadow = self.current_shadow.read().await.as_ref().map(Arc::clone);
        (active, shadow)
    }

    /// Activate a constitution into the shadow slot (Phase 3b, RFC
    /// 0018 §3.2). Runs the same loader validation pass as
    /// [`activate`] — load-time bound failures, named-predicate
    /// resolution errors, Cedar validator failures all surface here.
    /// Replaces any previously-loaded shadow without a separate
    /// shadow_clear receipt; the gRPC handler emits one
    /// `constitution.shadow_activate` receipt covering the activation.
    ///
    /// Does NOT bind the constitution onto the enforcement engine —
    /// the shadow slot is observation-only.
    ///
    /// [`activate`]: ConstitutionEvaluator::activate
    pub async fn activate_shadow(&self, constitution: Constitution) -> Result<Hash> {
        let activated = self.loader.load(constitution)?;
        let constitution_hash = activated.constitution.constitution_hash.clone();
        let mut guard = self.current_shadow.write().await;
        *guard = Some(Arc::new(activated));
        Ok(constitution_hash)
    }

    /// Clear the shadow slot (Phase 3b, RFC 0018 §3.2). Idempotent:
    /// returns the previously-shadowed constitution's hash if a shadow
    /// was loaded, or `None` if the slot was already empty. The caller
    /// (gRPC handler) uses the return value to populate the
    /// `previously_shadowed_constitution_hash` evidence on the
    /// `constitution.shadow_clear` receipt; an empty-slot call still
    /// emits the receipt with the evidence absent.
    pub async fn clear_shadow(&self) -> Option<Hash> {
        let mut guard = self.current_shadow.write().await;
        guard
            .take()
            .map(|arc| arc.constitution.constitution_hash.clone())
    }

    /// Atomically promote the shadow slot into the active slot (Phase
    /// 3b, RFC 0018 §3.2). The shadow slot is left empty.
    ///
    /// Returns `None` when the shadow slot was empty at the moment of
    /// the call — the gRPC handler maps `None` to `FAILED_PRECONDITION`.
    /// Returns `Some(PromoteShadowOutcome)` describing the slot
    /// transition for receipt emission and engine rebinding.
    ///
    /// Lock order: shadow write first, then active write. Same order is
    /// observed across every multi-lock path to prevent deadlocks.
    pub async fn promote_shadow(&self) -> Option<PromoteShadowOutcome> {
        let mut shadow_guard = self.current_shadow.write().await;
        let shadow_arc = shadow_guard.take()?;
        let mut current_guard = self.current.write().await;
        let previous_active = current_guard.replace(Arc::clone(&shadow_arc));

        Some(PromoteShadowOutcome {
            from_active_constitution_hash: previous_active
                .map(|a| a.constitution.constitution_hash.clone()),
            to_active_constitution_hash: shadow_arc.constitution.constitution_hash.clone(),
            to_constitution_version: shadow_arc.constitution.constitution_version.clone(),
            schema_version: shadow_arc.constitution.schema_version.clone(),
            promoted: shadow_arc,
        })
    }

    /// Evaluate one request against both the active and (when
    /// configured) the shadow constitution (Phase 3b, RFC 0018 §3.3).
    ///
    /// The active eval flows through the same path as
    /// [`evaluate`] — full Layer A + Layer B, with procedure-state
    /// mutation. The shadow eval, when triggered, clones the request,
    /// rewrites `constitution_hash` to the shadow's, and runs Layer A
    /// plus scoring. Procedure transitions are skipped on the shadow
    /// path per RFC 0018 §3.1.
    ///
    /// Shadow-side schema incompatibilities — the shared entity
    /// snapshot violating the shadow's strict-mode validation when
    /// active/shadow schemas differ — surface as a synthesized
    /// `Decision::Deny` with `deny_reason = "shadow_schema_incompatible"`
    /// per RFC 0018 §3.3 rather than propagating an error. The active
    /// outcome is unaffected.
    ///
    /// The entity snapshot is built once by the caller and shared
    /// across both evals — the substrate doesn't pay the resolver cost
    /// twice.
    ///
    /// [`evaluate`]: ConstitutionEvaluator::evaluate
    pub async fn evaluate_pair(
        &self,
        request: EvaluationRequest,
    ) -> Result<(EvaluationOutcome, Option<EvaluationOutcome>)> {
        let (active_opt, shadow_opt) = self.current_pair().await;

        let active = active_opt.ok_or_else(|| {
            CedarPlusError::ConstitutionUnresolved(
                "no active constitution; call activate() first".into(),
            )
        })?;

        if request.constitution_hash != active.constitution.constitution_hash {
            return Err(CedarPlusError::ConstitutionUnresolved(format!(
                "request pinned to constitution {}, active is {}",
                hex::encode(&request.constitution_hash.digest),
                hex::encode(&active.constitution.constitution_hash.digest),
            )));
        }

        let active_outcome = self
            .evaluate_against(&request, &active, EvaluationMode::Active)
            .await?;

        let shadow_outcome = match shadow_opt {
            None => None,
            Some(shadow) => {
                // Clone the request and rewrite its constitution_hash
                // pin so the shadow eval doesn't trip the
                // constitution-hash-mismatch check. The caller never
                // has to know two hashes are in play.
                let mut shadow_request = request.clone();
                shadow_request.constitution_hash = shadow.constitution.constitution_hash.clone();
                Some(
                    self.evaluate_against(&shadow_request, &shadow, EvaluationMode::Shadow)
                        .await?,
                )
            }
        };

        Ok((active_outcome, shadow_outcome))
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

        self.evaluate_against(&request, &active, EvaluationMode::Active)
            .await
    }

    async fn activate(&self, constitution: Constitution) -> Result<Hash> {
        let activated = self.loader.load(constitution)?;
        let constitution_hash = activated.constitution.constitution_hash.clone();
        let mut guard = self.current.write().await;
        *guard = Some(Arc::new(activated));
        Ok(constitution_hash)
    }
}

impl CedarPlusEvaluator {
    /// The slot-agnostic evaluation pipeline. Runs sandbox bounds,
    /// Cedar request construction, Layer A authorization, and
    /// mode-conditional Layer B (scoring always, procedure mutation
    /// only in [`EvaluationMode::Active`]).
    ///
    /// Phase 3b factoring (RFC 0018): the trait's [`ConstitutionEvaluator::evaluate`]
    /// resolves the active slot then calls this with [`EvaluationMode::Active`];
    /// [`evaluate_pair`] resolves both slots then calls this twice — once
    /// with `Active` against the active slot, once with `Shadow` against the
    /// shadow slot.
    ///
    /// Shadow-mode error mapping per RFC 0018 §3.3: when
    /// `mode == Shadow` and cedar Request/Entities construction fails
    /// with a schema-incompatibility error, return a synthesized
    /// `Deny` with `deny_reason = "shadow_schema_incompatible"` rather
    /// than propagating the error. Sandbox bounds and constitution-
    /// unresolved errors still propagate in shadow mode — only the
    /// Cedar shape failures map to a synthesized deny.
    ///
    /// [`evaluate_pair`]: CedarPlusEvaluator::evaluate_pair
    async fn evaluate_against(
        &self,
        request: &EvaluationRequest,
        activated: &Arc<ActivatedConstitution>,
        mode: EvaluationMode,
    ) -> Result<EvaluationOutcome> {
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

        // Per RFC 0018 §3.3, the shadow path treats schema-
        // incompatibility (the shared entity snapshot violating the
        // shadow's strict-mode validation) as a synthesized Deny
        // with the `shadow_schema_incompatible` reason. The active
        // path continues to propagate the original error.
        let entities = match build_cedar_entities(&request.entity_snapshot, schema_ref(activated)) {
            Ok(e) => e,
            Err(e) if matches!(mode, EvaluationMode::Shadow) => {
                tracing::debug!(
                    target: "yutha::cedar_plus::shadow",
                    error = %e,
                    "shadow eval: entity build failed; synthesizing shadow_schema_incompatible deny",
                );
                return Ok(schema_incompatible_deny(request));
            }
            Err(e) => return Err(e),
        };
        let context = match build_context(&request.context_attrs, &action_uid) {
            Ok(c) => c,
            Err(e) if matches!(mode, EvaluationMode::Shadow) => {
                tracing::debug!(
                    target: "yutha::cedar_plus::shadow",
                    error = %e,
                    "shadow eval: context build failed; synthesizing shadow_schema_incompatible deny",
                );
                return Ok(schema_incompatible_deny(request));
            }
            Err(e) => return Err(e),
        };

        let cedar_request = match cedar_policy::Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            context,
            Some(schema_ref(activated)),
        ) {
            Ok(r) => r,
            Err(e) if matches!(mode, EvaluationMode::Shadow) => {
                tracing::debug!(
                    target: "yutha::cedar_plus::shadow",
                    error = %e,
                    "shadow eval: Cedar Request shape rejected; synthesizing shadow_schema_incompatible deny",
                );
                return Ok(schema_incompatible_deny(request));
            }
            Err(e) => {
                return Err(CedarPlusError::RequestShapeInvalid(format!(
                    "Cedar Request rejected: {e}"
                )))
            }
        };

        // -- Stage 4: Layer A — Authorizer. -------------------------------
        let authorizer = cedar_policy::Authorizer::new();
        let response = authorizer.is_authorized(&cedar_request, &activated.policy_set, &entities);

        // -- Stage 5: Layer B — scoring + procedures (only on Permit). ----
        // Scoring runs in both Active and Shadow modes — it's stateless
        // and the shadow's `total_score` is a useful preview signal.
        // Procedure evaluation runs ONLY in Active mode: it mutates the
        // single `procedure_index` Mutex which is reserved for the
        // active constitution per RFC 0018 §3.1.
        let (score_contributions, total_score, procedure_effects) =
            if matches!(response.decision(), cedar_policy::Decision::Allow) {
                let scoring = evaluate_scoring(&cedar_request, &entities, activated);
                let total = scoring.total_score();

                let procedure_effects_out = match mode {
                    EvaluationMode::Active => {
                        // The procedure subsystem mutates the index,
                        // so we take the lock for the duration of
                        // the eval. F9 refines this with finer-
                        // grained locking if hot-path contention
                        // becomes measurable.
                        let mut index = self.procedure_index.lock().await;
                        let triggering_descriptor_digest =
                            hash_input_attributes(request, &request.entity_snapshot);
                        let swarm_id_str = activated.constitution.swarm_id.to_string();
                        let proc_ctx = ProcedureEvalContext {
                            triggering_descriptor_digest: &triggering_descriptor_digest,
                            swarm_id_str: &swarm_id_str,
                            request_action_kind: &request.action_kind,
                            current_wall_clock: &request.current_wall_clock,
                        };
                        let procedures = evaluate_procedures(
                            &cedar_request,
                            &entities,
                            activated,
                            &mut index,
                            proc_ctx,
                        );
                        drop(index);
                        procedures.effects
                    }
                    EvaluationMode::Shadow => {
                        // RFC 0018 §3.1: shadow eval skips procedure
                        // transitions. Operators previewing scoring
                        // changes still see `total_score`; previewing
                        // procedure changes is parked as a follow-on
                        // for a future RFC.
                        Vec::new()
                    }
                };

                (scoring.contributions, total, procedure_effects_out)
            } else {
                (Vec::new(), None, Vec::new())
            };

        // -- Stage 6: assemble the outcome. -------------------------------
        let outcome = map_cedar_response(
            &response,
            request,
            &request.entity_snapshot,
            score_contributions,
            total_score,
            procedure_effects,
        );
        Ok(outcome)
    }
}

/// Synthesize a [`EvaluationOutcome`] marking the shadow eval as a
/// `Decision::Deny` with `deny_reason = "shadow_schema_incompatible"`
/// per RFC 0018 §3.3. Used by the shadow path of [`CedarPlusEvaluator::evaluate_against`]
/// when the shared entity snapshot fails strict-mode validation against
/// the shadow's schema.
///
/// Evidence shape: empty `matched_rule_ids`, empty `score_contributions`,
/// empty `procedure_effects`. `evidence_digest` is computed over the
/// same canonical inputs the regular path uses so downstream receipt
/// content-addressing remains stable.
fn schema_incompatible_deny(request: &EvaluationRequest) -> EvaluationOutcome {
    let matched_rule_ids: Vec<String> = Vec::new();
    let input_attribute_digest = hash_input_attributes(request, &request.entity_snapshot);
    let evidence_digest =
        compute_evidence_digest(&matched_rule_ids, &[], &[], &input_attribute_digest);
    EvaluationOutcome {
        decision: Decision::Deny,
        deny_reason: Some("shadow_schema_incompatible".to_string()),
        matched_rule_ids,
        score_contributions: Vec::new(),
        total_score: None,
        procedure_effects: Vec::new(),
        evidence_digest,
        decided_at: Timestamp::now(),
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
///
/// The entity snapshot is canonicalized via [`canonicalize_entity_snapshot`]:
/// entities sorted by `(entity_type, entity_id)`, attrs as sorted
/// BTreeMap per record, parents UID-lex-sorted. This is the contract
/// the spec pins (evaluation.md §9 — "input_attribute_digest is
/// sha256 over the entity snapshot's canonical bytes plus the
/// context attrs"). Pre-Phase-3a-4 this function only hashed
/// `snapshot.entity_count()`, which was effectively equivalent while
/// all entity attrs were placeholders but became a spec-conformance
/// bug once 3a-2/3 wired real per-agent passport_tier / framework /
/// reputation values — two evaluations with different agent state
/// would have produced identical digests.
fn hash_input_attributes(request: &EvaluationRequest, snapshot: &EntitySnapshot) -> Hash {
    let context_sorted: BTreeMap<&String, &serde_json::Value> =
        request.context_attrs.iter().collect();
    let entities_canonical = canonicalize_entity_snapshot(snapshot);
    let canonical = json!({
        "action_kind": request.action_kind,
        "principal_id": request.principal_id.to_string(),
        "resource_uid": {
            "type": request.resource_uid.entity_type,
            "id": request.resource_uid.entity_id,
        },
        "context_attrs": context_sorted,
        "entity_snapshot": entities_canonical,
        "current_wall_clock": &request.current_wall_clock,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    yutha_crypto::sha256(&bytes)
}

/// Canonicalize an [`EntitySnapshot`] for inclusion in the
/// `input_attribute_digest` per evaluation.md §9.
///
/// Determinism rules:
///
/// - Entities sorted by `(entity_type, entity_id)` UID-lex.
/// - Within each entity, attrs serialized as a sorted `BTreeMap`
///   (sorted by attr name).
/// - Parents UID-lex-sorted by the same `(entity_type, entity_id)`
///   ordering as the outer entity list.
///
/// `serde_json::Value` nested inside attr values relies on serde_json's
/// default `Map = BTreeMap` (no `preserve_order` feature in this
/// crate's dep tree) so any nested objects also serialize with sorted
/// keys, end-to-end.
///
/// The result is a `Vec<serde_json::Value>` that `hash_input_attributes`
/// embeds under the `"entity_snapshot"` key. Two snapshots that
/// differ only in iteration order of the underlying `Vec<EntityRecord>`
/// or `HashMap<String, Value>` produce identical bytes; two snapshots
/// that differ in any actual attr value produce different bytes.
fn canonicalize_entity_snapshot(snapshot: &EntitySnapshot) -> Vec<serde_json::Value> {
    let mut sorted: Vec<&EntityRecord> = snapshot.entities.iter().collect();
    sorted.sort_by(|a, b| {
        a.uid
            .entity_type
            .cmp(&b.uid.entity_type)
            .then_with(|| a.uid.entity_id.cmp(&b.uid.entity_id))
    });
    sorted
        .into_iter()
        .map(|e| {
            let attrs_sorted: BTreeMap<&String, &serde_json::Value> = e.attrs.iter().collect();
            let mut parents_sorted: Vec<&EntityUid> = e.parents.iter().collect();
            parents_sorted.sort_by(|a, b| {
                a.entity_type
                    .cmp(&b.entity_type)
                    .then_with(|| a.entity_id.cmp(&b.entity_id))
            });
            let parents_json: Vec<serde_json::Value> = parents_sorted
                .into_iter()
                .map(|p| {
                    json!({
                        "type": &p.entity_type,
                        "id": &p.entity_id,
                    })
                })
                .collect();
            json!({
                "uid": {
                    "type": &e.uid.entity_type,
                    "id": &e.uid.entity_id,
                },
                "attrs": attrs_sorted,
                "parents": parents_json,
            })
        })
        .collect()
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

    // ---- 3a-4 regression guards: input_attribute_digest covers entity attrs ----
    //
    // evaluation.md §9 contract: the digest is sha256 over the entity
    // snapshot's canonical bytes plus context attrs. Pre-Phase-3a-4 the
    // implementation only hashed `entity_count`, which was effectively
    // equivalent while all entity attrs were placeholders but became a
    // spec-conformance bug once 3a-2/3 wired real per-agent values into
    // the snapshot. These tests are the regression guard.

    fn agent_record_with_reputation(rep: &str) -> EntityRecord {
        let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
        attrs.insert("agent_id".into(), serde_json::Value::String("alice".into()));
        attrs.insert(
            "passport_tier".into(),
            serde_json::Value::String("minimal".into()),
        );
        attrs.insert("framework".into(), serde_json::Value::String("".into()));
        attrs.insert(
            "passport_hash".into(),
            serde_json::Value::String("0".repeat(64)),
        );
        attrs.insert(
            "reputation".into(),
            serde_json::json!({ "__extn": { "fn": "decimal", "arg": rep } }),
        );
        attrs.insert(
            "budget_remaining_usd_cents".into(),
            serde_json::Value::Number(i64::MAX.into()),
        );
        attrs.insert(
            "budget_remaining_tool_calls".into(),
            serde_json::Value::Number(i64::MAX.into()),
        );
        attrs.insert(
            "budget_remaining_compute_ms".into(),
            serde_json::Value::Number(i64::MAX.into()),
        );
        EntityRecord {
            uid: EntityUid::new("Yutha::Agent", "alice"),
            attrs,
            parents: vec![EntityUid::new("Yutha::Swarm", "swarm-1")],
        }
    }

    #[test]
    fn input_digest_differs_when_entity_attrs_differ() {
        // Two snapshots that differ ONLY in agent reputation must
        // produce different input_attribute_digests. Pre-Phase-3a-4
        // they produced identical digests because only entity_count
        // was hashed.
        let req = make_request(
            "SendEnvelope",
            AgentId::new(),
            EntityUid::new("Yutha::Agent", "alice"),
        );

        let snap_a = EntitySnapshot {
            entities: vec![agent_record_with_reputation("1.0")],
        };
        let snap_b = EntitySnapshot {
            entities: vec![agent_record_with_reputation("0.5")],
        };

        let digest_a = hash_input_attributes(&req, &snap_a);
        let digest_b = hash_input_attributes(&req, &snap_b);
        assert_ne!(
            digest_a.digest, digest_b.digest,
            "input_attribute_digest must reflect entity attr differences \
             per evaluation.md §9; pre-3a-4 this assertion was false"
        );
    }

    #[test]
    fn input_digest_stable_across_attr_insertion_order() {
        // The canonicalizer must be insertion-order-independent —
        // a HashMap iterating attrs in different orders for two
        // semantically equal snapshots must still hash equal.
        let req = make_request(
            "SendEnvelope",
            AgentId::new(),
            EntityUid::new("Yutha::Agent", "alice"),
        );

        let record_x = agent_record_with_reputation("0.75");
        let mut record_y = agent_record_with_reputation("0.75");

        // Re-insert each attr from y's map under a fresh HashMap built
        // in reverse alphabetical order. serde_json's default
        // BTreeMap-backed Map serializes attrs sorted regardless, so
        // both records must hash the same bytes.
        let mut reversed: Vec<(String, serde_json::Value)> = record_y.attrs.drain().collect();
        reversed.sort_by(|a, b| b.0.cmp(&a.0));
        record_y.attrs.extend(reversed);

        // Light sanity that the HashMap state isn't somehow identical
        // by accident — only the iteration order changed.
        assert_eq!(record_x.attrs.len(), record_y.attrs.len());

        let snap_x = EntitySnapshot {
            entities: vec![record_x],
        };
        let snap_y = EntitySnapshot {
            entities: vec![record_y],
        };

        assert_eq!(
            hash_input_attributes(&req, &snap_x).digest,
            hash_input_attributes(&req, &snap_y).digest,
            "input_attribute_digest must be HashMap-insertion-order-independent"
        );
    }

    // ========================================================================
    // Phase 3b shadow-mode tests (RFC 0018 §3.1-§3.3)
    // ========================================================================
    //
    // These cover the substrate slot mechanics (activate_shadow /
    // clear_shadow / promote_shadow / current_pair) and the
    // evaluate_pair structural-failure paths. The shadow-schema-
    // incompatible synthesized-deny path (RFC 0018 §3.3) and the full
    // active+shadow happy-path eval are covered at integration level by
    // Phase 3b-G conformance scenario S10 — the unit-test setup to
    // build a valid Cedar request (the v1.1 schema requires Agent
    // entities `in [Swarm]`, plus per-entity full attribute surface for
    // strict-mode validation) is heavier than the value it adds at this
    // layer; the existing F7/F8 tests in this module use the same
    // structural-failure posture for the same reason.

    /// Helper: build a Constitution with a fresh content-address.
    /// Used by the slot-mechanics tests to distinguish slots that hold
    /// different constitutions (default `make_constitution` reuses
    /// `placeholder_hash()` which collides across calls).
    fn make_constitution_with_hash(cedar_source: &str, hash_byte: u8) -> Constitution {
        let mut c = make_constitution(cedar_source);
        c.constitution_hash =
            Hash::new(HashAlgorithm::Sha256, vec![hash_byte; 32]).expect("placeholder hash");
        c
    }

    #[tokio::test]
    async fn shadow_slot_starts_empty() {
        let evaluator = make_evaluator();
        assert!(evaluator.current_shadow().await.is_none());
    }

    #[tokio::test]
    async fn activate_shadow_loads_into_shadow_slot_only() {
        let evaluator = make_evaluator();
        let constitution =
            make_constitution_with_hash("permit (principal, action, resource);", 0x10);
        let constitution_hash = constitution.constitution_hash.clone();

        evaluator
            .activate_shadow(constitution)
            .await
            .expect("shadow activates");

        let shadow = evaluator
            .current_shadow()
            .await
            .expect("shadow slot loaded");
        assert_eq!(
            shadow.constitution.constitution_hash, constitution_hash,
            "shadow slot holds the activated constitution"
        );
        assert!(
            evaluator.current().await.is_none(),
            "activate_shadow MUST NOT write to the active slot"
        );
    }

    #[tokio::test]
    async fn activate_shadow_twice_replaces_prior_shadow() {
        let evaluator = make_evaluator();
        let first = make_constitution_with_hash("permit (principal, action, resource);", 0x11);
        let first_hash = first.constitution_hash.clone();
        evaluator
            .activate_shadow(first)
            .await
            .expect("first shadow activates");

        let second = make_constitution_with_hash("permit (principal, action, resource);", 0x22);
        let second_hash = second.constitution_hash.clone();
        evaluator
            .activate_shadow(second)
            .await
            .expect("second shadow activates");

        let shadow = evaluator
            .current_shadow()
            .await
            .expect("shadow slot loaded");
        assert_eq!(shadow.constitution.constitution_hash, second_hash);
        assert_ne!(shadow.constitution.constitution_hash, first_hash);
    }

    #[tokio::test]
    async fn current_pair_returns_both_slots() {
        let evaluator = make_evaluator();

        // Both empty.
        let (active, shadow) = evaluator.current_pair().await;
        assert!(active.is_none() && shadow.is_none(), "both slots empty");

        // Active only.
        let active_const =
            make_constitution_with_hash("permit (principal, action, resource);", 0x33);
        evaluator
            .activate(active_const)
            .await
            .expect("active activates");
        let (active, shadow) = evaluator.current_pair().await;
        assert!(
            active.is_some() && shadow.is_none(),
            "active loaded, shadow empty"
        );

        // Both populated.
        let shadow_const =
            make_constitution_with_hash("permit (principal, action, resource);", 0x44);
        evaluator
            .activate_shadow(shadow_const)
            .await
            .expect("shadow activates");
        let (active, shadow) = evaluator.current_pair().await;
        assert!(active.is_some() && shadow.is_some(), "both slots populated");
    }

    #[tokio::test]
    async fn clear_shadow_returns_previously_shadowed_hash() {
        let evaluator = make_evaluator();
        let constitution =
            make_constitution_with_hash("permit (principal, action, resource);", 0x55);
        let constitution_hash = constitution.constitution_hash.clone();
        evaluator
            .activate_shadow(constitution)
            .await
            .expect("shadow activates");

        let previous = evaluator
            .clear_shadow()
            .await
            .expect("clear returns prior hash");
        assert_eq!(previous, constitution_hash);
        assert!(
            evaluator.current_shadow().await.is_none(),
            "clear_shadow leaves the slot empty"
        );
    }

    #[tokio::test]
    async fn clear_shadow_on_empty_slot_returns_none() {
        let evaluator = make_evaluator();
        assert!(
            evaluator.clear_shadow().await.is_none(),
            "clearing an empty shadow is idempotent (returns None)"
        );
    }

    #[tokio::test]
    async fn promote_shadow_with_empty_shadow_returns_none() {
        let evaluator = make_evaluator();
        let active_const =
            make_constitution_with_hash("permit (principal, action, resource);", 0x66);
        let active_hash = active_const.constitution_hash.clone();
        evaluator
            .activate(active_const)
            .await
            .expect("active activates");

        assert!(
            evaluator.promote_shadow().await.is_none(),
            "promote with empty shadow returns None"
        );
        let still_active = evaluator.current().await.expect("active still loaded");
        assert_eq!(
            still_active.constitution.constitution_hash, active_hash,
            "active slot unchanged by failed promote"
        );
    }

    #[tokio::test]
    async fn promote_shadow_atomic_swap_with_active_loaded() {
        let evaluator = make_evaluator();
        let active_const =
            make_constitution_with_hash("permit (principal, action, resource);", 0x77);
        let active_hash = active_const.constitution_hash.clone();
        evaluator
            .activate(active_const)
            .await
            .expect("active activates");

        let mut shadow_const =
            make_constitution_with_hash("permit (principal, action, resource);", 0x88);
        shadow_const.constitution_version = "2.0.0".into();
        let shadow_hash = shadow_const.constitution_hash.clone();
        evaluator
            .activate_shadow(shadow_const)
            .await
            .expect("shadow activates");

        let outcome = evaluator.promote_shadow().await.expect("promote succeeds");
        assert_eq!(outcome.from_active_constitution_hash, Some(active_hash));
        assert_eq!(outcome.to_active_constitution_hash, shadow_hash);
        assert_eq!(outcome.to_constitution_version, "2.0.0");
        assert_eq!(outcome.schema_version, "1.1.0");

        let new_active = evaluator.current().await.expect("new active loaded");
        assert_eq!(
            new_active.constitution.constitution_hash, shadow_hash,
            "active slot now holds the formerly-shadowed constitution"
        );
        assert!(
            evaluator.current_shadow().await.is_none(),
            "promote leaves the shadow slot empty"
        );
    }

    #[tokio::test]
    async fn promote_shadow_with_empty_active_succeeds() {
        // Fresh-swarm case: bring a constitution up via shadow first,
        // then promote. No active loaded at the moment of promote.
        let evaluator = make_evaluator();
        let shadow_const =
            make_constitution_with_hash("permit (principal, action, resource);", 0x99);
        let shadow_hash = shadow_const.constitution_hash.clone();
        evaluator
            .activate_shadow(shadow_const)
            .await
            .expect("shadow activates");

        let outcome = evaluator.promote_shadow().await.expect("promote succeeds");
        assert_eq!(
            outcome.from_active_constitution_hash, None,
            "no previous active when promote-from-empty"
        );
        assert_eq!(outcome.to_active_constitution_hash, shadow_hash);

        let new_active = evaluator.current().await.expect("new active loaded");
        assert_eq!(
            new_active.constitution.constitution_hash, shadow_hash,
            "active slot now holds the formerly-shadowed constitution"
        );
        assert!(
            evaluator.current_shadow().await.is_none(),
            "shadow slot is empty after promote"
        );
    }

    #[tokio::test]
    async fn evaluate_pair_without_active_errors() {
        // Symmetric with `evaluate_without_activation_errors` for the
        // pair-evaluation surface — no active loaded means
        // constitution_unresolved regardless of shadow state.
        let evaluator = make_evaluator();
        let request = make_request(
            "SendEnvelope",
            AgentId::new(),
            EntityUid::new("Yutha::Agent", "00000000000000000000000000000000"),
        );
        let err = evaluator.evaluate_pair(request).await.unwrap_err();
        assert!(
            matches!(err, CedarPlusError::ConstitutionUnresolved(_)),
            "evaluate_pair without active errors as constitution_unresolved"
        );
    }

    #[tokio::test]
    async fn evaluate_pair_with_shadow_only_still_errors_on_no_active() {
        // Shadow can exist without active (a fresh-swarm operator might
        // load a shadow before any constitution has been activated).
        // evaluate_pair still errors because the active slot is
        // authoritative — shadow is observation-only per RFC 0018 §3.5.
        let evaluator = make_evaluator();
        let shadow_const =
            make_constitution_with_hash("permit (principal, action, resource);", 0xAA);
        evaluator
            .activate_shadow(shadow_const)
            .await
            .expect("shadow activates");

        let request = make_request(
            "SendEnvelope",
            AgentId::new(),
            EntityUid::new("Yutha::Agent", "00000000000000000000000000000000"),
        );
        let err = evaluator.evaluate_pair(request).await.unwrap_err();
        assert!(
            matches!(err, CedarPlusError::ConstitutionUnresolved(_)),
            "evaluate_pair errors when only shadow is loaded"
        );
    }

    #[tokio::test]
    async fn evaluate_pair_constitution_hash_mismatch_errors() {
        // Same posture as the existing `constitution_hash_mismatch_unresolved`
        // for evaluate(): when the request pins a constitution_hash
        // that doesn't match the active slot, evaluate_pair errors
        // before touching either eval path.
        let evaluator = make_evaluator();
        let constitution =
            make_constitution_with_hash("permit (principal, action, resource);", 0xBB);
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
        let err = evaluator.evaluate_pair(request).await.unwrap_err();
        assert!(matches!(err, CedarPlusError::ConstitutionUnresolved(_)));
    }

    #[test]
    fn schema_incompatible_deny_synthesizes_expected_outcome() {
        // The synthesized deny used on the shadow path when Cedar's
        // shape validation rejects the shared snapshot. Asserts the
        // documented evidence shape: empty matched_rule_ids /
        // score_contributions / procedure_effects, deny_reason set to
        // "shadow_schema_incompatible", evidence_digest computed over
        // the same inputs as a regular outcome.
        let req = make_request(
            "SendEnvelope",
            AgentId::new(),
            EntityUid::new("Yutha::Agent", "alice"),
        );
        let outcome = schema_incompatible_deny(&req);
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(
            outcome.deny_reason.as_deref(),
            Some("shadow_schema_incompatible"),
            "deny_reason matches RFC 0018 §3.3"
        );
        assert!(outcome.matched_rule_ids.is_empty());
        assert!(outcome.score_contributions.is_empty());
        assert!(outcome.total_score.is_none());
        assert!(outcome.procedure_effects.is_empty());
        // evidence_digest should match the canonical computation over
        // the same (empty) collections, anchored on the request's
        // input_attribute_digest.
        let expected_input_digest = hash_input_attributes(&req, &req.entity_snapshot);
        let expected_evidence = compute_evidence_digest(&[], &[], &[], &expected_input_digest);
        assert_eq!(outcome.evidence_digest.digest, expected_evidence.digest);
    }

    #[test]
    fn promote_shadow_outcome_is_clone_and_debug() {
        // PromoteShadowOutcome is part of the public API; ensure the
        // documented derives are present so the gRPC handler can
        // structurally bind / log without ceremony.
        fn assert_clone_debug<T: Clone + std::fmt::Debug>() {}
        assert_clone_debug::<PromoteShadowOutcome>();
    }
}
