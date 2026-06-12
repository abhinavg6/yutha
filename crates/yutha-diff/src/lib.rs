//! Structural + behavioural diff for Yutha constitutions.
//!
//! Phase 3d / Pillar 1 (simulation + observability). Pure compute
//! crate — given two [`yutha_cedar_plus::Constitution`] artifacts,
//! returns a [`ConstitutionDiff`] that names every section-level
//! change between them. Behavioural diff (replay-driven) is composed
//! separately at the call site; this crate handles the structural
//! delta + the [`BehaviouralDiff`] data model.
//!
//! ## Layered shape
//!
//! - [`ConstitutionDiff`] — the top-level value. Carries five
//!   [`NamedItemsDiff`] sections (cedar policies, named predicates,
//!   scoring rules, procedures, enforcement rules) plus a
//!   schema-version pair and an optional [`BehaviouralDiff`].
//! - [`NamedItemsDiff<T>`] — generic add/remove/modify triple keyed
//!   by a name. Same shape across all five sections.
//! - [`diff::diff_constitutions`] — the structural-diff entry point.
//!   Pure; no I/O; no async.
//! - [`render`] — JSON / Markdown / HTML renderers consuming
//!   [`ConstitutionDiff`]. Each rendering format lives in its own
//!   submodule; the parent module re-exports the entry points.
//!
//! ## What this crate is NOT
//!
//! - Not a Cedar policy linter. It assumes both sides parse + load
//!   successfully through [`yutha_cedar_plus::ConstitutionLoader`].
//!   A constitution that fails to load is a bug in the constitution,
//!   not in the diff.
//! - Not a behavioural-diff engine. [`BehaviouralDiff`] is a data
//!   model; populating it requires running a replay session and is
//!   the call site's responsibility (see `yutha-ops diff
//!   --against-window`).
//! - Not stable on the JSON output schema. The output is internal
//!   tooling; consumers should pin the `yutha-diff` version they
//!   parse against.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod behavioural;
pub mod cedar;
pub mod diff;
pub mod error;
pub mod model;
pub mod render;

pub use behavioural::{BehaviouralDiff, ChainDivergence, ReceiptCountDelta};
pub use cedar::{CedarPolicyEffect, CedarPolicyEntry};
pub use diff::diff_constitutions;
pub use error::{DiffError, Result};
pub use model::{ConstitutionDiff, NamedItemChange, NamedItemsDiff};
pub use render::{
    render_html, render_json, render_markdown, render_to, render_to_string, OutputFormat,
};
