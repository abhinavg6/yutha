//! Replay engine for the Yutha control plane (Phase 3c, RFC 0018 §4).
//!
//! A [`ReplaySession`] previews a candidate constitution against a past
//! receipt window. Each session owns:
//!
//! - An isolated [`yutha_cedar_plus::EnforcementEngine`] instance —
//!   activated with the candidate. Engine state is independent of
//!   production; reputation deltas and quarantine flips here are
//!   invisible outside the session.
//! - A session-scoped [`yutha_receipt::ReceiptStore`] handle obtained
//!   from [`yutha_receipt::ReplayStore::session_store`]. Within-session
//!   appends are partitioned from production and from other replay
//!   sessions.
//! - The same [`yutha_passport::ControlPlaneIdentity`] production uses,
//!   so within-session receipts are signed identically.
//!
//! ## What MVP replay does (Phase 3c)
//!
//! Iterates a receipt window, feeds each receipt through the
//! candidate's engine via `on_receipt`, and emits the resulting
//! `enforcement.*` effects as session-scoped receipts. The operator
//! sees what the candidate's enforcement rules WOULD have flagged in
//! that window — "candidate constitution Y has a tighter rate-limit
//! enforcement rule than active X; show me which agents would have
//! tripped it in the past 24h."
//!
//! Per [RFC 0018 §4.3](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0018-shadow-mode-and-replay.md):
//!
//! - Replay receipts use the SAME canonical action-kinds as
//!   production. Distinguishability is via store membership +
//!   `replay_session_id` evidence marker.
//! - Causal predecessors form a session-internal chain — each step's
//!   replay receipts reference the previous step's, keeping graph
//!   walks self-contained within the session store.
//! - Replay receipts ARE signed by `ControlPlaneIdentity`.
//! - Replay receipts are NEVER sealed and NEVER anchor to Sui (RFC
//!   0018 §4.4 — by construction; the `AnchorDriver` only sees the
//!   production store).
//!
//! ## What MVP replay does NOT do (Phase 3c)
//!
//! Re-evaluating `constitution.evaluate.{pass,deny}` receipts against
//! the candidate's Cedar policy requires the original entity snapshot,
//! which is not preserved on production receipts. Cedar-side replay
//! is a follow-on phase. Today's MVP is engine-state replay:
//! enforcement-rule firings against the candidate's engine config.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod error;
pub mod session;

pub use error::ReplayError;
pub use session::{ReplaySession, ReplayStepOutcome, ReplayWindowOutcome};
