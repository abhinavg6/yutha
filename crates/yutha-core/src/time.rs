//! [`Timestamp`] — wall-clock + monotonic time pair.
//!
//! Mirrors `Timestamp` from
//! [`/spec/common.proto`](../../../spec/common.proto). Per the spec,
//! implementations MUST emit both fields. Spec-mandated comparison logic uses
//! `monotonic_ns`; observability and audit display use `wall_clock`.

use crate::error::{CoreError, Result};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Wall-clock + monotonic time pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Timestamp {
    /// RFC 3339 wall-clock string. Human-meaningful; not authoritative for
    /// ordering decisions. Example: `"2026-05-10T19:50:00.123456789Z"`.
    pub wall_clock: String,

    /// Nanoseconds since an implementation-defined monotonic epoch. Monotonic
    /// across a single process; the receipt store tolerates non-monotonic
    /// across process restart by relying on `causal_predecessors` for
    /// ordering.
    pub monotonic_ns: u64,
}

impl Timestamp {
    /// Construct directly from components. Validates the wall-clock is
    /// parseable RFC 3339.
    pub fn new(wall_clock: String, monotonic_ns: u64) -> Result<Self> {
        OffsetDateTime::parse(&wall_clock, &Rfc3339)
            .map_err(|e| CoreError::Timestamp(format!("invalid RFC 3339: {e}")))?;
        Ok(Self {
            wall_clock,
            monotonic_ns,
        })
    }

    /// Construct from the current time. Wall clock is the system clock;
    /// monotonic is `Instant`-derived nanoseconds since the process started.
    ///
    /// This is the recommended constructor in normal code paths.
    pub fn now() -> Self {
        let monotonic = monotonic_now_ns();
        let wall = wall_clock_now();
        Self {
            wall_clock: wall,
            monotonic_ns: monotonic,
        }
    }

    /// Compare two timestamps using monotonic_ns.
    ///
    /// **Intra-process use only.** `monotonic_ns` is process-local;
    /// comparing two timestamps that originated in different processes
    /// is undefined (see [`Self::wall_at_or_after`] and RFC 0008). Use
    /// this for causal-event sequencing inside a single control-plane
    /// process; use [`Self::wall_at_or_after`] / [`Self::wall_after`]
    /// for any check that involves a Timestamp minted in another
    /// process (capability windows, passport/envelope/bearer expiry).
    pub fn precedes(&self, other: &Self) -> bool {
        self.monotonic_ns < other.monotonic_ns
    }

    /// Parse `wall_clock` as RFC 3339. Returns `None` on malformed
    /// input; callers in bound-check positions MUST default-deny on
    /// `None` per RFC 0008. Exposed for the rare caller that needs
    /// the parsed `OffsetDateTime` directly; prefer
    /// [`Self::wall_at_or_after`] / [`Self::wall_after`] otherwise.
    pub fn parsed_wall_clock(&self) -> Option<OffsetDateTime> {
        OffsetDateTime::parse(&self.wall_clock, &Rfc3339).ok()
    }

    /// True iff `self`'s wall_clock is at or after `other`'s
    /// wall_clock (RFC 3339 comparison). Default-denies on malformed
    /// input — either side failing to parse returns `false`.
    ///
    /// Use this for cross-process bound checks (RFC 0008): cap
    /// validity windows, passport/envelope/bearer expiry. The
    /// intra-process variant is [`Self::precedes`] which uses
    /// `monotonic_ns`.
    pub fn wall_at_or_after(&self, other: &Self) -> bool {
        match (self.parsed_wall_clock(), other.parsed_wall_clock()) {
            (Some(a), Some(b)) => a >= b,
            _ => false,
        }
    }

    /// True iff `self`'s wall_clock is strictly after `other`'s
    /// wall_clock. Default-denies on malformed input. Companion to
    /// [`Self::wall_at_or_after`] for the half-open expiry case.
    pub fn wall_after(&self, other: &Self) -> bool {
        match (self.parsed_wall_clock(), other.parsed_wall_clock()) {
            (Some(a), Some(b)) => a > b,
            _ => false,
        }
    }
}

fn wall_clock_now() -> String {
    let now = OffsetDateTime::from(SystemTime::now());
    now.format(&Rfc3339)
        .unwrap_or_else(|_| String::from("unknown"))
}

/// Monotonic nanoseconds since process start. Process-local, not portable
/// across restart — that's intentional; see `Timestamp::monotonic_ns` doc.
fn monotonic_now_ns() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    let elapsed = epoch.elapsed();
    elapsed
        .as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(elapsed.subsec_nanos()))
}

#[allow(dead_code)]
fn unix_epoch_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_produces_parseable_rfc3339() {
        let t = Timestamp::now();
        assert!(OffsetDateTime::parse(&t.wall_clock, &Rfc3339).is_ok());
    }

    #[test]
    fn rejects_invalid_wall_clock() {
        let result = Timestamp::new("not a timestamp".into(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn monotonic_advances() {
        let a = Timestamp::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = Timestamp::now();
        assert!(a.precedes(&b), "monotonic should advance: {a:?} {b:?}");
    }

    #[test]
    fn precedes_uses_monotonic_not_wall_clock() {
        // Construct two timestamps where wall_clock orderings disagree with
        // monotonic — verify `precedes` follows monotonic.
        let early_wall_late_mono = Timestamp::new("2020-01-01T00:00:00Z".into(), 100).unwrap();
        let late_wall_early_mono = Timestamp::new("2030-01-01T00:00:00Z".into(), 50).unwrap();
        assert!(late_wall_early_mono.precedes(&early_wall_late_mono));
        assert!(!early_wall_late_mono.precedes(&late_wall_early_mono));
    }

    #[test]
    fn wall_clock_helpers_use_wall_not_monotonic() {
        // The wall-clock helpers (RFC 0008) intentionally disregard
        // monotonic_ns. Construct two timestamps where the two
        // clocks disagree and verify only wall_clock is consulted.
        let early_wall_late_mono = Timestamp::new("2020-01-01T00:00:00Z".into(), 100).unwrap();
        let late_wall_early_mono = Timestamp::new("2030-01-01T00:00:00Z".into(), 50).unwrap();
        assert!(late_wall_early_mono.wall_at_or_after(&early_wall_late_mono));
        assert!(late_wall_early_mono.wall_after(&early_wall_late_mono));
        assert!(!early_wall_late_mono.wall_at_or_after(&late_wall_early_mono));
        assert!(!early_wall_late_mono.wall_after(&late_wall_early_mono));
    }

    #[test]
    fn wall_clock_helpers_default_deny_on_malformed() {
        // A Timestamp constructed via `new` can't have a malformed
        // wall_clock — the constructor rejects. Hostile callers can
        // still build one directly via the struct literal; verify
        // the helpers return false rather than panic.
        let good = Timestamp::new("2026-01-01T00:00:00Z".into(), 0).unwrap();
        let bad = Timestamp {
            wall_clock: "not a timestamp".into(),
            monotonic_ns: 0,
        };
        assert!(!good.wall_at_or_after(&bad));
        assert!(!bad.wall_at_or_after(&good));
        assert!(!bad.wall_at_or_after(&bad));
        assert!(!good.wall_after(&bad));
    }

    #[test]
    fn wall_at_or_after_is_inclusive() {
        let t = Timestamp::new("2026-01-01T00:00:00Z".into(), 0).unwrap();
        assert!(t.wall_at_or_after(&t));
        assert!(!t.wall_after(&t));
    }
}
