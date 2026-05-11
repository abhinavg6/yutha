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

    /// Compare two timestamps using monotonic_ns. Per spec, spec-mandated
    /// comparison logic uses monotonic; this helper makes that explicit at
    /// call sites.
    pub fn precedes(&self, other: &Self) -> bool {
        self.monotonic_ns < other.monotonic_ns
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
}
