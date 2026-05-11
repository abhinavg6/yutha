//! [`Outcome`] — structured pass/fail report from a conformance run.

/// The result of a single conformance test.
#[derive(Debug, Clone)]
pub struct TestOutcome {
    /// Stable test name (e.g., `"receipt.append.idempotent"`).
    pub name: &'static str,
    /// Pass / fail. Skipped tests count as passes for aggregate-pass
    /// purposes; the `skipped` flag distinguishes them in reports.
    pub passed: bool,
    /// Whether this test was skipped because the backend declined to claim
    /// the capability the test exercises (e.g., durability across restart
    /// on an in-memory store). Skipped tests have `passed = true`.
    pub skipped: bool,
    /// Detail on failure or skip-reason; empty on plain pass.
    pub detail: String,
}

impl TestOutcome {
    /// Construct a pass.
    pub fn pass(name: &'static str) -> Self {
        Self {
            name,
            passed: true,
            skipped: false,
            detail: String::new(),
        }
    }

    /// Construct a fail with detail.
    pub fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            passed: false,
            skipped: false,
            detail: detail.into(),
        }
    }

    /// Construct a skip with a short reason. Counts as a pass; flagged
    /// `skipped` so reports can distinguish.
    pub fn skip(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            passed: true,
            skipped: true,
            detail: reason.into(),
        }
    }
}

/// Aggregate outcome of a suite run.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Per-test outcomes in run order.
    pub tests: Vec<TestOutcome>,
}

impl Outcome {
    /// Whether every test passed (skipped tests count as passes).
    pub fn passed(&self) -> bool {
        self.tests.iter().all(|t| t.passed)
    }

    /// Number of failures.
    pub fn failures(&self) -> usize {
        self.tests.iter().filter(|t| !t.passed).count()
    }

    /// Number of skipped tests.
    pub fn skips(&self) -> usize {
        self.tests.iter().filter(|t| t.skipped).count()
    }

    /// Iterate failures.
    pub fn failed(&self) -> impl Iterator<Item = &TestOutcome> {
        self.tests.iter().filter(|t| !t.passed)
    }

    /// Iterate skipped tests.
    pub fn skipped(&self) -> impl Iterator<Item = &TestOutcome> {
        self.tests.iter().filter(|t| t.skipped)
    }

    /// Append a test outcome.
    pub fn record(&mut self, outcome: TestOutcome) {
        self.tests.push(outcome);
    }
}
