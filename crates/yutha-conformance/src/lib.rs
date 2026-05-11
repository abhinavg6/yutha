//! Conformance harness for Yutha.
//!
//! Backends register themselves and run the same test set; the harness
//! verifies they meet the spec'd behaviors at their declared conformance
//! level.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod outcome;
pub mod receipt;
pub mod scenarios;

pub use outcome::{Outcome, TestOutcome};
