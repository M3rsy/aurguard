//! Core static-analysis engine for AURGuard.
//!
//! Security invariant: this crate never sources or executes a PKGBUILD.
//! Package metadata is treated as untrusted input and inspected as data.

mod model;
mod rules;
mod scanner;

pub use model::{Finding, RiskLevel, ScanReport, Severity};
pub use scanner::scan_path;
