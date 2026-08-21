use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u16, has_critical: bool) -> Self {
        if has_critical || score >= 80 {
            Self::Critical
        } else if score >= 50 {
            Self::High
        } else if score >= 20 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    pub score: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub package: String,
    pub target: String,
    pub files_scanned: usize,
    pub text_files_scanned: usize,
    pub elf_files: usize,
    pub score: u16,
    pub risk: RiskLevel,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn finalize(
        package: String,
        target: String,
        files_scanned: usize,
        text_files_scanned: usize,
        elf_files: usize,
        mut findings: Vec<Finding>,
    ) -> Self {
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });

        let raw_score: u32 = findings.iter().map(|finding| finding.score as u32).sum();
        let score = raw_score.min(100) as u16;
        let has_critical = findings
            .iter()
            .any(|finding| finding.severity == Severity::Critical);
        let risk = RiskLevel::from_score(score, has_critical);

        Self {
            package,
            target,
            files_scanned,
            text_files_scanned,
            elf_files,
            score,
            risk,
            findings,
        }
    }
}
