use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};
use aurguard_core::{scan_path, RiskLevel, ScanReport};
use clap::{Parser, Subcommand, ValueEnum};
use tempfile::TempDir;

#[derive(Debug, Parser)]
#[command(
    name = "aurguard",
    version,
    about = "Static security scanner for Arch User Repository packages",
    long_about = "AURGuard inspects AUR repositories without sourcing or executing PKGBUILD files.\nIt detects suspicious shell patterns, bundled ELF binaries, disabled integrity checks, and other risk signals."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan an AUR package name or a local package repository directory.
    Scan {
        /// AUR package name (example: zen-browser-bin) or local directory.
        target: String,

        /// Report format.
        #[arg(long, value_enum, default_value = "terminal")]
        format: OutputFormat,

        /// Write the report to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Return a non-zero exit status when this risk level or higher is reached.
        #[arg(long, value_enum)]
        fail_on: Option<RiskArg>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RiskArg {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskArg {
    fn as_level(self) -> RiskLevel {
        match self {
            Self::Low => RiskLevel::Low,
            Self::Medium => RiskLevel::Medium,
            Self::High => RiskLevel::High,
            Self::Critical => RiskLevel::Critical,
        }
    }
}

enum ResolvedTarget {
    Local { path: PathBuf, package: String },
    Aur { _tempdir: TempDir, path: PathBuf, package: String },
}

impl ResolvedTarget {
    fn path(&self) -> &Path {
        match self {
            Self::Local { path, .. } | Self::Aur { path, .. } => path,
        }
    }

    fn package(&self) -> &str {
        match self {
            Self::Local { package, .. } | Self::Aur { package, .. } => package,
        }
    }

    fn display_target(&self) -> String {
        match self {
            Self::Local { path, .. } => path.display().to_string(),
            Self::Aur { package, .. } => format!("https://aur.archlinux.org/{package}.git"),
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("aurguard: error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { target, format, output, fail_on } => {
            let resolved = resolve_target(&target)?;
            let mut report = scan_path(resolved.path(), resolved.package().to_string())?;
            report.target = resolved.display_target();
            let rendered = match format {
                OutputFormat::Terminal => render_terminal(&report),
                OutputFormat::Json => serde_json::to_string_pretty(&report)?,
            };

            if let Some(path) = output {
                fs::write(&path, rendered)
                    .with_context(|| format!("unable to write report to {}", path.display()))?;
                println!("Report written to {}", path.display());
            } else {
                println!("{rendered}");
            }

            if let Some(threshold) = fail_on {
                if report.risk >= threshold.as_level() {
                    return Ok(ExitCode::from(2));
                }
            }

            Ok(ExitCode::SUCCESS)
        }
    }
}

fn resolve_target(target: &str) -> Result<ResolvedTarget> {
    let candidate = PathBuf::from(target);
    if candidate.exists() {
        if !candidate.is_dir() {
            bail!("local scan target must be a directory: {}", candidate.display());
        }
        let canonical = candidate
            .canonicalize()
            .with_context(|| format!("unable to resolve {}", candidate.display()))?;
        let package = canonical
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("local-package")
            .to_string();
        return Ok(ResolvedTarget::Local { path: canonical, package });
    }

    validate_aur_package_name(target)?;
    ensure_git_available()?;

    let tempdir = tempfile::Builder::new()
        .prefix("aurguard-")
        .tempdir()
        .context("unable to create temporary scan directory")?;
    let destination = tempdir.path().join("repo");
    let url = format!("https://aur.archlinux.org/{target}.git");

    let output = Command::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c", "core.hooksPath=/dev/null",
            "-c", "protocol.file.allow=never",
            "clone", "--quiet", "--depth", "20", "--",
        ])
        .arg(&url)
        .arg(&destination)
        .output()
        .context("failed to start hardened git clone")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("unable to clone AUR package {target}: {}", escape_terminal(stderr.trim()));
    }

    Ok(ResolvedTarget::Aur { _tempdir: tempdir, path: destination, package: target.to_string() })
}

fn validate_aur_package_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 255 {
        bail!("invalid AUR package name");
    }

    let valid = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
    });
    if !valid || value.starts_with('.') || value.starts_with('-') {
        bail!("invalid AUR package name: {value}");
    }
    Ok(())
}

fn ensure_git_available() -> Result<()> {
    let output = Command::new("git")
        .arg("--version")
        .output()
        .context("git is required to scan packages from aur.archlinux.org")?;
    if !output.status.success() {
        bail!("git is required to scan packages from aur.archlinux.org");
    }
    Ok(())
}

fn escape_terminal(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{{{:04x}}}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn render_terminal(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("AURGuard {}\n", env!("CARGO_PKG_VERSION")));
    out.push_str("Static AUR package security report\n\n");
    out.push_str(&format!("Package:            {}\n", escape_terminal(&report.package)));
    out.push_str(&format!("Target:             {}\n", escape_terminal(&report.target)));
    out.push_str(&format!("Files scanned:      {}\n", report.files_scanned));
    out.push_str(&format!("Text files scanned: {}\n", report.text_files_scanned));
    out.push_str(&format!("ELF files found:    {}\n", report.elf_files));
    out.push('\n');
    out.push_str(&format!("Risk:  {}  ({}/100)\n", report.risk, report.score));
    out.push_str("----------------------------------------\n");

    if report.findings.is_empty() {
        out.push_str("No configured risk indicators were detected.\n");
        out.push_str("This does NOT prove that the package is safe.\n");
        return out;
    }

    for finding in &report.findings {
        let location = match finding.line {
            Some(line) => format!("{}:{}", escape_terminal(&finding.file), line),
            None => escape_terminal(&finding.file),
        };
        out.push_str(&format!("\n[{}] {}  {}\n", finding.severity, finding.rule_id, finding.title));
        out.push_str(&format!("Location: {location}\n"));
        out.push_str(&format!("Reason:   {}\n", finding.description));
        if let Some(evidence) = &finding.evidence {
            out.push_str(&format!("Evidence: {}\n", escape_terminal(evidence)));
        }
        out.push_str(&format!("Weight:   +{}\n", finding.score));
    }

    out.push_str("\n----------------------------------------\n");
    out.push_str("Risk is heuristic. Review flagged changes before building or installing.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_control_sequences() {
        assert_eq!(escape_terminal("ok\x1b[31mred\n"), "ok\\u{001b}[31mred\\n");
    }

    #[test]
    fn accepts_common_aur_package_names() {
        for name in ["zen-browser-bin", "foo-git", "lib32-example", "python_pkg+test"] {
            assert!(validate_aur_package_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_shell_metacharacters_in_remote_target() {
        for name in ["foo;id", "$(id)", "../foo", "foo/bar", "-upload-pack=evil"] {
            assert!(validate_aur_package_name(name).is_err(), "{name}");
        }
    }
}
