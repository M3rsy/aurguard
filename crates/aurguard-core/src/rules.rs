use anyhow::{Context, Result};
use regex::Regex;

use crate::model::Severity;

#[derive(Debug)]
pub(crate) struct TextRule {
    pub id: &'static str,
    pub severity: Severity,
    pub score: u16,
    pub title: &'static str,
    pub description: &'static str,
    pub regex: Regex,
    pub only_pkgbuild_like: bool,
}

impl TextRule {
    fn new(
        id: &'static str,
        severity: Severity,
        score: u16,
        title: &'static str,
        description: &'static str,
        pattern: &'static str,
        only_pkgbuild_like: bool,
    ) -> Result<Self> {
        Ok(Self {
            id,
            severity,
            score,
            title,
            description,
            regex: Regex::new(pattern).with_context(|| format!("invalid built-in rule {id}"))?,
            only_pkgbuild_like,
        })
    }
}

pub(crate) fn builtin_rules() -> Result<Vec<TextRule>> {
    Ok(vec![
        TextRule::new(
            "SHELL001",
            Severity::Critical,
            100,
            "Remote content piped to a shell",
            "Downloads remote content and passes it directly to sh/bash. This pattern can execute unverified code immediately.",
            r"(?i)\b(curl|wget)\b[^\n|;]*(\||;|&&)\s*(/usr/bin/|/bin/)?(ba)?sh\b",
            true,
        )?,
        TextRule::new(
            "SHELL002",
            Severity::High,
            65,
            "Dynamic shell evaluation",
            "Uses eval on dynamically constructed content. Review the input source carefully.",
            r"(?i)(^|[;&|\s])eval(\s|$)",
            true,
        )?,
        TextRule::new(
            "SHELL003",
            Severity::High,
            70,
            "Privilege escalation command in build metadata",
            "Uses sudo, pkexec, or su from package build/install metadata. A normal PKGBUILD should not need to elevate privileges itself.",
            r"(?i)(^|[;&|\s])(sudo|pkexec)(\s|$)|(^|[;&|\s])su\s+-c(\s|$)",
            true,
        )?,
        TextRule::new(
            "SHELL004",
            Severity::High,
            65,
            "Raw networking utility",
            "Uses a low-level networking utility commonly capable of arbitrary TCP/UDP connections.",
            r"(?i)(^|[;&|\s])(nc|ncat|netcat|socat)(\s|$)",
            true,
        )?,
        TextRule::new(
            "SHELL005",
            Severity::Low,
            10,
            "Executable permission added",
            "Makes a file executable. This is not inherently malicious, but deserves review when paired with downloaded or bundled binaries.",
            r"(?i)\bchmod\b[^\n]*(\+x|\s[057]*[1357][0-7]{2}\s)",
            true,
        )?,
        TextRule::new(
            "SHELL006",
            Severity::Low,
            10,
            "Local executable launched from repository/build directory",
            "Executes a relative file. Verify that the executable comes from a trusted and authenticated source.",
            r"(^|[;&|\s])\./[A-Za-z0-9_.+/@-]+",
            true,
        )?,
        TextRule::new(
            "SHELL007",
            Severity::Medium,
            35,
            "Base64 decoding in executable build metadata",
            "Decodes Base64 content. Obfuscation is not automatically malicious, but can hide executable commands or payloads.",
            r"(?i)\bbase64\b[^\n]*(-d|--decode)",
            true,
        )?,
        TextRule::new(
            "SHELL008",
            Severity::High,
            60,
            "Sensitive user data path referenced",
            "References a sensitive user credential or browser-data location from build/install metadata.",
            r"(?i)(\.ssh/|id_rsa|id_ed25519|authorized_keys|\.gnupg/|\.mozilla/|\.config/(google-chrome|chromium|BraveSoftware)/|\.local/share/keyrings/)",
            true,
        )?,
        TextRule::new(
            "SHELL009",
            Severity::High,
            60,
            "Highly sensitive system path referenced",
            "References a path commonly associated with authentication or process injection. Legitimate packages are rare and should be manually reviewed.",
            r"(?i)(/etc/shadow|/etc/sudoers(\.d)?/|/etc/ld\.so\.preload|/proc/[0-9*]+/(mem|maps)|LD_PRELOAD)",
            true,
        )?,
        TextRule::new(
            "PKG001",
            Severity::Low,
            10,
            "Integrity check disabled with SKIP",
            "One or more source checksums are set to SKIP. This may be legitimate for VCS sources, but weakens integrity verification for downloaded artifacts.",
            r"(?i)(sha(1|224|256|384|512)sums|md5sums|b2sums)[^\n]*\bSKIP\b|['\"]SKIP['\"]",
            true,
        )?,
        TextRule::new(
            "SRC001",
            Severity::Medium,
            20,
            "Insecure HTTP source",
            "Uses an unencrypted HTTP URL. Prefer HTTPS or another authenticated transport for package sources.",
            r"(?i)http://[A-Za-z0-9]",
            true,
        )?,
        TextRule::new(
            "OBF001",
            Severity::Medium,
            40,
            "Large encoded-looking blob",
            "Contains a long Base64-like sequence. Review whether it is data, a signature, or an obfuscated payload.",
            r"[A-Za-z0-9+/]{180,}={0,2}",
            true,
        )?,
        TextRule::new(
            "NET001",
            Severity::Medium,
            20,
            "Network downloader command",
            "Invokes curl or wget from build/install metadata. Sources should normally be declared in source=() so makepkg can verify them.",
            r"(?i)(^|[;&|\s])(curl|wget)(\s|$)",
            true,
        )?,
        TextRule::new(
            "PERSIST001",
            Severity::Medium,
            25,
            "System service or persistence path referenced",
            "References a systemd, cron, udev, or profile location. This can be legitimate, but it affects system-wide startup or behavior.",
            r"(?i)(/etc/systemd/system/|/usr/lib/systemd/system/|/etc/cron\.d/|/etc/profile\.d/|/etc/udev/rules\.d/)",
            true,
        )?,
    ])
}
