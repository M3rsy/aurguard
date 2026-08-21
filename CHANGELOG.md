# Changelog

All notable changes to AURGuard will be documented here.

## [Unreleased]

### Planned

- Bash AST parser.
- Git update diff analysis.
- Source provenance and signature analysis.
- ELF semantic inspection.
- YARA-X support.
- Isolated build mode.

## [0.1.0] - 2026-08-20

### Added

- Initial Rust Cargo workspace.
- Reusable `aurguard-core` static scanning engine.
- `aurguard scan` for AUR package names and local directories.
- ELF magic detection and SHA-256 fingerprinting.
- Initial deterministic package/shell risk rules.
- Risk score and LOW/MEDIUM/HIGH/CRITICAL levels.
- JSON reports and CI threshold support.
- GitHub CI, security policy, contribution guide and initial AUR packaging template.
