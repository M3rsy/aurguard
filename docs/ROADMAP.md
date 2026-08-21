# AURGuard roadmap

## v0.1 — Static scanner MVP

- [x] Rust Cargo workspace.
- [x] `aurguard-core` reusable library.
- [x] `aurguard` CLI.
- [x] Scan AUR package by name.
- [x] Scan local checkout.
- [x] Detect bundled ELF magic.
- [x] SHA-256 ELF fingerprint.
- [x] Initial deterministic shell rules.
- [x] Initial source/integrity rules.
- [x] Risk scoring.
- [x] Terminal and JSON reports.
- [x] CI threshold with `--fail-on`.
- [ ] Bash AST parser (`tree-sitter-bash`).
- [ ] Detect executable commands at PKGBUILD top level.
- [ ] External TOML rule packs.

## v0.2 — Git Guardian

- [ ] `aurguard diff <package>`.
- [ ] Compare current update against previous commits.
- [ ] Highlight newly introduced executables.
- [ ] Highlight new network behavior.
- [ ] Highlight new persistence paths.
- [ ] AUR RPC metadata.
- [ ] Maintainer/adoption change signals.

## v0.3 — Binary and provenance analysis

- [ ] ELF metadata parsing using `object` or `goblin`.
- [ ] Imported symbol analysis.
- [ ] String indicators.
- [ ] Entropy/packer indicators with conservative scoring.
- [ ] Upstream/source-domain consistency checks.
- [ ] Signature-awareness and `validpgpkeys` analysis.
- [ ] YARA-X rule integration.

## v0.4 — Isolated builds

- [ ] `aurguard build`.
- [ ] Bubblewrap/Linux namespace isolation.
- [ ] Empty temporary HOME.
- [ ] No SSH/GPG/browser credentials mounted.
- [ ] Controlled source-download phase.
- [ ] Network disabled during build phase when possible.
- [ ] Filesystem write monitoring.

## v1.0

- [ ] Stable rule schema.
- [ ] Signed release binaries/checksums.
- [ ] Reproducible release process.
- [ ] Comprehensive fixture corpus.
- [ ] Documented false-positive policy.
- [ ] AUR package publication.
