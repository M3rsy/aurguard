# Architecture

## Security boundary

AURGuard's first boundary is the AUR Git checkout. Everything below that directory is untrusted.

The static-analysis path is intentionally one-way:

```text
untrusted AUR Git data
        |
        v
read-only scanner
        |
        +--> text rules
        +--> file magic / hashes
        +--> metadata checks
        |
        v
structured findings
        |
        v
risk aggregation
        |
        +--> terminal report
        +--> JSON report
```

No static-analysis module is allowed to execute a repository-controlled command.

## Crates

### `aurguard-core`

Reusable library responsible for walking a package checkout without following symlinks, recognizing ELF magic, hashing bundled ELF files, scanning metadata with deterministic rules, producing structured findings and calculating final risk.

### `aurguard` CLI

Responsible for parsing CLI options, validating AUR package names, hardened Git cloning, temporary checkout lifecycle, terminal/JSON rendering and CI exit thresholds.

## Planned modules

```text
aurguard-core
├── pkgbuild_ast
├── git_analysis
├── elf_analysis
├── provenance
├── yara
└── risk

aurguard
├── scan
├── diff
├── build
├── audit
└── install
```

Dynamic builds will be a separate explicit command; `aurguard scan` will remain static-only.
