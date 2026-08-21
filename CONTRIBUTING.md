# Contributing to AURGuard

Thank you for helping improve AUR package security.

## Development rules

- Never add code that sources or executes a scanned `PKGBUILD` during static analysis.
- Tests representing malicious behavior must use inert fixtures and reserved domains such as `example.invalid`.
- Every detection rule should explain why it fired and carry a stable rule ID.
- Prefer low false-positive rates over dramatic scoring.
- New blocking/critical rules require tests.

## Local checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
