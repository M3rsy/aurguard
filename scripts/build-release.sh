#!/usr/bin/env bash
set -euo pipefail

cargo build --release -p aurguard
printf 'Built: %s\n' "$(pwd)/target/release/aurguard"
