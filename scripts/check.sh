#!/usr/bin/env bash
# The quality gate. Everything it checks, it checks on this machine — no CI
# required and no network access. Run it before you commit; the pre-commit hook
# in .githooks runs it for you.
#
#   scripts/check.sh              full gate
#   scripts/check.sh --fast       skip the Windows cross-checks (~2s faster)
#
# Install the hook once, per clone:
#   git config core.hooksPath .githooks

set -euo pipefail
cd "$(dirname "$0")/.."

fast=0
[[ ${1:-} == "--fast" ]] && fast=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }

step "format"
cargo fmt --all --check

step "lint"
cargo clippy --workspace --all-targets --all-features -- -D warnings

step "test"
cargo test --workspace --all-features

step "design-rule guards"
python3 scripts/guards.py

if (( fast )); then
  printf '\n\033[33m! skipped Windows cross-checks (--fast)\033[0m\n'
else
  # We cannot run Windows here, but we can prove the Windows code paths still
  # compile. `cargo check` type-checks without linking, so no MSVC toolchain is
  # needed. `portable-hash` swaps blake3's assembly for its Rust implementation,
  # which is the only part that wants an assembler we do not have.
  #
  # Requires, once:  rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc
  for target in x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
    step "cross-check $target"
    cargo check --workspace --all-targets --target "$target" \
      --features scrub-core/portable-hash
  done
fi

printf '\n\033[32m✓ gate passed\033[0m\n'
