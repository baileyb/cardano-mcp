#!/usr/bin/env bash
# Preflight: run every CI check locally, before a commit or push.
# Mirrors .github/workflows/{ci,docs,zizmor}.yml — if this passes, CI passes.
# Wire it up:   git config core.hooksPath .githooks
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The repo's rust-toolchain.toml is the toolchain authority. An exported
# RUSTUP_TOOLCHAIN (e.g. from a version manager) silently overrides it and
# makes local results diverge from CI — neutralize it.
unset RUSTUP_TOOLCHAIN || true

fail=0
need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  echo "MISSING TOOL: $1 — install with: $2"
  fail=1
  return 1
}

step() { printf '\n== %s\n' "$1"; }

need cargo "rustup (rustup.rs)" || true
need cargo-deny "brew install cargo-deny" || true
need vale "brew install vale" || true
need lychee "brew install lychee" || true
need typos "brew install typos-cli" || true
need zizmor "brew install zizmor" || true
need npx "node/npm" || true
[ "$fail" -ne 0 ] && { echo "install missing tools first"; exit 1; }

step "cargo fmt --check"
cargo fmt --all --check

step "cargo clippy (all targets, locked)"
cargo clippy --workspace --all-targets --locked

step "cargo test (locked)"
cargo test --workspace --locked --quiet

step "crate dependency boundaries (decode/sanitize: no I/O deps)"
for crate in decode sanitize; do
  deps=$(sed -n '/^\[dependencies\]/,/^\[/p' "crates/$crate/Cargo.toml" | grep -E '^[a-zA-Z0-9_-]+\s*=' || true)
  banned=$(grep -E '^(reqwest|hyper|tokio|async-std|smol|ureq|curl|isahc|surf|actix|axum|warp|tide)' <<< "$deps" || true)
  if [ -n "$banned" ]; then
    echo "I/O dependency found in crates/$crate: $banned"
    exit 1
  fi
  echo "crates/$crate clean"
done

step "cargo deny check"
cargo-deny check

step "vale (prose, error level = CI gate)"
vale --minAlertLevel=error ./*.md

step "markdownlint (explicit dot-dir globs: CI scans them, local defaults skip them)"
npx --yes markdownlint-cli2 "**/*.md" ".claude/**/*.md" ".github/**/*.md"

step "lychee (links)"
lychee --no-progress --include-fragments "**/*.md"

step "typos"
typos

step "zizmor (workflow static analysis)"
zizmor --min-severity low .github/workflows/

printf '\nPREFLIGHT PASS\n'
