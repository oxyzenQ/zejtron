#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo build --release --locked

target/release/nestkit --version
target/release/nestkit path sh
target/release/nestkit recent . --limit 5
