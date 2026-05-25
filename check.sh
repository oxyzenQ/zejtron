#!/usr/bin/env bash
set -Eeuo pipefail

check_command() {
  local command="$1"
  local label="${2:-$1}"
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "error: required command not found: $label" >&2
    if [[ "$label" == "codespell" ]]; then
      echo "hint: install codespell or run SKIP_CODESPELL=1 ./check.sh" >&2
    fi
    exit 1
  fi
}

check_command cargo
check_command rustc
check_command git
check_command rustfmt
check_command cargo-clippy clippy
if [[ "${SKIP_CODESPELL:-0}" != "1" ]]; then
  check_command codespell
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

run() {
  echo "+ $*"
  "$@"
}

capture() {
  local name="$1"
  shift
  "$@" >"$tmpdir/${name}.out" 2>"$tmpdir/${name}.err"
}

run rustc --version
run cargo --version
run cargo fmt --all -- --check
run cargo check --all-targets --all-features --locked
run cargo clippy --all-targets --all-features --locked -- -D warnings
run cargo test --all-targets --all-features --locked
run cargo build --release --locked

capture version target/release/nestkit --version
if ! grep -q "nestkit" "$tmpdir/version.out"; then
  echo "error: version output did not contain 'nestkit'" >&2
  cat "$tmpdir/version.out" >&2
  cat "$tmpdir/version.err" >&2
  exit 1
fi

capture path_sh target/release/nestkit path sh
if ! grep -q "active:" "$tmpdir/path_sh.out"; then
  echo "error: path sh output did not contain 'active:'" >&2
  cat "$tmpdir/path_sh.out" >&2
  cat "$tmpdir/path_sh.err" >&2
  exit 1
fi
if ! grep -q "duplicates:" "$tmpdir/path_sh.out"; then
  echo "error: path sh output did not contain 'duplicates:'" >&2
  cat "$tmpdir/path_sh.out" >&2
  cat "$tmpdir/path_sh.err" >&2
  exit 1
fi

run target/release/nestkit recent . --limit 5

capture recent_zero target/release/nestkit recent . --limit 0
if [[ ! -s "$tmpdir/recent_zero.out" ]]; then
  echo "error: recent --limit 0 produced empty output" >&2
  cat "$tmpdir/recent_zero.err" >&2
  exit 1
fi

set +e
target/release/nestkit recent . --since nope >"$tmpdir/recent_invalid.out" 2>"$tmpdir/recent_invalid.err"
recent_invalid_status=$?
set -e
if [[ "$recent_invalid_status" -eq 0 ]]; then
  echo "error: recent --since nope unexpectedly succeeded" >&2
  cat "$tmpdir/recent_invalid.out" >&2
  exit 1
fi
if ! grep -q "invalid duration" "$tmpdir/recent_invalid.out" "$tmpdir/recent_invalid.err"; then
  echo "error: recent --since nope did not mention invalid duration" >&2
  cat "$tmpdir/recent_invalid.out" >&2
  cat "$tmpdir/recent_invalid.err" >&2
  exit 1
fi

if [[ "${SKIP_CODESPELL:-0}" == "1" ]]; then
  echo "+ codespell skipped because SKIP_CODESPELL=1"
else
  run codespell --config .codespellrc .
fi

echo "All checks passed. Safe to commit."
