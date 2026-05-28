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

expect_fail_contains() {
  local name="$1"
  local expected="$2"
  shift 2

  set +e
  "$@" >"$tmpdir/${name}.out" 2>"$tmpdir/${name}.err"
  local status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    echo "error: $* unexpectedly succeeded" >&2
    cat "$tmpdir/${name}.out" >&2
    exit 1
  fi
  if ! grep -q "$expected" "$tmpdir/${name}.out" "$tmpdir/${name}.err"; then
    echo "error: $* did not mention '$expected'" >&2
    cat "$tmpdir/${name}.out" >&2
    cat "$tmpdir/${name}.err" >&2
    exit 1
  fi
}

run rustc --version
run cargo --version
run cargo fmt --all -- --check
run cargo check --all-targets --all-features --locked
run cargo clippy --all-targets --all-features --locked -- -D warnings
run cargo test --all-targets --all-features --locked
run cargo build --release --locked

capture version target/release/zejtron --version
if ! grep -q "zejtron" "$tmpdir/version.out"; then
  echo "error: version output did not contain 'zejtron'" >&2
  cat "$tmpdir/version.out" >&2
  cat "$tmpdir/version.err" >&2
  exit 1
fi

capture path_sh target/release/zejtron path sh
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

run target/release/zejtron recent . --limit 5
run target/release/zejtron port
run target/release/zejtron port --tcp
run target/release/zejtron port --udp
run target/release/zejtron port --tcp --group
run target/release/zejtron env --keys
run target/release/zejtron env --filter PATH
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env save check-base
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env list
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env diff check-base
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env delete check-base

capture recent_zero target/release/zejtron recent . --limit 0
if [[ ! -s "$tmpdir/recent_zero.out" ]]; then
  echo "error: recent --limit 0 produced empty output" >&2
  cat "$tmpdir/recent_zero.err" >&2
  exit 1
fi

expect_fail_contains recent_invalid "invalid duration" target/release/zejtron recent . --since nope
expect_fail_contains port_zero "invalid port" target/release/zejtron port 0
expect_fail_contains port_too_high "invalid port" target/release/zejtron port 65536
expect_fail_contains port_invalid "invalid port" target/release/zejtron port abc
expect_fail_contains port_conflict "cannot be used" target/release/zejtron port --listen --all

if [[ "${SKIP_CODESPELL:-0}" == "1" ]]; then
  echo "+ codespell skipped because SKIP_CODESPELL=1"
else
  run codespell --config .codespellrc .
fi

echo "All checks passed. Safe to commit."
