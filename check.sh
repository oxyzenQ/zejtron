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

service_smoke() {
  local name="$1"
  shift

  set +e
  "$@" >"$tmpdir/${name}.out" 2>"$tmpdir/${name}.err"
  local status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    cat "$tmpdir/${name}.out"
    return
  fi

  if grep -Eqi "systemctl failed|Failed to connect|System has not been booted|No such file or directory|No medium found" \
    "$tmpdir/${name}.out" "$tmpdir/${name}.err"; then
    echo "+ service smoke tolerated because systemd is unavailable: $*"
    cat "$tmpdir/${name}.out"
    cat "$tmpdir/${name}.err" >&2
    return
  fi

  echo "error: service smoke failed unexpectedly: $*" >&2
  cat "$tmpdir/${name}.out" >&2
  cat "$tmpdir/${name}.err" >&2
  exit 1
}

run rustc --version
run cargo --version
run cargo fmt --all -- --check
run cargo check --all-targets --all-features --locked
run cargo clippy --all-targets --all-features --locked -- -D warnings
run cargo test --all-targets --all-features --locked
run cargo build --release --locked

run target/release/zejtron --help
run target/release/zejtron doctor
run target/release/zejtron service --help

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
run target/release/zejtron proc --me --depth 1
run target/release/zejtron proc --me --no-pid --depth 1
run target/release/zejtron proc --me --find sh --depth 2
run target/release/zejtron holds 53
touch "$tmpdir/held file"
printf 'hello\n' >"$tmpdir/touched file"
mkdir "$tmpdir/touched dir"
printf 'hello\n' >"$tmpdir/why file with spaces"
capture holds_temp target/release/zejtron holds "$tmpdir/held file"
if ! grep -q "No holders found" "$tmpdir/holds_temp.out"; then
  echo "error: holds temp file output did not mention no holders" >&2
  cat "$tmpdir/holds_temp.out" >&2
  cat "$tmpdir/holds_temp.err" >&2
  exit 1
fi
capture touch_file target/release/zejtron touch "$tmpdir/touched file"
if ! grep -q "filesystem metadata" "$tmpdir/touch_file.out"; then
  echo "error: touch temp file output did not mention filesystem metadata" >&2
  cat "$tmpdir/touch_file.out" >&2
  cat "$tmpdir/touch_file.err" >&2
  exit 1
fi
capture touch_dir target/release/zejtron touch "$tmpdir/touched dir"
if ! grep -q "actor: unknown" "$tmpdir/touch_dir.out"; then
  echo "error: touch temp directory output did not mention unknown actor" >&2
  cat "$tmpdir/touch_dir.out" >&2
  cat "$tmpdir/touch_dir.err" >&2
  exit 1
fi
run target/release/zejtron why 53
capture why_readme target/release/zejtron why README.md
if ! grep -q "reason:" "$tmpdir/why_readme.out"; then
  echo "error: why README output did not mention reason" >&2
  cat "$tmpdir/why_readme.out" >&2
  cat "$tmpdir/why_readme.err" >&2
  exit 1
fi
run target/release/zejtron why /etc/resolv.conf
capture why_spaces target/release/zejtron why "$tmpdir/why file with spaces"
if ! grep -q "why file with spaces" "$tmpdir/why_spaces.out"; then
  echo "error: why path with spaces output did not mention the path" >&2
  cat "$tmpdir/why_spaces.out" >&2
  cat "$tmpdir/why_spaces.err" >&2
  exit 1
fi
run target/release/zejtron env --keys
run target/release/zejtron env --filter PATH
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env save check-base
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env list
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env diff check-base
env XDG_DATA_HOME="$tmpdir/xdg-data" target/release/zejtron env delete check-base
if command -v systemctl >/dev/null 2>&1; then
  service_smoke service_failed target/release/zejtron service --failed
  service_smoke service_filter target/release/zejtron service --filter systemd
  service_smoke service_all target/release/zejtron service --all
else
  echo "+ service smoke skipped because systemctl is unavailable"
fi

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
expect_fail_contains holds_zero "invalid port" target/release/zejtron holds 0
expect_fail_contains holds_too_high "invalid port" target/release/zejtron holds 65536
expect_fail_contains touch_missing "path not found" target/release/zejtron touch "$tmpdir/missing path"
expect_fail_contains why_zero "invalid port" target/release/zejtron why 0
expect_fail_contains why_too_high "invalid port" target/release/zejtron why 65536
expect_fail_contains why_missing "path not found" target/release/zejtron why "$tmpdir/missing path"
expect_fail_contains proc_invalid_interval "must be between" target/release/zejtron proc --me --live --interval 1
expect_fail_contains service_scope_conflict "cannot be used" target/release/zejtron service --system --user

if [[ "${SKIP_CODESPELL:-0}" == "1" ]]; then
  echo "+ codespell skipped because SKIP_CODESPELL=1"
else
  run codespell --config .codespellrc .
fi

echo "All checks passed. Safe to commit."
