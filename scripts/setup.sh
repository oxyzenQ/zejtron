#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
# Copyright (C) 2026 rezky_nightky (oxyzenQ)
#
# scripts/setup.sh — the lazy one-command pipeline (the sibling's
# NIGHT-improve-18 lineage, adapted to zejtron's lanes).
#
# For the owner who does not want to remember the order: this runs
# the WHOLE bring-up and hands back a menu of next steps. Every phase
# is idempotent: re-running skips satisfied work (bootstrap re-checks
# in seconds, cargo rebuilds incrementally, the battery just runs
# again).
#
# The pipeline (each phase must pass before the next starts):
#   1. bootstrap        — rustup when missing + the pinned toolchain
#                         (rust-toolchain.toml resolves on first use)
#                         + the musl rust-std target + the static
#                         pro-native-musl build (musl is the only
#                         libc shape - night-badass-1, the GNU purge)
#   2. self-test        — the rootless CLI battery against the
#                         built binary (scripts/build.sh battery)
#   3. the release legs — the two arch-baseline shapes the release
#                         page ships (v3/v4, fully static musl), each
#                         built through its parity-checked cargo
#                         alias and run through the same battery
#
# Phase 3 fails the setup on a failing leg on purpose: these shapes
# are the deterministic release contract (the sibling's heavy phase
# only warns because its matrix rows are environment-sensitive; these
# are not).
#
# Usage:
#   ./scripts/setup.sh              # everything
#   ./scripts/setup.sh --skip-heavy # bootstrap + build + self-test only
#
# Run as your NORMAL user (not root): phase 1 installs into $HOME and
# a root cargo build corrupts target/ (the package scripts' law).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok() { echo -e "${GREEN}[setup]${NC} $1"; }
warn() { echo -e "${YELLOW}[setup]${NC} $1"; }
die() {
	echo -e "${RED}[setup]${NC} $1" >&2
	exit 1
}

SKIP_HEAVY=false

usage() {
	cat <<'EOF'
Usage: ./scripts/setup.sh [--skip-heavy]

  --skip-heavy  Stop after bootstrap + build + self-test
                (skip the two release-shape legs)
  -h, --help    Show this help
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--skip-heavy)
		SKIP_HEAVY=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage
		die "unknown option: $1"
		;;
	esac
done

if [ "$(id -u)" -eq 0 ]; then
	die "run as your normal user, not root — phase 1 installs into \$HOME and a root cargo build corrupts target/."
fi

cd "${REPO_ROOT}"

# bootstrap fixes ~/.profile PATH persistence for FUTURE shells; the
# current shell still needs the cargo entry for every later phase.
PATH="${HOME}/.cargo/bin:${PATH}"

SECONDS=0

# The musl rust-std target both --musl and the phase 4 musl legs need;
# installed once, idempotently (the aliases link through rust-lld, so
# the target is the only prerequisite - see .cargo/config.toml).
ensure_musl_target() {
	if ! rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
		ok "adding the musl rust-std target (rustup target add)"
		rustup target add x86_64-unknown-linux-musl
	fi
}

ok "phase 1/3: bootstrap (rustup + the pinned toolchain + the static pro-native-musl build)"
if [ "$(uname -m)" != "x86_64" ]; then
	die "the build pipeline is x86_64-only - musl is the only libc shape (night-badass-1, the GNU purge; see .cargo/config.toml)."
fi
if ! command -v cargo >/dev/null 2>&1; then
	ok "cargo not found - installing rustup (minimal profile; the pinned toolchain follows rust-toolchain.toml)"
	if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; then
		die "rustup install failed — read its output above; fix and re-run ./scripts/setup.sh (idempotent)."
	fi
fi
ensure_musl_target
if ! cargo pro-native-musl --locked; then
	die "the pro-native-musl build failed — read the compiler output above; fix and re-run ./scripts/setup.sh (idempotent)."
fi
ok "phase 1/3: pro-native-musl ready at target/x86_64-unknown-linux-musl/pro-native-musl/zejtron (${SECONDS}s)"

ok "phase 2/3: CLI battery self-test (rootless, against the built binary)"
if ! ZEJTRON_BIN_PATH="target/x86_64-unknown-linux-musl/pro-native-musl/zejtron" "${SCRIPT_DIR}/build.sh" battery; then
	die "self-test failed — the built binary broke the runtime contract; fix and re-run ./scripts/setup.sh (idempotent)."
fi
ok "phase 2/3: self-test green"

if [ "${SKIP_HEAVY}" = true ]; then
	ok "phase 3/3: release legs skipped (--skip-heavy)"
else
	ok "phase 3/3: the release legs (v3/v4 musl, 5+ min cold)"
	for leg in pro-linux-amd64-v3-musl pro-linux-amd64-v4-musl; do
		leg_bin="target/x86_64-unknown-linux-musl/${leg}/zejtron"
		ok "leg ${leg}: build"
		if ! cargo "${leg}" --locked; then
			die "leg ${leg} build failed — read the compiler output above; fix and re-run ./scripts/setup.sh (idempotent)."
		fi
		ok "leg ${leg}: battery"
		if ! ZEJTRON_BIN_PATH="${leg_bin}" "${SCRIPT_DIR}/build.sh" battery; then
			die "leg ${leg} battery failed — ${leg_bin} broke the runtime contract."
		fi
	done
fi

BUILT="${REPO_ROOT}/target/x86_64-unknown-linux-musl/pro-native-musl/zejtron"
echo ""
ok "setup finished in ${SECONDS}s — binary: ${BUILT}"
echo ""
echo "next steps — the menu:"
echo "  want it installed to /usr/bin?   ./scripts/package/install-on-my-machine.sh"
echo "  want it gone again?              ./scripts/package/uninstall.sh"
echo "  explore the CLI:                 ${BUILT} --help"
echo "  check this host:                 ${BUILT} doctor"
echo "  docs:                            README.md + docs/"
