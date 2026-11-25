#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only - the fixture builds the project's own toolchains.
#
# scripts/sandbox/build-fixtures.sh - the Z11 detonation fixture's
# host-side build lane (night-frontier-Z11). The detonation
# (detect-rootkit.sh) rides on two fixture artifacts: the pidhide
# userspace loader (static musl) and the bpfel object it plants.
# CI builds both inline (supermassive-kernel-floor.yml) and packs
# them into the micro-VM's rootfs; the host lane has no packer, so
# the artifacts live in the repo's own fixture build tree and the
# detonation resolves them from there. This script runs that exact
# CI recipe by hand - same locked manifests, same offline posture,
# same toolchains - and verifies both artifacts land.
#
# The recipe mirrors CI byte for byte:
#   loader  stable MSRV (the rust-toolchain.toml pin the main build
#           carries), --target x86_64-unknown-linux-musl, --locked,
#           --offline (the committed lock is the supply-chain law);
#   ebpf    the dated nightly the probes' nested build runs with,
#           inside the fixture's own ebpf/ directory - the nightly
#           pin, the bpfel target spec, and the v3 rustflags ride
#           the fixture's own ebpf/.cargo/config.toml, and
#           RUSTUP_TOOLCHAIN overrides the job's stable pin the same
#           way build.rs does for the main probes.
#
# The builds are hermetic: nothing installs, nothing upgrades, no
# network (CARGO_NET_OFFLINE=true on every call). A missing toolchain
# is a named failure with the exact install command, never a silent
# skip and never an auto-fetch.
#
# Usage:
#   scripts/sandbox/build-fixtures.sh            build + verify
#   scripts/sandbox/build-fixtures.sh -q         build + verify, quiet
#   scripts/sandbox/build-fixtures.sh -f         force the rebuild: remove
#           both fixture target trees first, so a pair that predates the
#           fixture sources (the remembered bytes of an earlier shape -
#           the target tree survives `git pull` untouched) can never run
#           again
#
# Exit codes: 0 both artifacts present; 1 any named failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${REPO_ROOT}/test-fixtures/pidhide"

QUIET=0
FORCE=0
for arg in "$@"; do
	case "${arg}" in
	-q) QUIET=1 ;;
	-f) FORCE=1 ;;
	*)
		echo "usage: $0 [-q] [-f]" >&2
		exit 1
		;;
	esac
done

note() { [ "${QUIET}" -eq 1 ] || echo "[fixtures] $*"; }
die() {
	echo "[fixtures] FAIL: $*" >&2
	exit 1
}

LOADER="${FIXTURE}/target/x86_64-unknown-linux-musl/release/pidhide-loader"
OBJECT="${FIXTURE}/ebpf/target/bpfel-unknown-none/release/pidhide-ebpf"

command -v cargo >/dev/null 2>&1 ||
	die "no cargo on PATH (install the toolchain: rustup toolchain install 1.98.1)"
rustup toolchain list 2>/dev/null | grep -q "nightly-2026-09-18" ||
	die "the bpfel build needs the dated nightly it is pinned to (install: rustup toolchain install nightly-2026-09-18 --profile minimal -t nightly-2026-09-18-rust-src)"

# Both cargo calls run with the same net posture CI carries: the
# committed locks answer every dependency, offline.
export CARGO_NET_OFFLINE=true

if [ "${FORCE}" -eq 1 ]; then
	note "forced rebuild: removing the fixture build trees first - a pair that predates the sources must never run again"
	rm -rf "${FIXTURE}/target" "${FIXTURE}/ebpf/target"
elif [ -x "${LOADER}" ] && [ -f "${OBJECT}" ]; then
	note "artifacts already present (rebuild skipped; pass -f to force)"
else
	note "building the pidhide loader (stable MSRV, x86_64-unknown-linux-musl)..."
	(
		cd "${FIXTURE}" &&
			cargo build --release --locked --offline \
				--target x86_64-unknown-linux-musl
	)

	note "building the pidhide ebpf object (nightly-2026-09-18, bpfel-unknown-none)..."
	(
		cd "${FIXTURE}/ebpf" &&
			RUSTUP_TOOLCHAIN=nightly-2026-09-18 cargo build --release --locked --offline \
				-Z build-std=core -Z json-target-spec
	)
fi

[ -x "${LOADER}" ] || die "the loader did not land: ${LOADER}"
[ -f "${OBJECT}" ] || die "the ebpf object did not land: ${OBJECT}"

note "loader: ${LOADER}"
note "object: ${OBJECT}"
note "the detonation resolves these from the fixture build tree; the rootfs seat (/opt/zejtron/.sandbox) wins when the artifacts are packed there (CI's lane)"
