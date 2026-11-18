#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# repro-build.sh (night-depth-hardening-Z1, the cosmostrix D4
# lineage): the LOCAL half of the reproducible release chain.
#
# Proves PROCESS identity on one host: two cold builds of the SAME
# commit, from the SAME checkout path, with the SAME pinned epoch
# and the release lane's EXACT RUSTFLAGS composition, must produce
# byte-identical release binaries. This is the local half of the
# chain; the two-host half lives in CI (.github/workflows/
# reproducible-release.yml: reproducible_build on two independent
# runners, no shared cache, and reproducible_verify's byte-identity
# cmp).
#
# Why the same checkout path: the release lane redacts ${PWD} and
# ${HOME}/.cargo through --remap-path-prefix, so the embedded path
# strings are constant regardless of the checkout location; building
# twice in place keeps every other input constant too. The CI job is
# the stronger proof (two truly independent hosts).
#
# What is pinned here:
#   - toolchain: rust-toolchain.toml (the repo's single version
#     source) + the eBPF nested lane's own pinned nightly
#     (ebpf/rust-toolchain.toml, bpf-linker pinned in
#     scripts/dev/bootstrap-ebpf.sh) - the source-built object is
#     part of the release bytes, so its toolchain pins are part of
#     the recipe
#   - epoch: SOURCE_DATE_EPOCH = the commit timestamp
#     (git log -1 --format=%ct), the same pin the CI reproducible
#     lane uses; build.rs honors it in ZEJTRON_BUILD_TIME
#   - flags: the release matrix's EXACT composition plus the redacted
#     path prefixes (-D warnings -C target-cpu=x86-64-v3 -C
#     target-feature=+crt-static --remap-path-prefix=${HOME}/.cargo=redacted
#     --remap-path-prefix=${PWD}=redacted)
#   - profile: release (codegen-units=1, thin LTO, strip, incremental
#     off) on x86_64-unknown-linux-musl - the exact shipped shape
#   - deps: --locked (Cargo.lock)
#
# Cost: two full optimized builds plus the nested eBPF build each
# pass. This script is opt-in - it is NOT wired into check-all; CI
# runs the two-host proof on every push, so a local run is only
# needed to reproduce a CI failure.
#
# Usage: bash scripts/release/repro-build.sh
# Requires: the dev toolchain on PATH (cargo, rustup, b3sum,
# bpf-linker - scripts/dev/bootstrap-ebpf.sh sets the eBPF half up).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

BIN_REL="target/x86_64-unknown-linux-musl/release/zejtron"
PROFILE_DIR="target/x86_64-unknown-linux-musl/release"

if ! command -v cargo >/dev/null 2>&1; then
	echo "error: cargo not found (the dev toolchain must be on PATH)" >&2
	exit 2
fi
if ! rustup target list --installed 2>/dev/null | grep -qx 'x86_64-unknown-linux-musl'; then
	echo "error: the pinned lane builds x86_64-unknown-linux-musl, which is not installed" >&2
	echo "  Fix: rustup target add x86_64-unknown-linux-musl" >&2
	exit 2
fi

# The pinned epoch: the commit timestamp, the same pin the CI
# reproducible lane exports. Identical on every host that checks out
# this commit - the stamp ZEJTRON_BUILD_TIME carries becomes part of
# the reproducible bytes instead of the builder's wall clock.
EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH="${EPOCH}"
export ZEJTRON_BUILD="pro-linux-amd64-v3-musl"
export RUSTFLAGS="-D warnings -C target-cpu=x86-64-v3 -C target-feature=+crt-static --remap-path-prefix=${HOME}/.cargo=redacted --remap-path-prefix=${PWD}=redacted"
export CARGO_INCREMENTAL=0

echo "repro-build: commit $(git rev-parse --short=7 HEAD), SOURCE_DATE_EPOCH=${EPOCH}"

# Artifacts are staged OUTSIDE target/: the cold wipe between passes
# removes the profile's build directory, and a stage inside target/
# would be destroyed with it.
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

build_once() {
	local label="$1"
	local dest="$2"
	echo "repro-build: building ${label} (full cold build, be patient)"
	cargo build --release --locked --target x86_64-unknown-linux-musl
	mkdir -p "$(dirname "${dest}")"
	cp "${BIN_REL}" "${dest}"
	# Cold wipe of ONLY the release lane's target directory: the proof
	# is about the PROCESS, so the next build recompiles the whole
	# graph from the lockfile (mirroring the cache-free CI lane)
	# without touching any other profile the machine may have built.
	# The nested eBPF object rebuilds with it - its determinism is
	# part of what this proof covers.
	rm -rf "${PROFILE_DIR}"
}

build_once "host-a (same host, cold pass 1)" "${STAGE}/host-a/zejtron"
build_once "host-b (same host, cold pass 2)" "${STAGE}/host-b/zejtron"

sha256sum "${STAGE}/host-a/zejtron" "${STAGE}/host-b/zejtron"
if cmp -s "${STAGE}/host-a/zejtron" "${STAGE}/host-b/zejtron"; then
	echo "REPRODUCIBLE RELEASE CHAIN (local, same host): PASS - two cold builds are byte-identical"
	echo "  artifact: ${STAGE}/host-a/zejtron"
else
	echo "REPRODUCIBLE RELEASE CHAIN (local, same host): FAIL - the two builds differ" >&2
	cmp -l "${STAGE}/host-a/zejtron" "${STAGE}/host-b/zejtron" | head -20 || true
	exit 1
fi
