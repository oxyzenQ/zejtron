#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool; no other OS
# is supported (the object is a bpfel ELF; the recipe is git + coreutils).
#
# regenerate-ebpf-prebuilt.sh (night-improve-5) — rebuild the kernel
# tap object and refresh ebpf-prebuilt/ after any change under ebpf/.
# This script is the ONE WRITER of the prebuilt lane; build/ebpf.rs's
# registry lane only stages what this script wrote (and verifies the
# manifest's object sha against the staged bytes before embedding),
# and scripts/gates/check-commit-gate.sh enforces the pin at commit
# time through this script's read-only --check verdict. One writer,
# one reader-shaped gate, no second implementation of the recipe.
#
# The manifest's ebpf_tree_sha256 recipe (the zylaxion night-improve-31
# shape, documented here so the number is reproducible from now on):
#
#   git ls-files -z -- ebpf/ | LC_ALL=C sort -z \
#     | xargs -0 -r sha256sum | sha256sum
#
# (the sha256 over the LC_ALL=C byte-sorted, NUL-separated sha256sum
# listing of the git-tracked ebpf/ files — one "digest  path" line
# per file, list hashed as a whole). The hashed listing carries each
# file's path, so a content-preserving rename under ebpf/ still stales
# the pin (the pin describes the tree, not just its content multiset),
# and the NUL-separated -z pipeline is locale-proof and newline-proof
# by construction.
#
# Host-independence law (inherited from the zylaxion lineage): the
# manifest pins are the TREE (a deterministic git fact), the STAGED
# object's identity (sha256 + size), the toolchain pin, and the
# version mirror. A fresh rebuild's bytes are deliberately NOT
# compared against the pinned object — byte reproducibility is a
# host property, and a foreign rebuild must never churn the lane.
# The tree-sha pin is the staleness surface; the staged copy's sha
# and size are the lane-integrity surface.
#
# Usage:
#   ./scripts/dev/regenerate-ebpf-prebuilt.sh          # rebuild + rewrite
#   ./scripts/dev/regenerate-ebpf-prebuilt.sh --check  # read-only verdict
#
# Exit codes: 0 in sync (or the rewrite succeeded); 1 stale/drift
# (or the build/prerequisite step failed); 2 usage error.

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

OBJECT_NAME="zejtron-ebpf"
STAGED_OBJECT="ebpf-prebuilt/${OBJECT_NAME}.o"
MANIFEST="ebpf-prebuilt/manifest.toml"
BUILT_OBJECT="ebpf/target/bpfel-unknown-none/release/${OBJECT_NAME}"
# The validated build pair's second half (the dated nightly pin is the
# first half, read live from ebpf/rust-toolchain.toml). Kept in
# lockstep with build/ebpf.rs's BPF_LINKER_VERSION constant.
BPF_LINKER_VERSION="0.11.1"
# The six attach targets the loader plants (src/ebpf/loader.rs). The
# manifest documents the contract; the commit that changes the tap set
# edits this list in the same commit.
ATTACH_TARGETS="\"sched_process_exec\", \"inet_sock_set_state\", \"vfs_open\", \"vfs_write\", \"sched_process_fork\", \"sched_process_exit\""

# The version mirror law: root Cargo.toml, ebpf/Cargo.toml, and the
# manifest's [contract] version must all say the same thing. The
# --check verdict enforces the triple; the rewrite derives its version
# from the ebpf/ tree it describes.
tree_version() {
        awk -F'"' '/^version = /{print $2; exit}' ebpf/Cargo.toml
}

root_version() {
        awk -F'"' '/^version = /{print $2; exit}' Cargo.toml
}

tree_sha256() {
        git ls-files -z -- ebpf/ | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}'
}

toolchain_pin() {
        awk -F'"' '/^channel/{print $2; exit}' ebpf/rust-toolchain.toml
}

if [ "${1:-}" = "--check" ]; then
        [ "$#" -eq 1 ] || { echo "usage: $0 [--check]" >&2; exit 2; }
        STALE=0
        [ -f "$MANIFEST" ] || { echo "stale: $MANIFEST is missing entirely"; exit 1; }
        [ -f "$STAGED_OBJECT" ] || { echo "stale: the staged $STAGED_OBJECT is missing"; exit 1; }

        TREE_NOW="$(tree_sha256)"
        STAGED_SHA="$(sha256sum "$STAGED_OBJECT" | awk '{print $1}')"
        STAGED_SIZE="$(stat -c %s "$STAGED_OBJECT")"
        PIN_TREE="$(awk -F'"' '/^ebpf_tree_sha256 = /{print $2}' "$MANIFEST")"
        PIN_OBJ="$(awk -F'"' '/^sha256 = /{print $2; exit}' "$MANIFEST")"
        PIN_SIZE="$(awk -F' = ' '/^size = /{print $2; exit}' "$MANIFEST")"
        PIN_TOOLCHAIN="$(awk -F'"' '/^toolchain = /{print $2; exit}' "$MANIFEST")"
        PIN_VERSION="$(awk -F'"' '/^version = /{print $2; exit}' "$MANIFEST")"

        [ "$TREE_NOW" = "$PIN_TREE" ] || { echo "stale: manifest ebpf_tree_sha256 lags the ebpf/ tree ($PIN_TREE -> $TREE_NOW)"; STALE=1; }
        [ "$STAGED_SHA" = "$PIN_OBJ" ] || { echo "stale: the staged $STAGED_OBJECT is not the pinned object bytes ($PIN_OBJ -> $STAGED_SHA)"; STALE=1; }
        [ "$STAGED_SIZE" = "$PIN_SIZE" ] || { echo "stale: the staged object size no longer matches the pin ($PIN_SIZE -> $STAGED_SIZE)"; STALE=1; }
        [ "$(toolchain_pin)" = "$PIN_TOOLCHAIN" ] || { echo "stale: manifest toolchain lags ebpf/rust-toolchain.toml ($PIN_TOOLCHAIN -> $(toolchain_pin))"; STALE=1; }

        # The version mirror, enforced with the rest of the pins: the
        # manifest, the ebpf/ tree, and the root manifest must agree.
        [ "$(tree_version)" = "$PIN_VERSION" ] || { echo "stale: manifest [contract] version lags ebpf/Cargo.toml ($PIN_VERSION -> $(tree_version))"; STALE=1; }
        [ "$(root_version)" = "$(tree_version)" ] || { echo "stale: the version mirror is broken - root Cargo.toml ($(root_version)) != ebpf/Cargo.toml ($(tree_version))"; STALE=1; }

        [ "$STALE" -eq 0 ] && { echo "in sync: manifest pins match the ebpf/ tree, the staged copy, the toolchain pin, and the version mirror"; exit 0; }
        exit 1
fi

[ "$#" -eq 0 ] || { echo "usage: $0 [--check]" >&2; exit 2; }

# ── Preflight: the two source-build prerequisites, named on failure ──
# Mirrors build/ebpf.rs's preflight (the same pair, the same fix
# message shape) so both entries into the nested build fail the same
# way before compile time is spent.
PIN="$(toolchain_pin)"
[ -n "$PIN" ] || { echo "could not read the channel pin from ebpf/rust-toolchain.toml - the file is part of the tree; restore it or re-clone" >&2; exit 1; }
if ! command -v rustup >/dev/null 2>&1 \
        || ! rustup toolchain list 2>/dev/null | grep -q "^${PIN}-"; then
        echo "the eBPF source-build needs the dated nightly pin ${PIN} (rust-src included) and it is not installed." >&2
        echo "One command: rustup toolchain install ${PIN} --profile minimal --component rust-src (or ./scripts/dev/bootstrap-ebpf.sh)" >&2
        exit 1
fi
LINKER_REPORT="$(bpf-linker --version 2>/dev/null || true)"
if ! printf '%s' "$LINKER_REPORT" | grep -q "$BPF_LINKER_VERSION"; then
        echo "the eBPF source-build needs bpf-linker ${BPF_LINKER_VERSION} on PATH and rustc cannot invoke it ('${LINKER_REPORT:-no answer}')." >&2
        echo "One command: ./scripts/dev/bootstrap-ebpf.sh (installs the pin plus the pinned linker release)" >&2
        exit 1
fi

# ── The nested build: the same invocation build/ebpf.rs drives ───────
# rustup run forces the dated pin (the CARGO env a build script hands
# down resolves to the stable cargo, which would drop the -Z flags);
# cwd inside ebpf/ keeps the crate's .cargo/config.toml in effect.
# The inherited rustflags get the same host-poison strip and v3 force
# build/ebpf.rs applies (env rustflags shadow config; host-CPU flags
# are poison for bpfel; the v3 level is what selects BPF_ATOMIC).
FLAGS="${RUSTFLAGS:-}"
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
        FLAGS="${FLAGS} ${CARGO_ENCODED_RUSTFLAGS//$'\x1f'/ }"
fi
FILTERED=""
for token in $FLAGS; do
        case "$token" in
                *target-cpu* | *linker=* | *link-self-contained*) ;; # host poison, dropped
                *) FILTERED="${FILTERED}${FILTERED:+ }${token}" ;;
        esac
done
export RUSTFLAGS="${FILTERED} -Ctarget-cpu=v3"

echo "building the tap object (${PIN}, bpf-linker ${BPF_LINKER_VERSION})..."
(
        cd ebpf
        env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC -u RUSTC_WORKSPACE_WRAPPER -u RUSTC_WRAPPER \
                rustup run "$PIN" cargo build --release --locked \
                --target bpfel-unknown-none.json --package zejtron-ebpf \
                -Z build-std=core -Z json-target-spec
)

[ -f "$BUILT_OBJECT" ] || { echo "the build reported success but no object landed at $BUILT_OBJECT" >&2; exit 1; }

# ── The rewrite: stage the object, recompute every pin, write ────────
TREE_SHA="$(tree_sha256)"
OBJ_SHA="$(sha256sum "$BUILT_OBJECT" | awk '{print $1}')"
OBJ_SIZE="$(stat -c %s "$BUILT_OBJECT")"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION="$(tree_version)"
BUILT_BY="$(git config user.name >/dev/null 2>&1 && git config user.email >/dev/null 2>&1 \
        && printf '%s <%s>' "$(git config user.name)" "$(git config user.email)" \
        || printf 'oxyzenQ <130107241+oxyzenQ@users.noreply.github.com>')"

mkdir -p ebpf-prebuilt
install -m 644 "$BUILT_OBJECT" "$STAGED_OBJECT"

cat > "$MANIFEST" <<EOF
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# zejtron prebuilt eBPF object manifest (night-improve-5, the zylaxion
# night-improve-23 shape). Regenerated ONLY by
# scripts/dev/regenerate-ebpf-prebuilt.sh - the one writer of the
# lane; scripts/gates/check-commit-gate.sh enforces the pins at commit
# time through the same script's read-only --check verdict, and
# build/ebpf.rs's registry lane verifies the object sha against the
# staged bytes before embedding them. ebpf_tree_sha256 pins the exact
# ebpf/ source tree the object was built from: the sha256 over the
# LC_ALL=C byte-sorted (NUL-separated) sha256sum listing of the
# git-tracked ebpf/ files - one "digest  path" line per file, list
# hashed as a whole (the zylaxion night-improve-31 recipe). The
# [contract] version is the version mirror law: it must equal the
# root Cargo.toml and ebpf/Cargo.toml versions, and the --check
# verdict fails the commit when the three disagree. These are the
# bytes a registry-install build embeds.

schema = 1
generated = "${GENERATED}"
toolchain = "${PIN}"
bpf_linker = "${BPF_LINKER_VERSION}"
ebpf_tree_sha256 = "${TREE_SHA}"
built_by = "${BUILT_BY}"

[[object]]
name = "${OBJECT_NAME}"
sha256 = "${OBJ_SHA}"
size = ${OBJ_SIZE}

[contract]
# The six attach targets the loader plants (src/ebpf/loader.rs),
# documented for the registry consumer; a tap-set change rewrites
# this list in the same commit that changes the ebpf/ tree.
attach_targets = [${ATTACH_TARGETS}]
version = "${VERSION}"
EOF

echo "manifest written: ${MANIFEST} (object ${OBJ_SHA}, ${OBJ_SIZE} bytes, tree ${TREE_SHA})"
