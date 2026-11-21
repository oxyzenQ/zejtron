#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
#
# DEPENDENCY BAN CHECK (the local seat of deny.toml's [bans] family)
#
# The owner's dependency law: banned crates must not exist in ANY
# Cargo.lock of this repository. CI's `cargo deny check` (audit.yml)
# enforces the root workspace, but the ebpf/ crate is a DETACHED
# workspace — cargo-deny never sees its lock. This gate closes that
# gap with a tool-free read of every tracked lock file, so a banned
# crate cannot re-enter through a lane CI does not scan.
#
# Banned everywhere, no exceptions:
#   chrono, iana-time-zone, time  — the civil clock contract is
#     std-only (night-improve-13; src/info/clock.rs carries the math)
#   serde, serde_core, serde_derive, serde_json — the JSON lane is
#     hand-written in src/evidence/json.rs (std-only,
#     byte-deterministic); no crates exist only to move JSON
#
# The carve-outs, explicit and guarded:
#   ebpf/Cargo.lock carries serde/serde_json through UPSTREAM
#   aya-ebpf's unconditional build-dependency on aya-build (both 0.2.0
#   and 0.2.1; aya-build parses `cargo metadata` JSON via
#   cargo_metadata). That chain is host-side only - it runs aya-ebpf's
#   build.rs on the developer machine and never compiles into the
#   shipped bpfel-unknown-none object. Removing it means forking aya,
#   which trades a transient host-only path for a permanent fork the
#   project must rebase - rejected. The carve-out is shape-guarded:
#   serde-family crates are allowed in ebpf/Cargo.lock ONLY while
#   aya-build is their root cause. serde appearing in ebpf/ without
#   aya-build (a direct dependency added by hand) fails.
#   proofs/Cargo.lock carries the serde family through UPSTREAM
#   proptest's property-exhaustion graph (night-datapath-1: proptest →
#   bit-set → bit-vec's optional serde support, plus the toml reader
#   inside the same graph). The proofs package is a detached,
#   publish=false dev instrument - the root manifest's dependency
#   graph never sees it and nothing here ships in any binary; the
#   hand-written JSON lane's law is about SHIPPED bytes and holds. The
#   carve-out is shape-guarded the same way: serde-family crates are
#   allowed in proofs/Cargo.lock ONLY while proptest is in that lock
#   as their root cause. serde appearing in proofs/ without proptest
#   (a direct dependency added by hand) fails. serde appearing in the
#   root or any other lock fails, always.
#
# Usage: scripts/gates/check-dep-bans.sh
# Output: one line per finding; exit 0 clean / exit 1 on any finding.

set -euo pipefail

BANNED=(chrono iana-time-zone time serde serde_core serde_derive serde_json)
SERDE_FAMILY="serde serde_core serde_derive serde_json"
CARVE_OUT_ROOT="aya-build"
PROOFS_ROOT="proptest"

status=0

find_banned() {
	local lock="$1" crate="$2"
	grep -q "^name = \"${crate}\"$" "$lock"
}

for lock in $(git ls-files -- '*Cargo.lock' | sort); do
	for crate in "${BANNED[@]}"; do
		if ! find_banned "$lock" "$crate"; then
			continue
		fi
		if [ "$lock" = "ebpf/Cargo.lock" ] && [[ "${SERDE_FAMILY}" == *"$crate"* ]]; then
			# The guarded carve-out: allowed only as the
			# upstream aya-build probe chain's passenger.
			if grep -q "^name = \"${CARVE_OUT_ROOT}\"$" "$lock"; then
				echo "  carve-out (upstream aya-ebpf build probe): $lock: $crate"
			else
				echo "  BANNED (no aya-build chain - a direct dependency): $lock: $crate"
				status=1
			fi
		elif [ "$lock" = "proofs/Cargo.lock" ] && [[ "${SERDE_FAMILY}" == *"$crate"* ]]; then
			# The guarded carve-out: allowed only as the upstream
			# proptest graph's passenger in the detached dev
			# instrument (night-datapath-1).
			if grep -q "^name = \"${PROOFS_ROOT}\"$" "$lock"; then
				echo "  carve-out (upstream proptest graph, detached dev instrument): $lock: $crate"
			else
				echo "  BANNED (no proptest chain - a direct dependency): $lock: $crate"
				status=1
			fi
		else
			echo "  BANNED: $lock: $crate"
			status=1
		fi
	done
done

if [ "$status" -eq 0 ]; then
	echo "dependency ban check: clean (root and fuzz locks carry zero banned crates;"
	echo "ebpf carries only the upstream aya-build probe carve-out; proofs carries"
	echo "only the upstream proptest graph carve-out, detached and never shipped)"
fi

exit "$status"
