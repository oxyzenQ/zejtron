#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
# OS: Linux only - zejtron is a Linux introspection tool.
#
# scripts/package/pack-local.sh - the local artifact packaging law
# (night-cafe-1, the sibling labs-exp shape).
#
# A locally built or patched zejtron binary is a product of THIS
# machine: the raw bytes never ride a commit. The tracked lane is the
# packaged pair - a gzip archive plus its blake3 sidecar - so another
# machine can verify what it receives without ever trusting a raw
# binary in git. The raw name class is already wall-walled in
# .gitignore (scripts/labs-exp/zejtron-fixed-*); this script produces
# the pair beside it and proves the walls hold.
#
# The contract:
#   1. Input: a raw binary path, plus an optional output name
#      (default: the binary's basename). The binary must be a regular
#      executable file - a truncated or wrong-path input fails here,
#      not downstream.
#   2. Package: `gzip -9 -n` (the -n drops the embedded timestamp and
#      original name, so the same input bytes produce the same archive
#      bytes - a re-pack is diff-stable) into
#      scripts/labs-exp/<name>.gz, then `b3sum` writes
#      scripts/labs-exp/<name>.b3sum (the lane's digest tool, the
#      prebuilt-manifest algorithm - sha256 is not the family's
#      checksum lane).
#   3. Verify, don't trust: the archive round-trips through
#      `gunzip -c` and the extracted bytes must blake3-match the
#      original binary byte-for-byte; then `b3sum -c` must accept the
#      sidecar against the archive. A package that fails either probe
#      is removed, never left half-shipped.
#   4. The walls are part of the output: `git check-ignore` must
#      ignore the raw name and must NOT ignore the .gz or .b3sum
#      sidecars. Any other verdict means the .gitignore lanes and the
#      packaging lane disagree - fail loudly, because that is the
#      silent-commit leak class this whole lane exists to close.
#
# Output land is scripts/labs-exp/ (the sibling's vendoring ground):
# the sidecar pair lands tracked-ready (644), the raw binary stays
# where it was - never moved, never copied into the tree.

set -euo pipefail

# The brand palette (night-cafe-1): verdicts and the digest line ride
# the same tiers the CLI renders. Defaults first so a missing lib
# degrades to mono; the source overrides with the depth-correct
# escapes (the depth ladder probes stdout once at source time). The
# source is the repo's one gate-recognized idiom (1d, fail-closed):
# anchored at this script's own path, climbing one directory up.
# shellcheck disable=SC2034 # the full tier set pre-seeds mono-safe; the source overrides
UX_BRAND="" UX_OK="" UX_ERR="" UX_WARN="" UX_GREY="" UX_WHITE="" UX_RESET=""
# shellcheck disable=SC1091 # the palette lib sits one directory up in scripts/lib
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/ux_palette.sh"

LABS_DIR="scripts/labs-exp"

die() {
	echo "${UX_ERR}pack-local: error: $*${UX_RESET}" >&2
	exit 1
}
ok() { echo "${UX_OK}pack-local: ok: $*${UX_RESET}"; }
warn() { echo "${UX_WARN}pack-local: warn: $*${UX_RESET}" >&2; }

usage() {
	echo "usage: $0 <binary> [name]" >&2
	echo "  <binary>  raw zejtron binary to package (must be a regular executable file)" >&2
	echo "  [name]    output name (default: the binary's basename)" >&2
	echo "  lands:    ${LABS_DIR}/<name>.gz + ${LABS_DIR}/<name>.b3sum" >&2
	exit 2
}

[ "${1:-}" = "--help" ] && usage
case "$#" in
1 | 2) ;;
*) usage ;;
esac

BINARY=$1
NAME=${2:-$(basename "$BINARY")}

command -v b3sum >/dev/null 2>&1 ||
	die "b3sum not on PATH - the lane's digest tool; install it: cargo install b3sum"
command -v gzip >/dev/null 2>&1 || die "gzip not on PATH"

[ -f "$BINARY" ] || die "not a regular file: $BINARY"
[ -x "$BINARY" ] || die "not executable: $BINARY"
case "$NAME" in
*/ | . | ..) die "refusing unsafe output name: $NAME" ;;
*)
	case "$NAME" in
	*.gz | *.b3sum) die "output name must be the raw name (no .gz / .b3sum suffix): $NAME" ;;
	esac
	;;
esac

GZ="$LABS_DIR/$NAME.gz"
B3="$LABS_DIR/$NAME.b3sum"
mkdir -p "$LABS_DIR"

# 2. Package: timestamp-free archive, then the blake3 sidecar.
gzip -9 -n -c "$BINARY" >"$GZ"
b3sum "$GZ" >"$B3"

# 3. Verify: the round-trip probe, then the sidecar probe. Both must
# pass or the pair is removed - a half-shipped package is worse than
# no package.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
gunzip -c "$GZ" >"$TMP/$NAME"
ORIG=$(b3sum "$BINARY" | cut -d' ' -f1)
ROUND=$(b3sum "$TMP/$NAME" | cut -d' ' -f1)
if [ "$ORIG" != "$ROUND" ]; then
	rm -f "$GZ" "$B3"
	die "round-trip mismatch - removed $GZ and $B3 (the archive does not reproduce the input)"
fi
if ! b3sum -c "$B3" >/dev/null 2>&1; then
	rm -f "$GZ" "$B3"
	die "sidecar mismatch - removed $GZ and $B3 (the digest does not match the archive)"
fi

# 4. The walls: raw ignored, sidecars trackable. The exact verdicts
# the .gitignore night-cafe-1 lanes promise.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	warn "not inside a git work tree - the staging walls were not probed"
elif git check-ignore -q "$LABS_DIR/$NAME"; then
	ok "wall holds: raw $LABS_DIR/$NAME is git-ignored (can never ride a commit)"
else
	die "wall BROKEN: raw $LABS_DIR/$NAME is NOT git-ignored - fix .gitignore before committing anything"
fi
for sidecar in "$GZ" "$B3"; do
	if git check-ignore -q "$sidecar"; then
		die "wall BROKEN: sidecar $sidecar is git-ignored - the tracked lane is the packaged pair"
	fi
done
ok "walls hold: sidecars $GZ and $B3 stay trackable"

SZ_RAW=$(wc -c <"$BINARY")
SZ_GZ=$(wc -c <"$GZ")
SUMMARY=$(b3sum "$GZ" | cut -d' ' -f1)
echo "${UX_WHITE}pack-local: packed $NAME: ${SZ_RAW} raw bytes -> ${SZ_GZ} archive bytes${UX_RESET}"
echo "${UX_WHITE}pack-local: blake3($GZ) = $SUMMARY${UX_RESET}"
echo "${UX_GREY}pack-local: verify on another machine: b3sum -c $B3 && gunzip -c $GZ > $NAME${UX_RESET}"
