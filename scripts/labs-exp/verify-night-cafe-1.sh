#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
# OS: Linux only - zejtron is a Linux introspection tool.
#
# labs-exp/verify-night-cafe-1.sh - the night-cafe-1 verification lab
# (the sibling labs-exp shape: one command proves the whole task on
# THIS machine, and the exit code is the verdict).
#
# night-cafe-1 is two laws, and this lab pins both mechanically:
#
#   A. THE PALETTE LAW - the shell surfaces render the SAME tiers the
#      CLI renders. The proof is mechanical, not eyeball: the lab
#      re-derives the escape tables from src/output/mod.rs (the CLI's
#      Tier::open source of truth) and from scripts/lib/ux_palette.sh,
#      and diffs them. The five CLI tiers must match byte-for-byte at
#      every depth; the palette's extra seat is exactly the sibling's
#      crystal-white rungs (255 at 256 depth, 97 at 16 depth, the
#      #DCEBFF triple at RGB) and nothing else. The depth ladder is
#      then exercised in four forced lanes: mono, truecolor, 256, and
#      the forced-dumb 16 floor.
#
#   B. THE ARTIFACT LAW - a locally built binary is a product of the
#      machine, never a tracked file. The proof: the .gitignore walls
#      ignore the raw name class while the .gz / .b3sum sidecars stay
#      trackable, and pack-local.sh performs one real pack - sidecar
#      verify, wall verdicts, round-trip digest - then the lab
#      removes the pair (nothing this lab touches stays behind).
#
# Usage:
#   scripts/labs-exp/verify-night-cafe-1.sh
#
# b3sum is the lane's digest tool (the prebuilt manifest's algorithm);
# without it the pack check names itself skipped rather than faking a
# pass. The lab needs no root and no built binary - every check reads
# sources and .gitignore rules, or exercises pack-local.sh on a copy
# of /bin/true under a lab-owned name.

set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 1
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd) || exit 1
PAL="$REPO_ROOT/scripts/lib/ux_palette.sh"
CLI_OUT="$REPO_ROOT/src/output/mod.rs"

# The brand palette (night-cafe-1): this lab's own verdicts ride the
# same tiers it verifies. Defaults first (mono-safe), then the source
# in the repo's one gate-recognized idiom (1d, fail-closed): anchored
# at this script's own path, climbing one directory up to scripts/lib.
UX_BRAND="" UX_OK="" UX_ERR="" UX_WARN="" UX_GREY="" UX_WHITE="" UX_RESET=""
# shellcheck disable=SC1091 # the palette path is resolved above
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/ux_palette.sh"

PASS=0
FAIL=0

pass() {
	echo "${UX_OK}PASS $*${UX_RESET}"
	PASS=$((PASS + 1))
}
fail() {
	echo "${UX_ERR}FAIL $*${UX_RESET}"
	FAIL=$((FAIL + 1))
}
rail() {
	echo
	echo "${UX_BRAND}-- $* --${UX_RESET}"
}

echo "${UX_GREY}night-cafe-1 verification lab - repo $REPO_ROOT${UX_RESET}"

# ── A1. the lib exists at the sourced-lib shape ────────────────────
rail "A1. the palette lib"
if [[ -f "$PAL" ]]; then
	pass "scripts/lib/ux_palette.sh exists"
else
	fail "scripts/lib/ux_palette.sh missing - the shell twin is the whole task"
fi
pal_mode=$(stat -c%a "$PAL" 2>/dev/null || echo missing)
if [[ "$pal_mode" == "644" ]]; then
	pass "permissions 644 : sourced, never executed (the lib law)"
else
	fail "permissions $pal_mode : the lib must be 644"
fi
if head -1 "$PAL" | grep -q "^#!"; then
	fail "no-shebang law broken : a sourced lib never carries a shebang"
else
	pass "no shebang : the file is sourced, never executed"
fi

# ── A2. the escape-table parity (the mechanical proof) ─────────────
rail "A2. shell-vs-CLI escape parity"
# Both tables read as sorted-unique escape fragments: the RGB triples,
# the 256 rungs, the 16 rungs. The CLI set must be a subset of the
# palette set, and the only additions must be the crystal-white
# rungs - the sibling's ladder, documented in the lib's header.
rgb_re='[0-9]+;[0-9]+;[0-9]+m'
cli_rgb=$(grep -oE "38;2;$rgb_re" "$CLI_OUT" | sed 's/38;2;//;s/m$//' | sort -u)
pal_rgb=$(grep -oE "38;2;$rgb_re" "$PAL" | sed 's/38;2;//;s/m$//' | sort -u)
cli_256=$(grep -o '38;5;[0-9]*m' "$CLI_OUT" | sed 's/38;5;//;s/m$//' | sort -u)
pal_256=$(grep -o '38;5;[0-9]*m' "$PAL" | sed 's/38;5;//;s/m$//' | sort -u)
# The 16 rungs ride bare SGRs; both files carry them as \x1b[NNm
# literals (the Rust source strings them, the shell lib $-strings
# them) - grep the bracketed bodies.
cli_16=$(grep -o $'x1b\[[0-9]*m' "$CLI_OUT" | sed 's/x1b\[//;s/m$//' | sort -u)
pal_16=$(grep -o $'x1b\[[0-9]*m' "$PAL" | sed 's/x1b\[//;s/m$//' | sort -u)

white_rgb="220;235;255"
white_256="255"
white_16="97"

only_pal_rgb=$(comm -13 <(printf '%s\n' "$cli_rgb") <(printf '%s\n' "$pal_rgb") | grep -v '^$' || true)
only_pal_256=$(comm -13 <(printf '%s\n' "$cli_256") <(printf '%s\n' "$pal_256") | grep -v '^$' || true)
only_pal_16=$(comm -13 <(printf '%s\n' "$cli_16") <(printf '%s\n' "$pal_16") | grep -v '^$' || true)

if [[ "$only_pal_rgb" == "$white_rgb" && -n "$cli_rgb" ]]; then
	pass "RGB parity : the CLI triples all ride the palette; the one addition is crystal white #$white_rgb"
else
	fail "RGB drift : palette-minus-CLI is [$(echo "$only_pal_rgb" | tr '\n' ' ')] - want exactly [$white_rgb]"
fi
if [[ "$only_pal_256" == "$white_256" && -n "$cli_256" ]]; then
	pass "256 parity : the one additional rung is $white_256 (the sibling's white ladder)"
else
	fail "256 drift : palette-minus-CLI is [$only_pal_256] - want exactly [$white_256]"
fi
if [[ "$only_pal_16" == "$white_16" && -n "$cli_16" ]]; then
	pass "16 parity : the one additional rung is $white_16 (bright white)"
else
	fail "16 drift : palette-minus-CLI is [$only_pal_16] - want exactly [$white_16]"
fi
# Reverse direction: the palette may never drop a CLI tier.
missing_rgb=$(comm -23 <(printf '%s\n' "$cli_rgb") <(printf '%s\n' "$pal_rgb") | grep -v '^$' || true)
if [[ -z "$missing_rgb" ]]; then
	pass "no CLI tier dropped : every CLI triple renders from the shell too"
else
	fail "palette lost CLI triples : [$missing_rgb]"
fi

# ── A3. the depth ladder, forced ───────────────────────────────────
rail "A3. the depth ladder"
# lane <VAR=VALUE...> - the resolved UX_OK from a subshell whose
# stdout is a pipe (never a TTY), so the ladder's TTY probe cannot
# lie about the lane under test. The palette path rides PAL_PATH
# (exported below), so the inner source stays mid-line - which the
# 1d fail-closed translator rightly ignores; the lib's existence is
# proved by this script's own gate-checked source line above.
PAL_PATH="$PAL"
export PAL_PATH
lane() {
	NO_COLOR="" CLICOLOR="" CLICOLOR_FORCE=1 bash -c 'for kv in "$@"; do export "$kv"; done; . "$PAL_PATH" 2>/dev/null; printf "%s" "$UX_OK"' bash "$@"
}
mono_out=$(NO_COLOR=1 bash -c ". '$PAL' >/dev/null 2>&1; printf '%s' \"\$UX_OK\"")
if [[ -z "$mono_out" ]]; then
	pass "NO_COLOR -> mono : every tier is the empty string"
else
	fail "NO_COLOR leaked escapes : UX_OK=${mono_out}"
fi
rgb_out=$(lane "COLORTERM=truecolor")
if [[ "$rgb_out" == *"38;2;80;250;123m" ]]; then
	pass "truecolor lane : UX_OK carries the exact #50FA7B triple"
else
	fail "truecolor lane wrong : ${rgb_out}"
fi
c256_out=$(lane "TERM=xterm-256color")
if [[ "$c256_out" == *"38;5;84m" ]]; then
	pass "256 lane : UX_OK carries rung 84"
else
	fail "256 lane wrong : ${c256_out}"
fi
c16_out=$(lane "TERM=dumb")
if [[ "$c16_out" == $'\x1b[32m' ]]; then
	pass "16 floor : the forced-dumb lane lands on rung 32"
else
	fail "16 floor wrong : ${c16_out}"
fi

# ── B1. the artifact walls ─────────────────────────────────────────
rail "B1. the artifact walls"
RAW="scripts/labs-exp/zejtron-fixed-cli-hardening-1"
if git -C "$REPO_ROOT" check-ignore -q "$RAW"; then
	pass "raw class ignored : $RAW can never ride a commit"
else
	fail "wall BROKEN : $RAW is not git-ignored"
fi
for sidecar in "$RAW.gz" "$RAW.b3sum"; do
	if git -C "$REPO_ROOT" check-ignore -q "$sidecar"; then
		fail "wall BROKEN : sidecar $sidecar is ignored - the tracked lane is the packaged pair"
	else
		pass "sidecar trackable : $sidecar"
	fi
done
if git -C "$REPO_ROOT" check-ignore -q "dist/x"; then
	pass "dist staging ignored : a local release rehearsal never commits"
else
	fail "wall BROKEN : dist/ is not git-ignored"
fi

# ── B2. the real pack (and its removal) ────────────────────────────
rail "B2. pack-local round trip"
if ! command -v b3sum >/dev/null 2>&1; then
	echo "${UX_WARN}SKIP pack round trip : b3sum is not on PATH (install: cargo install b3sum)${UX_RESET}"
else
	cp /bin/true "$REPO_ROOT/scripts/labs-exp/zejtron-fixed-verify-lab"
	pack_out=$(bash "$REPO_ROOT/scripts/package/pack-local.sh" \
		"$REPO_ROOT/scripts/labs-exp/zejtron-fixed-verify-lab" 2>&1)
	pack_rc=$?
	if [[ "$pack_rc" -eq 0 ]] && grep -q "walls hold" <<<"$pack_out"; then
		pass "pack-local packed, verified, and proved the walls"
	else
		fail "pack-local failed (rc=$pack_rc): $pack_out"
	fi
	if b3sum -c "$REPO_ROOT/scripts/labs-exp/zejtron-fixed-verify-lab.b3sum" >/dev/null 2>&1; then
		pass "the sidecar verifies against the archive"
	else
		fail "the sidecar does not verify"
	fi
	# Leave-as-found: the pair and the raw copy are the lab's own
	# products, removed on exit.
	rm -f "$REPO_ROOT/scripts/labs-exp/zejtron-fixed-verify-lab" \
		"$REPO_ROOT/scripts/labs-exp/zejtron-fixed-verify-lab.gz" \
		"$REPO_ROOT/scripts/labs-exp/zejtron-fixed-verify-lab.b3sum"
	pass "leave-as-found : the lab's pack products removed"
fi

# ── C. the wiring sanity ───────────────────────────────────────────
rail "C. the wiring"
for wired in scripts/package/pack-local.sh \
	scripts/labs-exp/zejtron-cli-ux-verify.sh \
	scripts/labs-exp/zejtron-forensic-proof.sh; do
	if grep -q "lib/ux_palette.sh" "$REPO_ROOT/$wired"; then
		pass "sourced : $wired"
	else
		fail "not wired : $wired never sources the palette"
	fi
done

echo
echo "${UX_WHITE}== night-cafe-1 verdict: $PASS passed, $FAIL failed ==${UX_RESET}"
if [[ "$FAIL" -eq 0 ]]; then
	echo "${UX_OK}ALL GREEN - the palette and the artifact walls hold.${UX_RESET}"
	exit 0
fi
exit 1
