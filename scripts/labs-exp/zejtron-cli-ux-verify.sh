# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
# OS: Linux only - zejtron is a Linux introspection tool.
#
# labs-exp/zejtron-cli-ux-verify.sh - the CLI UX hardening verifier
# (night-total-hardening-1 follow-up).
#
# Runs the complete usage-error contract against a zejtron binary so
# the owner can verify the fixes on any machine in one shot. Every
# check names the contract it pins; the exit code is the verdict
# (0 = all green).
#
# The binary resolves through the shared estate law
# (lib/zejtron-bin.sh): an explicit argument wins, then
# $ZEJTRON_BIN_PATH, then discovery under the repo's target/ tree -
# the profile-named lanes (pro-native-musl and friends) rank above
# the basic release dir, the newest executable wins within a tier.
#
# Usage:
#   scripts/labs-exp/zejtron-cli-ux-verify.sh [path-to-binary]
#   ZEJTRON_BIN_PATH=/path/to/zejtron scripts/labs-exp/zejtron-cli-ux-verify.sh
#   ZEJTRON_ALLOW_STALE=1 ... (verify a binary built from another
#   commit on purpose; see the build-fingerprint guard below)

set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 1
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd) || exit 1

# The brand palette (night-cafe-1): verdict tokens, rails, and the
# emphasized lines ride the same tiers the CLI renders. Defaults come
# first so a missing lib degrades to mono, never to a set -u crash;
# the source overrides them with the depth-correct escapes.
UX_BRAND="" UX_OK="" UX_ERR="" UX_WARN="" UX_GREY="" UX_WHITE="" UX_RESET=""
# shellcheck disable=SC1091 # the palette lib sits beside this lab in scripts/lib
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/ux_palette.sh"

# The shared resolver (one authority for every script that exercises
# the binary): explicit arg, then ZEJTRON_BIN_PATH, then target
# discovery with the profile-over-basic preference.
# shellcheck disable=SC1091 # the dynamic resolver path; its existence is the source-resolution gate's fact
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/zejtron-bin.sh"

zejtron_resolve_bin BIN "$REPO_ROOT" "${1:-}"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
	echo "${UX_ERR}verify: no zejtron binary found (tried the argument, ZEJTRON_BIN_PATH, and target/ discovery)${UX_RESET}" >&2
	echo "${UX_ERR}verify: build one first - cargo build --release (or scripts/build.sh check-all)${UX_RESET}" >&2
	exit 2
fi
echo "${UX_GREY}verify: binary $BIN${UX_RESET}"

# The build-fingerprint guard: the verdict is only honest when the
# binary under test was built from the tree the lab rides in. A
# target/ discovery that resolves a binary from an older commit
# reports the fixed contract as failing - it reads like a regression
# when it is only a stale build. An explicit target (the argument or
# ZEJTRON_BIN_PATH) is deliberate and only warns; ZEJTRON_ALLOW_STALE=1
# is the on-purpose bypass for either lane. A tree without git or a
# binary without a Build commit skips the guard silently.
head_commit=""
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	head_commit=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null | cut -c1-7)
fi
bin_commit=$("$BIN" -V 2>/dev/null | sed -n 's/^Build:.*(\([0-9a-f]\{7,40\}\)).*/\1/p' | cut -c1-7)
if [[ -n "$head_commit" && -n "$bin_commit" && "$bin_commit" != "$head_commit" ]]; then
	if [[ -n "${1:-}" || -n "${ZEJTRON_BIN_PATH:-}" || "${ZEJTRON_ALLOW_STALE:-0}" == 1 ]]; then
		echo "${UX_WARN}verify: WARNING the binary is built from $bin_commit, the tree is at $head_commit - the verdict covers the binary, not the tree${UX_RESET}"
	else
		echo "${UX_ERR}verify: the binary is built from $bin_commit, but the tree is at $head_commit${UX_RESET}" >&2
		echo "${UX_ERR}verify: a stale target binary makes the verdict lie - rebuild first, then re-run${UX_RESET}" >&2
		echo "${UX_ERR}verify:   cargo build --release   (or scripts/package/install-on-my-machine.sh)${UX_RESET}" >&2
		echo "${UX_ERR}verify: set ZEJTRON_ALLOW_STALE=1 to verify the old binary on purpose${UX_RESET}" >&2
		exit 2
	fi
fi

PASS=0
FAIL=0

# expect_exit <expected-code> <description> <args...>
expect_exit() {
	local want="$1" desc="$2"
	shift 2
	"$BIN" "$@" >/dev/null 2>&1
	local got=$?
	if [[ "$got" -eq "$want" ]]; then
		echo "${UX_OK}PASS exit=$want : $desc${UX_RESET}"
		PASS=$((PASS + 1))
	else
		echo "${UX_ERR}FAIL exit=$got (want $want) : $desc${UX_RESET}"
		FAIL=$((FAIL + 1))
	fi
}

# expect_tip <needle> <description> <args...>
# The tip line must exist (a rescue fired) - the one-tip contract is
# checked separately, so exactly-one-tip is not asserted here.
expect_tip() {
	local needle="$1" desc="$2"
	shift 2
	local out
	out=$("$BIN" "$@" 2>&1 >/dev/null)
	if [[ "$out" == *"$needle"* ]]; then
		echo "${UX_OK}PASS tip '$needle' : $desc${UX_RESET}"
		PASS=$((PASS + 1))
	else
		echo "${UX_ERR}FAIL tip '$needle' missing : $desc${UX_RESET}"
		FAIL=$((FAIL + 1))
	fi
}

# expect_no_tip <needle> <description> <args...>
expect_no_tip() {
	local needle="$1" desc="$2"
	shift 2
	local out
	out=$("$BIN" "$@" 2>&1 >/dev/null)
	if [[ "$out" != *"$needle"* ]]; then
		echo "${UX_OK}PASS absent '$needle' : $desc${UX_RESET}"
		PASS=$((PASS + 1))
	else
		echo "${UX_ERR}FAIL found '$needle' : $desc${UX_RESET}"
		FAIL=$((FAIL + 1))
	fi
}

# expect_output <needle> <description> <args...>
expect_output() {
	local needle="$1" desc="$2"
	shift 2
	local out
	out=$("$BIN" "$@" 2>/dev/null)
	if [[ "$out" == *"$needle"* ]]; then
		echo "${UX_OK}PASS output '$needle' : $desc${UX_RESET}"
		PASS=$((PASS + 1))
	else
		echo "${UX_ERR}FAIL output '$needle' missing : $desc${UX_RESET}"
		FAIL=$((FAIL + 1))
	fi
}

echo "${UX_BRAND}-- 1. the ceiling wording (the pro-mode row sync) --${UX_RESET}"
expect_output "(0-1000000)" "--limit row mirrors the CLI struct" -h
expect_output "(1-1024)" "--depth row mirrors the CLI struct" -h
expect_no_tip "default 20)" "stale --limit wording is gone" -h
expect_no_tip "minimum 1)" "stale --depth wording is gone" -h

echo "${UX_BRAND}-- 2. the case-variant subcommand rescue --${UX_RESET}"
expect_tip "a similar subcommand exists: 'port'" "PORT names the real verb" PORT
expect_tip "a similar subcommand exists: 'holds'" "WHOHOLDS lands on the successor" WHOHOLDS
expect_exit 2 "case-variant verbs stay usage errors" PORT

echo "${UX_BRAND}-- 3. clap's own tips survive (the fallback never doubles) --${UX_RESET}"
expect_tip "a similar subcommand exists: 'proc'" "prco keeps clap's own tip" prco

echo "${UX_BRAND}-- 4. the migration redirects (exact spellings) --${UX_RESET}"
expect_tip "'holds'" "whoholds redirects to holds" whoholds
expect_tip "'touch'" "lasttouch redirects to touch" lasttouch
expect_tip "'why'" "whyopen redirects to why" whyopen
expect_tip "'path'" "envpath redirects to path" envpath
expect_tip "zejtron --help" "help lands on the reference" help

echo "${UX_BRAND}-- 5. the non-UTF-8 argv contract (no panic) --${UX_RESET}"
expect_exit 2 "invalid UTF-8 is a usage error, not exit 101" holds $'\xff'
rendered=$("$BIN" holds $'\xff' 2>&1 >/dev/null || true)
if [[ "$rendered" == *"invalid UTF-8"* ]] && [[ "$rendered" != *"panicked"* ]]; then
	echo "${UX_OK}PASS clean render : the UTF-8 refusal renders, no backtrace note${UX_RESET}"
	PASS=$((PASS + 1))
else
	echo "${UX_ERR}FAIL render : $rendered${UX_RESET}"
	FAIL=$((FAIL + 1))
fi

echo "${UX_BRAND}-- 6. the case-variant flag rescue (proc lane) --${UX_RESET}"
expect_tip "a similar argument exists: '--me'" "proc --ME names the real flag" proc --ME
expect_tip "a similar argument exists: '--depth'" "proc --Depth rescues" proc --Depth

echo "${UX_BRAND}-- 7. the top-level authority rescue --${UX_RESET}"
expect_tip "--check-update" "subcommand-scoped --check-updated names the top level" proc --check-updated

echo "${UX_BRAND}-- 8. the one-tip contract (rescued errors carry exactly one tip) --${UX_RESET}"
for probe in PORT WHOHOLDS; do
	tips=$("$BIN" "$probe" 2>&1 >/dev/null | grep -c "tip: " || true)
	if [[ "$tips" -eq 1 ]]; then
		echo "${UX_OK}PASS one tip : $probe${UX_RESET}"
		PASS=$((PASS + 1))
	else
		echo "${UX_ERR}FAIL tip count $tips : $probe${UX_RESET}"
		FAIL=$((FAIL + 1))
	fi
done

echo "${UX_BRAND}-- 9. the exit-code law (help 0, usage 2, runtime 1) --${UX_RESET}"
expect_exit 0 "-h exits 0" -h
expect_exit 0 "--help exits 0" --help
expect_exit 0 "-V exits 0 on stdout" -V
expect_exit 0 "verb -V short-circuits before required args" path -V
expect_exit 1 "runtime failure keeps exit 1" path /definitely/not/a/real/command-xyz

echo "${UX_BRAND}-- 10. the depth-matrix signature (night-signature-advanced-1) --${UX_RESET}"
expect_output "Depth-sig: fp=" "-V carries the masked scheme's status line" -V
expect_output "status=verified anchor=b3:" "-V reports the verified anchor over the masked payload" -V
expect_exit 0 "sig verifies the running binary" sig
expect_exit 0 "the long 'signature' spelling rides the same arm" signature
sigverdict=$("$BIN" sig 2>/dev/null | sed -n 's/^verdict: //p')
if [[ "$sigverdict" == "SIGNATURE: AUTHENTIC (4/4 depths verified)" ]]; then
	echo "${UX_OK}PASS verdict : the matrix closes with the full-authentic line${UX_RESET}"
	PASS=$((PASS + 1))
else
	echo "${UX_ERR}FAIL verdict : $sigverdict${UX_RESET}"
	FAIL=$((FAIL + 1))
fi
sigjson=$("$BIN" sig --print-json 2>/dev/null)
if [[ "$sigjson" == *'"verdict":"AUTHENTIC"'* ]] && [[ "$sigjson" == *'"payload_tag":"zejtron/depth-matrix/v1"'* ]] &&
	[[ "$sigjson" != *$'\n'* ]]; then
	echo "${UX_OK}PASS json : the depth matrix speaks one jq-ready line${UX_RESET}"
	PASS=$((PASS + 1))
else
	echo "${UX_ERR}FAIL json : $sigjson${UX_RESET}"
	FAIL=$((FAIL + 1))
fi
masked_hits=$(grep -ac "rezky_nightky" "$BIN" || true)
if [[ "$masked_hits" == "0" ]]; then
	echo "${UX_OK}PASS masked : the artifact carries no greppable identity (the at-rest contract)${UX_RESET}"
	PASS=$((PASS + 1))
else
	echo "${UX_ERR}FAIL masked : $masked_hits identity hits in the artifact${UX_RESET}"
	FAIL=$((FAIL + 1))
fi

echo
echo "${UX_WHITE}== verdict: $PASS passed, $FAIL failed ==${UX_RESET}"
if [[ "$FAIL" -eq 0 ]]; then
	echo "${UX_OK}ALL GREEN - the CLI UX contract holds.${UX_RESET}"
	exit 0
fi
exit 1
