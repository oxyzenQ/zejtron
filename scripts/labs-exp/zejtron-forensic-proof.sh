# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
# OS: Linux only - zejtron is a Linux introspection tool.
#
# labs-exp/zejtron-forensic-proof.sh - the live forensic pair proof
# (night-total-hardening-1 follow-up, the one-command proof of the
# night-frontier-2 innovation on THIS host).
#
# One command proves the who-deleted-this-file innovation end to
# end: attach (idempotent, privileged one-shot), create a file,
# unlink it two seconds into a live watch, and demand the ledger
# name the actor - an unlinked row with rm and its pid, and exactly
# one op=unlink record drained (the single-publish law). The same
# contract is proved for mv: exactly one renamed row and one
# op=rename record. 14 checks; the last line is always
# "FORENSIC-PROOF: PASS|FAIL (...)" so the verdict relays without
# parsing prose.
#
# Root is the law here: the event lane reads the root-pinned maps
# under /sys/fs/bpf/zejtron, and a non-root watch degrades to the
# snapshot fallback - a snapshot never proves the live pair, so a
# non-root run is a named refusal, never a fake proof. The kernel
# floor is 5.15; a host below it gets the attach refusal named, and
# this lab fails honestly (a refusal is a host fact, not a fake
# pass).
#
# Leave-as-found: probes already recording before this lab started
# stay attached; a probe this lab attached itself is detached after.
# The lab never disturbs a recording it did not start.
#
# Usage:
#   sudo scripts/labs-exp/zejtron-forensic-proof.sh [path-to-binary]
#   ZEJTRON_BIN_PATH=/path/to/zejtron sudo -E scripts/labs-exp/zejtron-forensic-proof.sh
#   ZEJTRON_ALLOW_STALE=1 (with sudo -E) - prove a binary built from
#   another commit on purpose

set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 1
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd) || exit 1

# The brand palette (night-cafe-1): verdict tokens, rails, and
# refusal lines ride the same tiers the CLI renders. Defaults come
# first so a missing lib degrades to mono, never to a set -u crash;
# the source overrides them with the depth-correct escapes.
# shellcheck disable=SC2034 # the full tier set pre-seeds mono-safe; the source overrides
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
	echo "${UX_ERR}proof: no zejtron binary found (tried the argument, ZEJTRON_BIN_PATH, and target/ discovery)${UX_RESET}" >&2
	echo "${UX_ERR}proof: build one first - cargo build --release (or scripts/build.sh check-all)${UX_RESET}" >&2
	exit 2
fi
echo "${UX_GREY}proof: binary $BIN${UX_RESET}"

# Root comes before the fingerprint guard: there is no point
# fingerprinting a binary the caller is not privileged enough to
# exercise. The event lane is the whole proof.
if [[ "$(id -u)" -ne 0 ]]; then
	echo "${UX_ERR}proof: refused - the live forensic pair needs root (the event lane reads the root-pinned maps)${UX_RESET}" >&2
	echo "proof: re-run me as: (sudo scripts/labs-exp/zejtron-forensic-proof.sh)${UX_RESET}" >&2
	exit 2
fi

# The build-fingerprint guard (the same law the CLI UX lab carries):
# the verdict is only honest when the binary under test was built
# from the tree this lab rides in. A discovered target/ binary from
# an older commit may predate the probes themselves - that is a
# false FAIL, which reads like a kernel regression. An explicit
# target (the argument or ZEJTRON_BIN_PATH) is deliberate and only
# warns; ZEJTRON_ALLOW_STALE=1 is the on-purpose bypass. A tree
# without git, or a binary without a Build commit, skips silently.
head_commit=""
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	head_commit=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null | cut -c1-7)
fi
bin_commit=$("$BIN" -V 2>/dev/null | sed -n 's/^Build:.*(\([0-9a-f]\{7,40\}\)).*/\1/p' | cut -c1-7)
if [[ -n "$head_commit" && -n "$bin_commit" && "$bin_commit" != "$head_commit" ]]; then
	if [[ -n "${1:-}" || -n "${ZEJTRON_BIN_PATH:-}" || "${ZEJTRON_ALLOW_STALE:-0}" == 1 ]]; then
		echo "${UX_WARN}proof: WARNING the binary is built from $bin_commit, the tree is at $head_commit - the verdict covers the binary, not the tree${UX_RESET}"
	else
		echo "${UX_ERR}proof: the binary is built from $bin_commit, but the tree is at $head_commit${UX_RESET}" >&2
		echo "${UX_ERR}proof: a stale target binary makes the verdict lie - rebuild first, then re-run${UX_RESET}" >&2
		echo "${UX_ERR}proof:   cargo build --release   (or scripts/package/install-on-my-machine.sh)${UX_RESET}" >&2
		echo "${UX_ERR}proof: set ZEJTRON_ALLOW_STALE=1 to prove the old binary on purpose${UX_RESET}" >&2
		exit 2
	fi
fi

SCRATCH=$(mktemp -d) || exit 1
trap 'rm -rf "$SCRATCH"' EXIT

echo "${UX_BRAND}-- attach (the privileged one-shot) --${UX_RESET}"
attach_out=$("$BIN" doctor --attach 2>&1)
attach_rc=$?
echo "$attach_out"
if [[ "$attach_rc" -ne 0 ]]; then
	echo
	echo "${UX_ERR}FORENSIC-PROOF: FAIL (the attach refused on this host - the reason is named above)${UX_RESET}"
	exit 1
fi
was_attached=0
if [[ "$attach_out" == *"already attached"* ]]; then
	was_attached=1
	echo "${UX_GREY}proof: the probes were recording before this lab started - they stay attached (leave-as-found)"
fi

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

echo
echo "${UX_BRAND}-- 1. the unlink proof (who deleted this file?) --${UX_RESET}"
un_file="$SCRATCH/unlink-proof.txt"
echo evidence >"$un_file"
timeout 30 "$BIN" why "$un_file" --since 10s --raw >"$SCRATCH/unlink.out" 2>"$SCRATCH/unlink.err" &
un_why=$!
sleep 2
rm -v "$un_file" >/dev/null
wait "$un_why"
un_rc=$?
un_out=$(cat "$SCRATCH/unlink.out")
if [[ "$un_rc" -eq 0 ]]; then
	pass "exit=0 : the live watch survives the unlink"
else
	fail "exit=$un_rc (want 0) : the live watch survives the unlink"
fi
if [[ "$un_out" == *"Mode: live"* ]]; then
	pass "Mode: live : the event lane is live, not the snapshot fallback"
else
	fail "Mode: live missing : the event lane is live, not the snapshot fallback"
fi
if [[ "$un_out" == *"unlinked"* ]]; then
	pass "unlinked row : the ledger names the unlink"
else
	fail "unlinked row missing : the ledger names the unlink"
fi
un_rows=$(grep -c " unlinked " "$SCRATCH/unlink.out" || true)
if [[ "$un_rows" -eq 1 ]]; then
	pass "exactly one unlinked row : the single-publish law"
else
	fail "unlinked rows=$un_rows (want 1) : the single-publish law"
fi
if [[ "$un_out" == *"op=unlink"* ]]; then
	pass "op=unlink record : the raw lane names the syscall"
else
	fail "op=unlink record missing : the raw lane names the syscall"
fi
un_raws=$(grep -c "op=unlink" "$SCRATCH/unlink.out" || true)
if [[ "$un_raws" -eq 1 ]]; then
	pass "exactly one op=unlink : one catch, one drain"
else
	fail "op=unlink count=$un_raws (want 1) : one catch, one drain"
fi
if [[ "$un_out" == *"rm (pid"* ]]; then
	pass "actor named : rm with its pid"
else
	fail "actor name missing : rm with its pid"
fi

echo
echo "${UX_BRAND}-- 2. the rename proof (the renamed row, vfs_rename) --${UX_RESET}"
rn_a="$SCRATCH/rename-a.txt"
rn_b="$SCRATCH/rename-b.txt"
echo move-me >"$rn_a"
timeout 30 "$BIN" why "$rn_a" --since 10s --raw >"$SCRATCH/rename.out" 2>"$SCRATCH/rename.err" &
rn_why=$!
sleep 2
mv -v "$rn_a" "$rn_b" >/dev/null
wait "$rn_why"
rn_rc=$?
rn_out=$(cat "$SCRATCH/rename.out")
if [[ "$rn_rc" -eq 0 ]]; then
	pass "exit=0 : the live watch survives the rename"
else
	fail "exit=$rn_rc (want 0) : the live watch survives the rename"
fi
if [[ "$rn_out" == *"Mode: live"* ]]; then
	pass "Mode: live : the event lane is live, not the snapshot fallback"
else
	fail "Mode: live missing : the event lane is live, not the snapshot fallback"
fi
if [[ "$rn_out" == *"renamed"* ]]; then
	pass "renamed row : the ledger names the rename"
else
	fail "renamed row missing : the ledger names the rename"
fi
rn_rows=$(grep -c " renamed " "$SCRATCH/rename.out" || true)
if [[ "$rn_rows" -eq 1 ]]; then
	pass "exactly one renamed row : the single-publish law"
else
	fail "renamed rows=$rn_rows (want 1) : the single-publish law"
fi
if [[ "$rn_out" == *"op=rename"* ]]; then
	pass "op=rename record : the raw lane names the syscall"
else
	fail "op=rename record missing : the raw lane names the syscall"
fi
rn_raws=$(grep -c "op=rename" "$SCRATCH/rename.out" || true)
if [[ "$rn_raws" -eq 1 ]]; then
	pass "exactly one op=rename : one catch, one drain"
else
	fail "op=rename count=$rn_raws (want 1) : one catch, one drain"
fi
if [[ "$rn_out" == *"mv (pid"* ]]; then
	pass "actor named : mv with its pid"
else
	fail "actor name missing : mv with its pid"
fi

if [[ "$was_attached" -eq 0 ]]; then
	echo
	echo "${UX_BRAND}-- detach (leave-as-found: this lab attached, this lab detaches) --${UX_RESET}"
	"$BIN" doctor --detach || true
fi

echo
TOTAL=$((PASS + FAIL))
if [[ "$FAIL" -eq 0 ]]; then
	echo "${UX_OK}FORENSIC-PROOF: PASS ($TOTAL checks)${UX_RESET}"
	exit 0
fi
echo "${UX_ERR}FORENSIC-PROOF: FAIL ($FAIL of $TOTAL checks failed)${UX_RESET}"
exit 1
