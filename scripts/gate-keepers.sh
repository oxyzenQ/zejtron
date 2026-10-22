#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# Pre-commit gatekeeper script for zejtron (the sibling's wholesale
# gate, ported to zejtron's section set).
# Runs all non-code linters/checks before allowing a commit.
#
# Usage:
#   ./scripts/gate-keepers.sh           # Run all checks
#   ./scripts/gate-keepers.sh --fix-all # Run with auto-fix where possible
#
# Checks performed (exclude Rust core code - use `cargo clippy` via
# ./scripts/build.sh check-all for that):
#    0.  Pre-commit hook self-install (core.hooksPath=.githooks,
#        repo-local - the sibling's NIGHT-dinner-1 lineage)
#    1.  Shell scripts (strict quad):
#         1a. bash -n   - syntax check (fast fail-fast pre-filter)
#         1b. shellcheck - static analysis (default rule set)
#         1c. shfmt -d  - canonical formatting (tabs, function braces
#             on own line, case branches expanded); --fix-all runs
#             `shfmt -w` to auto-canonicalize
#         1d. source resolution - every `source`/`.` target exists
#             (the literal path, not the directive)
#    2.  yamllint on .github YAML (repo .yamllint config)
#    3.  actionlint on .github/workflows/*.yml
#    4.  TOML syntax validation (python3 tomllib)
#    5.  codespell on all text files (repo .codespellrc)
#    6.  SPDX license header check (scripts/gates/check-headers.sh -
#        both house forms across rs/sh/toml/yml/md; untracked files
#        included so new files fail BEFORE commit)
#    7.  File permission guard (owner rule - git-tracked files 644,
#        tracked executables and directories 755, shebang parity;
#        scripts/gates/check-permissions.sh, --fix-all chmods)
#    8.  Emoji sweep (owner rule - no emoji-class codepoints in ANY
#        tracked text file; fail blocks, strict detector, exit 1 on
#        hits)
#    9.  Rust source LOC cap (scripts/gates/check-loc.sh - hard limit
#        600 lines, tree-wide by file type; night-improve-18 retired
#        the tracked-debt list whole - over the cap FAILS, the
#        no-mercy law, split a pure move with gates green in between)
#   10.  Rust toolchain version sync (scripts/gates/check-rust-version-sync.sh -
#        rust-toolchain.toml pin == Cargo.toml MSRV == workflow
#        RUST_VERSION pins)
#   11.  Language discipline (scripts/gates/check-language.sh:
#        non-Latin scripts outside NON_LATIN_FIXTURE-marked coverage
#        files plus an Indonesian vocabulary detector; the repo is
#        English-only, the sibling of the emoji sweep for everything
#        that sweep cannot see)
#   12.  Scripts LOC cap (scripts/gates/check-scripts-loc.sh, hard
#        limit 1000 lines for every .sh/.py under scripts/; the
#        scripts twin of section 9)
#   13.  Version-string anti-pattern guard
#        (scripts/gates/check-version-anti-patterns.sh: no test may
#        assert that Cargo.toml contains its own version string - the
#        tautology that once broke CI on every bump)
#   14.  Release parity (scripts/gates/check-release-parity.sh: the
#        four arch-baseline platforms' -C codegen tokens in
#        .cargo/config.toml's pro-linux-amd64-* aliases must equal the
#        release matrix's rustflags, so a local alias build reproduces
#        the release optimization tier bit-for-bit; a one-file edit
#        can no longer silently break that contract)
#
#   15.  Family name case (scripts/gates/check-name-case.py: both
#        family names - the sibling zylaxion and this project's own
#        zejtron - are lowercase in every context, docs/BRANDING.md
#        section 7 - every tracked file and path scanned, nothing
#        excluded; a mixed-case form of either name fails the gate)
#
#   16.  Prebuilt pin parity (scripts/dev/regenerate-ebpf-prebuilt.sh
#        --check, the push-time CI seat of the commit gate's prebuilt
#        verdict: the ebpf/ tree pin, the staged object's blake3 and
#        size, the toolchain pin, and the version mirror must all
#        agree on the pushed tree. The build-time arm auto-heals a
#        stale lane for every local cargo build - right for the
#        developer, wrong as the only CI mirror, because a heal
#        inside the runner leaves the pushed lane stale and the run
#        green; this section turns that state red. Skips with a
#        warning when b3sum is absent (the wholesale contract); the
#        Gate-keepers CI lane installs the pinned tool, so the seat
#        never sleeps in CI)
#
# Pre-commit hook: the first wholesale run on a clone self-installs
# .githooks/pre-commit (git config core.hooksPath=.githooks - repo-
# local, never --global), so every future commit on that clone
# executes scripts/gates/check-commit-gate.sh (the commit-time arm of
# the actions-pin health contract) even when this wholesale script is
# forgotten. The hook enforces the same lane contract at commit time
# that CI enforces at push time.
#
# Missing tools are skipped with a warning so the gate stays usable
# on minimal development machines; CI runs this script WHOLESALE
# (the gate-keepers.yml job, full tool set installed and pinned):
# every section executes on every push - no gate can rot silently
# behind a missing CI mirror step again.
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed

set -euo pipefail

# One mktemp -d scratch instead of fixed /tmp/zj-* names
# (night-total-lts-2): no symlink planting on multi-user hosts, no
# crosstalk between concurrent gate runs, and the EXIT trap leaves
# nothing behind. build.sh's tmpdir contract, ported home.
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/zejtron-gate.XXXXXX")"
trap 'rm -rf "${SCRATCH}"' EXIT

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

FIX_ALL=false
if [[ "${1:-}" == "--fix-all" ]]; then
	FIX_ALL=true
elif [[ $# -gt 0 ]]; then
	echo "usage: ./scripts/gate-keepers.sh [--fix-all]" >&2
	exit 2
fi

PASS=0
FAIL=0
declare -a FAILED_SECTIONS=()

header() {
	echo ""
	echo "── $1 ──"
}

pass() {
	echo -e "${GREEN}PASS${NC}: $1"
	PASS=$((PASS + 1))
}

fail() {
	echo -e "${RED}FAIL${NC}: $1"
	FAIL=$((FAIL + 1))
	FAILED_SECTIONS+=("$1")
}

warn_skip() {
	echo -e "${YELLOW}SKIP${NC}: $1 (tool not installed)"
}

# ── 0. Pre-commit hook self-install ─────────────────────────────────────────
header "Pre-commit hook self-install"
CURRENT_HOOKS_PATH="$(git config core.hooksPath || true)"
if [ "${CURRENT_HOOKS_PATH}" != ".githooks" ]; then
	git config core.hooksPath .githooks
	echo "installed: git config core.hooksPath=.githooks (repo-local)"
	pass "pre-commit hook wired (was: '${CURRENT_HOOKS_PATH:-unset}')"
else
	pass "pre-commit hook already wired (core.hooksPath=.githooks)"
fi

# ── 1. Shell quad ───────────────────────────────────────────────────────────
header "1. Shell scripts (strict quad)"
SHELL_FILES=$(find scripts .githooks -type f -name '*.sh' 2>/dev/null | sort)
if [ -z "${SHELL_FILES}" ]; then
	# .githooks/pre-commit is extensionless; lint it explicitly.
	SHELL_FILES=""
fi

QUAD_FAIL=0

# 1a. bash -n (always available)
if [ -n "${SHELL_FILES}" ]; then
	while IFS= read -r f; do
		if ! bash -n "$f" 2>"${SCRATCH}/zj-bashn.err"; then
			echo "  bash -n: $f"
			cat "${SCRATCH}/zj-bashn.err"
			QUAD_FAIL=1
		fi
	done <<<"${SHELL_FILES}"
fi
if ! bash -n .githooks/pre-commit 2>"${SCRATCH}/zj-bashn.err"; then
	echo "  bash -n: .githooks/pre-commit"
	cat "${SCRATCH}/zj-bashn.err"
	QUAD_FAIL=1
fi
[ "${QUAD_FAIL}" -eq 0 ] && pass "1a. bash -n syntax"

# 1b. shellcheck
if command -v shellcheck >/dev/null 2>&1; then
	QUAD_FAIL=0
	while IFS= read -r f; do
		if ! shellcheck "$f" >"${SCRATCH}/zj-sc.out" 2>&1; then
			echo "  shellcheck: $f"
			head -20 "${SCRATCH}/zj-sc.out"
			QUAD_FAIL=1
		fi
	done <<<"${SHELL_FILES}"
	if ! shellcheck .githooks/pre-commit >"${SCRATCH}/zj-sc.out" 2>&1; then
		echo "  shellcheck: .githooks/pre-commit"
		head -20 "${SCRATCH}/zj-sc.out"
		QUAD_FAIL=1
	fi
	if [ "${QUAD_FAIL}" -eq 0 ]; then
		pass "1b. shellcheck static analysis"
	else
		fail "1b. shellcheck static analysis"
	fi
else
	warn_skip "1b. shellcheck static analysis"
fi

# 1c. shfmt
if command -v shfmt >/dev/null 2>&1; then
	# Intentional word splitting: SHELL_FILES is the newline-separated
	# find list and shfmt consumes it as N separate file arguments -
	# quoting it would hand shfmt one newline-blob filename instead.
	if [ "${FIX_ALL}" = true ]; then
		# shellcheck disable=SC2086
		shfmt -w ${SHELL_FILES} .githooks/pre-commit
	fi
	# shellcheck disable=SC2086
	if shfmt -d ${SHELL_FILES} .githooks/pre-commit >"${SCRATCH}/zj-shfmt.out" 2>&1; then
		pass "1c. shfmt canonical formatting"
	else
		echo "  shfmt diff (run ./scripts/gate-keepers.sh --fix-all to auto-fix):"
		head -20 "${SCRATCH}/zj-shfmt.out"
		fail "1c. shfmt canonical formatting"
	fi
else
	warn_skip "1c. shfmt canonical formatting"
fi

# 1d. source resolution (the sibling's NIGHT-blade-14 fail-closed
# translator): resolve every `source X` / `. X` line the way bash
# would. Two repo idioms are recognized - the cd/pwd idiom anchored
# at BASH_SOURCE[0], and a plain path relative to the sourcing
# script's own directory; any other shape fails loudly, and a new
# idiom must extend this translator (fail-closed, never fail-open).
QUAD_FAIL=0
SRC_RE='^[[:space:]]*(source|\.)[[:space:]]+"\$\(cd[[:space:]]+"\$\(dirname[[:space:]]+"\$\{BASH_SOURCE\[0\]\}"\)(/(\.\.)+)*"[[:space:]]+&&[[:space:]]+pwd\)/([^"]+)"$'
SRC_PLAIN='^[[:space:]]*(source|\.)[[:space:]]+([^"$][^[:space:]]*)[[:space:]]*$'
for f in ${SHELL_FILES} .githooks/pre-commit; do
	fdir="$(dirname "$f")"
	while IFS= read -r line; do
		if [[ $line =~ $SRC_RE ]]; then
			climb="${BASH_REMATCH[2]}"
			target="${BASH_REMATCH[4]}"
			if [ ! -e "$fdir$climb/$target" ]; then
				echo "  source resolution: $f: target missing: $line"
				QUAD_FAIL=1
			fi
		elif [[ $line =~ $SRC_PLAIN ]]; then
			rel="${BASH_REMATCH[2]}"
			if [ ! -e "$fdir/$rel" ]; then
				echo "  source resolution: $f: target missing: $line"
				QUAD_FAIL=1
			fi
		else
			echo "  source resolution: $f: unsupported idiom (extend the 1d translator): $line"
			QUAD_FAIL=1
		fi
	done < <(grep -E '^[[:space:]]*(source|\.)[[:space:]]' "$f" 2>/dev/null || true)
done
if [ "${QUAD_FAIL}" -eq 0 ]; then
	pass "1d. source resolution"
else
	fail "1d. source resolution"
fi

# ── 2. yamllint ─────────────────────────────────────────────────────────────
header "2. yamllint (.github YAML)"
if command -v yamllint >/dev/null 2>&1; then
	if yamllint .github/ >"${SCRATCH}/zj-yaml.out" 2>&1; then
		pass "yamllint"
	else
		head -20 "${SCRATCH}/zj-yaml.out"
		fail "yamllint"
	fi
else
	warn_skip "yamllint"
fi

# ── 3. actionlint ───────────────────────────────────────────────────────────
header "3. actionlint (workflows)"
if command -v actionlint >/dev/null 2>&1; then
	if actionlint -color >"${SCRATCH}/zj-al.out" 2>&1; then
		pass "actionlint"
	else
		head -30 "${SCRATCH}/zj-al.out"
		fail "actionlint"
	fi
else
	warn_skip "actionlint"
fi

# ── 4. TOML syntax ──────────────────────────────────────────────────────────
header "4. TOML syntax (python3 tomllib)"
TOML_FAIL=0
while IFS= read -r f; do
	# The TOML path rides argv, never a quoted interpolation
	# (night-total-lts-2): a filename is data, not code - a crafted
	# name broke out of the single-quoted -c string and ran Python.
	if ! python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' "$f" 2>"${SCRATCH}/zj-toml.err"; then
		echo "  invalid TOML: $f"
		head -3 "${SCRATCH}/zj-toml.err"
		TOML_FAIL=1
	fi
done < <(git ls-files --cached --others --exclude-standard -- '*.toml' 2>/dev/null)
if [ "${TOML_FAIL}" -eq 0 ]; then
	pass "TOML syntax"
else
	fail "TOML syntax"
fi

# ── 5. codespell ────────────────────────────────────────────────────────────
header "5. codespell"
if command -v codespell >/dev/null 2>&1; then
	if codespell --config .codespellrc . >"${SCRATCH}/zj-cs.out" 2>&1; then
		pass "codespell"
	else
		head -20 "${SCRATCH}/zj-cs.out"
		fail "codespell"
	fi
else
	warn_skip "codespell"
fi

# ── 6. SPDX headers ─────────────────────────────────────────────────────────
header "6. SPDX license headers"
if bash scripts/gates/check-headers.sh; then
	pass "6. SPDX headers"
else
	fail "6. SPDX headers"
fi

# ── 7. Permissions ──────────────────────────────────────────────────────────
header "7. File permission guard"
if [ "${FIX_ALL}" = true ]; then
	bash scripts/gates/check-permissions.sh --fix || true
fi
if bash scripts/gates/check-permissions.sh; then
	pass "7. permissions (644/755/shebang parity)"
else
	fail "7. permissions (644/755/shebang parity)"
fi

# ── 8. Emoji sweep ──────────────────────────────────────────────────────────
header "8. Emoji Sweep (repo-wide)"
if command -v python3 >/dev/null 2>&1; then
	EMOJI_RC=0
	python3 - <<'PYEOF' || EMOJI_RC=1
import os
import sys

RANGES = (
    (0x1F000, 0x1FFFF),  # astral emoji (incl. regional indicator flags)
    (0x2600, 0x27BF),   # Miscellaneous Symbols .. Dingbats
    (0x2300, 0x23FF),   # Misc Technical (clocks, media controls, key caps)
    (0x2B00, 0x2BFF),   # Misc Symbols and Arrows (stars, thick arrows)
    (0xFE0F, 0xFE0F),   # Variation Selector-16 (emoji presentation)
    (0xFE0E, 0xFE0E),   # Variation Selector-15 (text presentation)
    (0x200D, 0x200D),   # Zero-Width Joiner (emoji composition)
)


def is_emoji(cp):
    return any(lo <= cp <= hi for lo, hi in RANGES)


SKIP_DIRS = {".git", "target", "assets", "node_modules", "__pycache__"}
SKIP_FILES = {"CHANGELOG.md", "CHANGELOG-V10.0.0-ERA.md"}
SKIP_PREFIXES = ("docs/archive/",)

findings = 0
checked = 0
for root, dirnames, filenames in os.walk("."):
    dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
    for name in sorted(filenames):
        path = os.path.join(root, name)
        if name in SKIP_FILES or any(path.startswith(p) for p in SKIP_PREFIXES):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue  # binary - the logo assets and lockfiles ride here
        checked += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            hits = [ch for ch in line if is_emoji(ord(ch))]
            if hits:
                findings += 1
                print("  emoji %s:%d: %s" % (path, lineno, line.strip()[:70]))

print("emoji sweep: %d text file(s) checked, %d finding(s)" % (checked, findings))
sys.exit(1 if findings else 0)
PYEOF
	if [ "${EMOJI_RC}" -eq 0 ]; then
		pass "8. emoji sweep"
	else
		fail "8. emoji sweep"
	fi
else
	warn_skip "8. emoji sweep (python3 not installed)"
fi

# ── 9. Rust source LOC cap ──────────────────────────────────────────────────
header "9. Rust source LOC cap (600, tree-wide)"
if bash scripts/gates/check-loc.sh; then
	pass "9. .rs LOC cap"
else
	fail "9. .rs LOC cap"
fi

# ── 10. Rust toolchain version sync ─────────────────────────────────────────
header "10. Rust toolchain version sync"
if bash scripts/gates/check-rust-version-sync.sh; then
	pass "10. toolchain pin sync"
else
	fail "10. toolchain pin sync"
fi

# ── 11. Language discipline ─────────────────────────────────────────────────
header "11. Language discipline (English-only)"
if bash scripts/gates/check-language.sh; then
	pass "11. language discipline"
else
	fail "11. language discipline"
fi

# ── 12. Scripts LOC cap ─────────────────────────────────────────────────────
header "12. Scripts LOC cap (1000, scripts/ tree)"
if bash scripts/gates/check-scripts-loc.sh; then
	pass "12. scripts LOC cap"
else
	fail "12. scripts LOC cap"
fi

# ── 13. Version anti-patterns ───────────────────────────────────────────────
header "13. Version-string anti-pattern guard"
if bash scripts/gates/check-version-anti-patterns.sh; then
	pass "13. version anti-patterns"
else
	fail "13. version anti-patterns"
fi

# ── 14. Release parity ──────────────────────────────────────────────────────
header "14. Release parity (alias == matrix rustflags)"
if bash scripts/gates/check-release-parity.sh; then
	pass "14. release parity"
else
	fail "14. release parity"
fi

# ── 15. Family name case ────────────────────────────────────────────────
header "15. Family name case (zylaxion + zejtron lowercase law)"
if python3 scripts/gates/check-name-case.py; then
	pass "15. name case"
else
	fail "15. name case"
fi

# ── 16. Prebuilt pin parity ────────────────────────────────────────────────
header "16. Prebuilt pin parity (ebpf-prebuilt vs the ebpf/ tree)"
# The push-time seat of the commit gate's prebuilt verdict. The
# build-time arm (build/ebpf.rs) auto-heals a stale lane for every
# local cargo build, which is right for the developer but wrong as
# the only CI mirror: a heal inside the runner leaves the pushed
# manifest stale and the run green. The one writer's read-only
# --check verdict is fail-closed here, so a stale tree pin, a
# tampered staged object, or a broken version mirror turns the push
# red instead of silently self-repairing on the runner. A
# present-but-wrong-version b3sum fails through the script's own
# version probe - a finding, not a skip.
if command -v b3sum >/dev/null 2>&1; then
	if bash scripts/dev/regenerate-ebpf-prebuilt.sh --check; then
		pass "16. prebuilt pin parity"
	else
		fail "16. prebuilt pin parity"
	fi
else
	warn_skip "16. prebuilt pin parity (b3sum not installed)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "======================================================="
echo "Gate-keepers summary: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -gt 0 ]; then
	echo "Failed sections:"
	for section in "${FAILED_SECTIONS[@]}"; do
		echo "  - ${section}"
	done
	echo "======================================================="
	exit 1
fi
echo "All gate-keepers passed. Safe to commit."
echo "======================================================="
exit 0
