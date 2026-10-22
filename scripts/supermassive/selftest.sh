# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# selftest.sh — the engine's own verification, no zejtron binary
# needed. The suite judges the binary; this judges the judge. Run via
# ./scripts/supermassive/supermassive.sh --self-test.
#
# The contract: every helper is exercised against known-good and
# known-bad fixtures; the counters must land on the exact expected
# totals, the skip law must turn a reason-less skip into a failure,
# and the normalizer must neutralize every volatile field it claims.
# A green suite whose engine is broken is a fake PASS factory - this
# file is the anti-fake.

set -Eeuo pipefail

# The target is resolved dynamically from BASH_SOURCE; the gate's
# 1d source-resolution check verifies it exists, fail-closed.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

sm_init
# Runner-level contract variable: the sourced engine reads it as the
# default per-invocation timeout.
# shellcheck disable=SC2034
SM_TEST_TIMEOUT=10
SM_SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/supermassive-selftest.XXXXXX")"
mkdir -p "$SM_SCRATCH/home"
# Runner-level contract variable, same class as SM_TEST_TIMEOUT.
# shellcheck disable=SC2034
SM_BIN_PATH_ENV="$PATH"
SM_FLAGS_USED_FILE="$SM_SCRATCH/flags-used.txt"
: >"$SM_FLAGS_USED_FILE"

# Deliberate bad probes are failures by design. The final verdict
# counts them against the real failure counter: engine probes that
# exist only to trip the engine must be the ONLY failures present.
probe_failures=0

# 1. The pass/fail/skip counters and the skip law.
sm_pass "selftest: pass records"
[[ "$SM_PASS" -eq 1 ]] || sm_fail "selftest: pass counter" "want 1, got $SM_PASS"

probe_failures=$((probe_failures + 1))
sm_fail "selftest: injected failure" "expected by the self-test"
[[ "$SM_FAIL" -eq "$probe_failures" ]] || sm_fail "selftest: fail counter" "want $probe_failures"

sm_skip "selftest: honest skip" "the self-test exercises the skip law"
probe_failures=$((probe_failures + 1))
sm_skip "selftest: reason-less skip" ""
# The reason-less skip must have been converted into a failure.
[[ "$SM_FAIL" -eq "$probe_failures" ]] || sm_fail "selftest: skip law" \
	"a SKIP without a reason did not become a failure"

# 2. Assertions against known-good and known-bad invocations.
rc=0
sm_run "$SM_SCRATCH/t.out" "$SM_SCRATCH/t.err" rc 5 -- /bin/echo hello
sm_assert_rc 0 "$rc" "selftest: echo exits 0"
sm_assert_contains "$SM_SCRATCH/t.out" "hello" "selftest: stdout captured"
sm_assert_file_nonempty "$SM_SCRATCH/t.out" "selftest: nonempty file"
sm_assert_eq "$rc" "0" "selftest: assert_eq works"

rc=0
sm_run "$SM_SCRATCH/f.out" "$SM_SCRATCH/f.err" rc 5 -- /bin/false
sm_assert_rc 1 "$rc" "selftest: false exits 1 (rc capture is exact)"

rc=0
sm_run "$SM_SCRATCH/s.out" "$SM_SCRATCH/s.err" rc 1 -- /bin/sleep 30
sm_assert_rc 124 "$rc" "selftest: run_with_timeout kills a wedged invocation"

# not_contains must pass on clean text and FAIL on dirty text.
sm_assert_not_contains "$SM_SCRATCH/t.out" "absent-needle" "selftest: not_contains passes on clean text"
probe_failures=$((probe_failures + 1))
sm_assert_not_contains "$SM_SCRATCH/t.out" "hello" "selftest: injected not_contains probe"
[[ "$SM_FAIL" -eq "$probe_failures" ]] || sm_fail "selftest: not_contains law" \
	"not_contains on a needle that IS present did not record a failure"

# 3. The normalizer neutralizes every volatile field it names.
printf 'started 2026-10-20 05:56:42 UTC, pid=1234, took 150ms\n' >"$SM_SCRATCH/n1"
printf 'started 2026-10-20 05:57:02 UTC, pid=5678, took 180ms\n' >"$SM_SCRATCH/n2"
sm_normalize "$SM_SCRATCH/n1" "$SM_SCRATCH/n1.norm"
sm_normalize "$SM_SCRATCH/n2" "$SM_SCRATCH/n2.norm"
if cmp -s "$SM_SCRATCH/n1.norm" "$SM_SCRATCH/n2.norm"; then
	sm_pass "selftest: normalizer absorbs timestamps and pids"
else
	sm_fail "selftest: normalizer absorbs timestamps and pids" "normalized fixtures differ"
fi

printf 'pkts rx=1201 tx=99, errors=0 drops=2, 4.5KB moved\n' >"$SM_SCRATCH/g1"
printf 'pkts rx=1207 tx=104, errors=0 drops=2, 4.9KB moved\n' >"$SM_SCRATCH/g2"
sm_normalize "$SM_SCRATCH/g1" "$SM_SCRATCH/g1.norm"
sm_normalize "$SM_SCRATCH/g2" "$SM_SCRATCH/g2.norm"
if cmp -s "$SM_SCRATCH/g1.norm" "$SM_SCRATCH/g2.norm"; then
	sm_pass "selftest: normalizer absorbs gauge counters and the KB range"
else
	sm_fail "selftest: normalizer absorbs gauge counters and the KB range" \
		"normalized gauge fixtures differ"
fi

# 3b. The visible-process gauge (the 7.2 witness's find, night-improve-54):
# kernel threads appear and vanish between two adjacent doctor runs on
# the newest kernel lines - the pids row's count is a moving gauge.
printf '  pids:            OK    113 processes visible\n' >"$SM_SCRATCH/vp1"
printf '  pids:            OK    114 processes visible\n' >"$SM_SCRATCH/vp2"
sm_normalize "$SM_SCRATCH/vp1" "$SM_SCRATCH/vp1.norm"
sm_normalize "$SM_SCRATCH/vp2" "$SM_SCRATCH/vp2.norm"
if cmp -s "$SM_SCRATCH/vp1.norm" "$SM_SCRATCH/vp2.norm"; then
	sm_pass "selftest: normalizer absorbs the visible-process gauge"
else
	sm_fail "selftest: normalizer absorbs the visible-process gauge" "normalized fixtures differ"
fi

# 4. The escape detector: a file with CSI is caught, clean text is not.
printf 'plain line\n' >"$SM_SCRATCH/clean"
printf 'colored \033[38;2;255;90;90mred\033[0m line\n' >"$SM_SCRATCH/dirty"
sm_assert_no_escapes "$SM_SCRATCH/clean" "selftest: clean file passes the escape gate"
if LC_ALL=C grep -q "$(printf '\033\[')" "$SM_SCRATCH/dirty"; then
	sm_pass "selftest: escape detector finds CSI in a dirty file"
else
	sm_fail "selftest: escape detector" "CSI not found in a file that contains one"
fi

# 5. The color tri-test against a stand-in binary that obeys the
# same capability law (plain when captured, colored when forced).
cat >"$SM_SCRATCH/fake-tool" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${CLICOLOR_FORCE:-}" ]]; then
        printf '\033[38;2;80;250;123mverdict: ok\033[0m\n'
else
        printf 'verdict: ok\n'
fi
EOF
chmod 755 "$SM_SCRATCH/fake-tool"
before_pass=$SM_PASS
before_fail=$SM_FAIL
sm_color_tritest "selftest: fake-tool tri" 5 -- "$SM_SCRATCH/fake-tool"
gained_pass=$((SM_PASS - before_pass))
gained_fail=$((SM_FAIL - before_fail))
# 7 checks: 2 zero-escape gates, NO_COLOR exit-status pin, NO_COLOR
# byte-equality, forced exit-status pin, truecolor escape presence,
# and forced-differs-from-plain.
if [[ "$gained_pass" -eq 7 && "$gained_fail" -eq 0 ]]; then
	sm_pass "selftest: tri-test scores 7/7 on an obedient tool"
else
	sm_fail "selftest: tri-test scoring" "want 7 pass / 0 fail, got $gained_pass / $gained_fail"
fi

# 5b. The structural tri-test mode: a rank-sampled gauge tool whose
# data rows move between ANY two invocations passes the NO_COLOR
# equality on the skeleton, while a skeleton change still fails.
cat >"$SM_SCRATCH/fake-ranked" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${CLICOLOR_FORCE:-}" ]]; then
        printf '\033[38;2;80;250;123mdoctor\033[0m\n'
else
        printf 'doctor\n'
        printf '  PID %s (probe) PSS %s.1 MiB\n' "$$" "$((RANDOM % 9))"
        printf 'verdict: ok\n'
fi
EOF
chmod 755 "$SM_SCRATCH/fake-ranked"
before_pass=$SM_PASS
before_fail=$SM_FAIL
SM_TRITEST_STRUCTURAL=1 sm_color_tritest "selftest: fake-ranked structural tri" 5 -- "$SM_SCRATCH/fake-ranked"
gained_pass=$((SM_PASS - before_pass))
gained_fail=$((SM_FAIL - before_fail))
if [[ "$gained_pass" -eq 7 && "$gained_fail" -eq 0 ]]; then
	sm_pass "selftest: structural tri scores 7/7 on a rank-sampled tool"
else
	sm_fail "selftest: structural tri scoring" \
		"want 7 pass / 0 fail, got $gained_pass / $gained_fail"
fi

# 5c. The family-frame skeleton: the report frame's furniture (the
# heavy-bar banner and the indented colon-key rows, the render grammar
# since night-weekly-maintenance-2) belongs to the structural
# skeleton, while a moving indented data row ("  PID ...") stays out
# of it.
cat >"$SM_SCRATCH/fake-frame" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${CLICOLOR_FORCE:-}" ]]; then
        printf '\033[38;2;80;250;123m━━━ frame tool ━━━\033[0m\n'
else
        printf '━━━ frame tool ━━━\n'
        printf '  Mode:            unprivileged (partial results expected)\n'
        printf '  PID %s (probe) PSS %s.1 MiB\n' "$$" "$((RANDOM % 9))"
        printf 'verdict: ok\n'
fi
EOF
chmod 755 "$SM_SCRATCH/fake-frame"
before_pass=$SM_PASS
before_fail=$SM_FAIL
SM_TRITEST_STRUCTURAL=1 sm_color_tritest "selftest: fake-frame structural tri" 5 -- "$SM_SCRATCH/fake-frame"
gained_pass=$((SM_PASS - before_pass))
gained_fail=$((SM_FAIL - before_fail))
if [[ "$gained_pass" -eq 7 && "$gained_fail" -eq 0 ]]; then
	sm_pass "selftest: structural tri keeps the frame furniture and drops the moving rows"
else
	sm_fail "selftest: frame skeleton" \
		"want 7 pass / 0 fail on a family-frame tool, got $gained_pass / $gained_fail"
fi

# 5d. The structural mode can still FAIL: a colon-key row whose value
# moves outside the volatile table changes the skeleton, and the tri
# must record exactly that one failure (the anti-fake direction of
# 5b's "a skeleton change still fails" claim, now actually pinned).
cat >"$SM_SCRATCH/fake-drift" <<'EOF'
#!/usr/bin/env bash
runs_file="$(dirname "$0")/.runs"
n=$(( $(cat "$runs_file" 2>/dev/null || echo 0) + 1 ))
printf '%s' "$n" >"$runs_file"
if [[ -n "${CLICOLOR_FORCE:-}" ]]; then
        printf '\033[38;2;80;250;123mverdict: ok\033[0m\n'
else
        printf '━━━ drift tool ━━━\n'
        printf '  Mode:            run-%s\n' "$n"
        printf 'verdict: ok\n'
fi
EOF
chmod 755 "$SM_SCRATCH/fake-drift"
before_pass=$SM_PASS
before_fail=$SM_FAIL
# The drift run's one equality failure is a deliberate engine probe -
# counted like every other injected failure in the final verdict's math.
probe_failures=$((probe_failures + 1))
SM_TRITEST_STRUCTURAL=1 sm_color_tritest "selftest: fake-drift structural tri" 5 -- "$SM_SCRATCH/fake-drift"
gained_pass=$((SM_PASS - before_pass))
gained_fail=$((SM_FAIL - before_fail))
if [[ "$gained_pass" -eq 6 && "$gained_fail" -eq 1 ]]; then
	sm_pass "selftest: a drifting colon-key row fails the structural equality"
else
	sm_fail "selftest: drift law" \
		"want 6 pass / 1 fail on a skeleton-drifting tool, got $gained_pass / $gained_fail"
fi

# 6. The flag registry. The grep "--" separator matters here in
# earnest: the needle itself is a flag spelling, and without the
# separator grep would parse it as its own --version option (the
# same class of dash-needle bug scripts/build.sh warns about).
sm_flag_used "--version"
grep -qxF -- "--version" "$SM_FLAGS_USED_FILE" || sm_fail "selftest: flag registry" "recorded flag not found"

rm -rf "$SM_SCRATCH"

# The verdict: the failure counter must hold EXACTLY the deliberate
# probes - any other failure means the engine misfired somewhere.
if [[ "$SM_FAIL" -eq "$probe_failures" && "$SM_PASS" -ge 12 ]]; then
	printf 'self-test verdict: PASS (%d checks, %d known injected probes)\n' "$SM_PASS" "$probe_failures"
	exit 0
fi
printf 'self-test verdict: FAIL (pass=%d fail=%d probes=%d)\n' "$SM_PASS" "$SM_FAIL" "$probe_failures"
exit 1
