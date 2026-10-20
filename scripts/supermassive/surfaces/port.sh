# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_port.sh — the `port` surface.
#
# Depth: the success shape, every documented flag (--tcp --udp
# --listen --all --numeric --group --no-pid --since --events-only
# --snapshot-only), the invalid-port error ladder (0 / 65536 / abc),
# the clap conflict error (--listen --all), structural determinism
# (the socket table moves under the suite by definition), and the
# color tri-test. Pure procfs - no dormant variant.
# Exercised flags: all ten documented port flags.

surface_port() {
        local rc

        # Success path: the wide snapshot.
        sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" port --snapshot-only
        sm_assert_rc 0 "$rc" "port --snapshot-only exits 0"
        sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "port renders content"

        # Flag ladder: every documented flag runs clean, one invocation
        # each (the flag-specific contract is rc 0 + rendered content;
        # the render shape is pinned by the snapshot check above).
        local flag
        for flag in --tcp --udp --listen --all --numeric --group --no-pid --snapshot-only; do
                sm_run "$SM_SCRATCH/f.out" "$SM_SCRATCH/f.err" rc 5 -- "$SM_DEFAULT_BIN" port "$flag"
                sm_assert_rc 0 "$rc" "port $flag exits 0"
                sm_assert_file_nonempty "$SM_SCRATCH/f.out" "port $flag renders content"
                sm_flag_used "port $flag"
        done

        # --events-only and --since are the event-window family. The
        # verified honest contract: the window renders with its width and
        # states its capture ability plainly (unavailable or observed -
        # never a fake event table).
        sm_run "$SM_SCRATCH/ev.out" "$SM_SCRATCH/ev.err" rc 5 -- \
                "$SM_DEFAULT_BIN" port --events-only --since 1m
        sm_assert_rc 0 "$rc" "port --events-only --since 1m exits 0"
        sm_assert_contains "$SM_SCRATCH/ev.out" "Changes in the last" \
                "port --events-only renders the honest window header"
        sm_flag_used "port --events-only"
        sm_flag_used "port --since"

        # A combined ladder: the flags compose.
        sm_run "$SM_SCRATCH/comb.out" "$SM_SCRATCH/comb.err" rc 5 -- \
                "$SM_DEFAULT_BIN" port --tcp --numeric --no-pid --group --snapshot-only
        sm_assert_rc 0 "$rc" "port --tcp --numeric --no-pid --group --snapshot-only composes"

        # Error ladder: invalid port numbers are runtime failures (exit 1)
        # with the battery-pinned wording.
        local bad
        for bad in 0 65536 abc; do
                sm_run "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" rc 5 -- "$SM_DEFAULT_BIN" port "$bad"
                sm_assert_rc 1 "$rc" "port $bad exits 1"
                if grep -q "invalid port" "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" 2>/dev/null; then
                        sm_pass "port $bad names the invalid port"
                else
                        sm_fail "port $bad names the invalid port" "neither stream mentioned 'invalid port'"
                fi
        done

        # Clap conflict: --listen and --all are declared exclusive, so
        # this is a usage error - exit 2, battery-pinned wording.
        sm_run "$SM_SCRATCH/conf.out" "$SM_SCRATCH/conf.err" rc 5 -- \
                "$SM_DEFAULT_BIN" port --listen --all
        sm_assert_rc 2 "$rc" "port --listen --all is a usage error (exit 2)"
        if grep -q "cannot be used" "$SM_SCRATCH/conf.out" "$SM_SCRATCH/conf.err" 2>/dev/null; then
                sm_pass "port --listen --all names the conflict"
        else
                sm_fail "port --listen --all names the conflict" "neither stream mentioned 'cannot be used'"
        fi

        # Determinism: the socket table is live kernel state, so the
        # honest determinism claim is the stable skeleton (headers and
        # verdict lines), not the moving rows.
        sm_deterministic_structural "port determinism (structural)" 5 -- \
                "$SM_DEFAULT_BIN" port --snapshot-only --numeric

        # The color tri-test.
        sm_color_tritest "port" 5 -- "$SM_DEFAULT_BIN" port --snapshot-only
}
