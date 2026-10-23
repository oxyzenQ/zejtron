# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_touch.sh — the `touch` surface.
#
# Depth: the success shape for both fixture kinds (file and
# directory - the battery-pinned type rows), the missing-path error
# path, the invalid-duration error path, the --since flag, fixture
# determinism, the color tri-test, and the dormant build variant
# (touch rides the fallback ladder).
# Exercised flags: --since, positional PATH.

surface_touch() {
	local rc
	local file="$SM_SCRATCH/touched file"
	local dir="$SM_SCRATCH/touched dir"
	printf 'content\n' >"$file"
	mkdir -p "$dir"

	# Success path, file form: the battery-pinned type row.
	sm_run "$SM_SCRATCH/file.out" "$SM_SCRATCH/file.err" rc 5 -- "$SM_DEFAULT_BIN" touch "$file"
	sm_assert_rc 0 "$rc" "touch <file> exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/file.out" "touch <file> renders content"
	sm_assert_contains "$SM_SCRATCH/file.out" "type file" "touch <file> names the file type"

	# Success path, directory form.
	sm_run "$SM_SCRATCH/dir.out" "$SM_SCRATCH/dir.err" rc 5 -- "$SM_DEFAULT_BIN" touch "$dir"
	sm_assert_rc 0 "$rc" "touch <dir> exits 0"
	sm_assert_contains "$SM_SCRATCH/dir.out" "type directory" "touch <dir> names the directory type"

	# Error path: a path that does not exist (battery-pinned).
	sm_run "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" rc 5 -- \
		"$SM_DEFAULT_BIN" touch "$SM_SCRATCH/no-such-path"
	sm_assert_rc 1 "$rc" "touch <missing> exits 1"
	if grep -q "path not found" "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" 2>/dev/null; then
		sm_pass "touch <missing> names the missing path"
	else
		sm_fail "touch <missing> names the missing path" "neither stream mentioned 'path not found'"
	fi

	# --since grammar and its invalid-duration refusal.
	sm_run "$SM_SCRATCH/since.out" "$SM_SCRATCH/since.err" rc 5 -- \
		"$SM_DEFAULT_BIN" touch "$file" --since 1m
	sm_assert_rc 0 "$rc" "touch --since 1m exits 0"
	sm_flag_used "touch --since"

	sm_run "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" rc 5 -- \
		"$SM_DEFAULT_BIN" touch "$file" --since nope
	sm_assert_rc 1 "$rc" "touch --since nope exits 1"
	if grep -q "invalid duration" "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" 2>/dev/null; then
		sm_pass "touch --since nope names the invalid duration"
	else
		sm_fail "touch --since nope names the invalid duration" \
			"neither stream mentioned 'invalid duration'"
	fi

	# Determinism: the fixture's mtimes are frozen for the whole
	# surface (nothing touches them), so the report is byte-stable
	# modulo the volatile-field table.
	sm_deterministic "touch determinism (fixture)" 5 -- "$SM_DEFAULT_BIN" touch "$file"

	# The color tri-test.
	# Gauge knob: the event window may cover the fixture
	# creation, so the NO_COLOR equality rides the volatile-field table.
	SM_TRITEST_NORMALIZE=1 sm_color_tritest "touch" 5 -- "$SM_DEFAULT_BIN" touch "$file"

	# Lane honesty: no dormant build exists (owner law); the lane
	# declaration and the no-fake-observed-rows rule are the check.
	sm_run "$SM_SCRATCH/lane.out" "$SM_SCRATCH/lane.err" rc 5 -- "$SM_DEFAULT_BIN" touch "$file"
	sm_assert_rc 0 "$rc" "lane honesty: touch renders its mode"
	sm_assert_contains "$SM_SCRATCH/lane.out" "Mode:" "lane honesty: touch declares its lane"
	if grep -q "Mode: snapshot" "$SM_SCRATCH/lane.out"; then
		sm_assert_not_contains "$SM_SCRATCH/lane.out" "\\[observed\\]" \
			"lane honesty: snapshot mode renders no fake [observed] rows"
	else
		sm_pass "lane honesty: snapshot mode renders no fake [observed] rows (probe lane active)"
	fi

	# The writev proof (night-improve-42), the touch half: the same
	# live vectorized write the why surface proves, caught by the
	# write surface's own window. A real writev(2) - two iovecs
	# through syscall 20 (x86_64, the only architecture this project
	# ships) - must surface as an [observed] row naming the write
	# path and the writer's pid. Gated on attach (the doctor's own
	# preflight) and perl on PATH; hosts without either skip with
	# the honest label.
	if command -v perl >/dev/null 2>&1 &&
		"$SM_DEFAULT_BIN" doctor --attach >"$SM_SCRATCH/wv-attach.out" 2>"$SM_SCRATCH/wv-attach.err"; then
		sm_pass "writev proof: the probe attaches on this host"
		local wv_file="$SM_SCRATCH/writev-proof.txt"
		local wv_touch_pid wv_writer wv_rc wv_pid
		: >"$wv_file"
		# The window opens first: touch inserts the filter key and
		# collects for --since seconds while the writer crosses it.
		timeout 20 "$SM_DEFAULT_BIN" touch "$wv_file" --since 5s \
			>"$SM_SCRATCH/wv-touch.out" 2>"$SM_SCRATCH/wv-touch.err" &
		wv_touch_pid=$!
		sleep 1
		# The writer: opens, writev's two buffers, prints its pid,
		# then stays alive past the render (an exited writer reads
		# as unaccounted by design - the attribution needs /proc).
		perl -e '
                        $| = 1;
                        my $f = shift;
                        open(my $fh, ">>", $f) or die "open: $!";
                        my $d1 = "zejtron-writev-proof-one-" . ("A" x 32);
                        my $d2 = "zejtron-writev-proof-two-" . ("B" x 32);
                        my $p1 = unpack("J", pack("p", $d1));
                        my $p2 = unpack("J", pack("p", $d2));
                        my $iov = pack("JJJJ", $p1, length($d1), $p2, length($d2));
                        my $r = syscall(20, fileno($fh), $iov, 2);
                        die "writev failed: $!" unless defined $r && $r == length($d1) + length($d2);
                        print "pid=$$\n";
                        sleep 8;
                ' "$wv_file" >"$SM_SCRATCH/wv-writer.out" 2>"$SM_SCRATCH/wv-writer.err" &
		wv_writer=$!
		wv_rc=0
		wait "$wv_touch_pid" || wv_rc=$?
		sm_assert_rc 0 "$wv_rc" "writev proof: touch --since 5s exits 0"
		wv_pid="$(grep -o "pid=[0-9]*" "$SM_SCRATCH/wv-writer.out" 2>/dev/null | head -1 | cut -d= -f2 || true)"
		if grep -q "wrote (writev)" "$SM_SCRATCH/wv-touch.out" 2>/dev/null; then
			sm_pass "writev proof: the write surface names the vectorized write path"
		else
			sm_fail "writev proof: the write surface names the vectorized write path" \
				"no 'wrote (writev)' row in the touch render"
		fi
		if [[ -n "$wv_pid" ]] && grep -q "pid $wv_pid," "$SM_SCRATCH/wv-touch.out" 2>/dev/null; then
			sm_pass "writev proof: the row attributes the writer (pid $wv_pid)"
		else
			sm_fail "writev proof: the row attributes the writer (pid ${wv_pid:-unknown})" \
				"the touch render does not name the writer pid"
		fi
		if grep -q "\[observed\]" "$SM_SCRATCH/wv-touch.out" 2>/dev/null; then
			sm_pass "writev proof: the writev row is [observed]"
		else
			sm_fail "writev proof: the writev row is [observed]" \
				"no [observed] tag in the touch render"
		fi
		kill "$wv_writer" 2>/dev/null || true
		wait "$wv_writer" 2>/dev/null || true
		# The surface ends clean: the probe it attached, it detaches.
		sm_run "$SM_SCRATCH/wv-detach.out" "$SM_SCRATCH/wv-detach.err" rc 20 -- \
			"$SM_DEFAULT_BIN" doctor --detach
		sm_assert_rc 0 "$rc" "writev proof: doctor --detach returns the host to clean"
		if [[ -e /sys/fs/bpf/zejtron ]]; then
			sm_fail "writev proof: detach removes the pin directory" \
				"/sys/fs/bpf/zejtron still exists after detach"
		else
			sm_pass "writev proof: detach removes the pin directory"
		fi
	else
		sm_pass "writev proof: skipped on this host (no attach or no perl) - the refusal direction is the doctor surface's"
	fi
}
