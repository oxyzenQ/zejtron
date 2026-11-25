<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# Z11 - The Green Baseline, Recorded (2026-11-25)

The first all-green Z11 detonation on the host's own kernel and the
host's own vmlinux - five legs, zero refusals, and the failure arc
that got it there, written down while the evidence is fresh.

## The run

- **Date / time:** 2026-11-25, 12:37
- **Host:** nightpc (rezky) · **Kernel:** 6.18.60-3-cachyos-lts
- **Lane:** `sudo ./scripts/sandbox/detect-rootkit.sh`
- **Commit range:** `b410054..fd34b03` - exactly one commit in the
  range (`fd34b032b14dc10d0d8755469a7e524e49a36fc8`), `+16/-2` in
  `test-fixtures/pidhide/src/btf.rs`
- **Closing commit:** `fd34b03` - *"night-frontier-Z11 c/D9c - the
  info word decodes like the camera's"*
- **Main binary:** built at `1d57b97`, version `v80.6.0-dragon.1`
  (untouched - the commit touches fixture sources only)
- **Verdict:** `SANDBOX-VERDICT: PASS (legs passed: 5)`

## The timeline: refusal, then fix

1. **The state before (the `4a6c14c` era).** The silent-fixture-build
   fix had landed - artifacts build, seats resolve - yet leg b still
   failed, and the failure had changed shape: no longer a build that
   swallowed its own errors, but the **refusal lane** turning the
   loader away *by name* - a string offset of `0x0A000000`, past the
   end of the BTF string section. The new signature was not a
   regression; it was the defense working. The failure was loud and
   named its cause instead of desyncing quietly.
2. **The diagnosis (`fd34b03`).** The info word was decoded swapped.
   The first shape read `kind` from the low bits and `vlen` from the
   high half; the kernel packs `vlen` into bits 0-15, `kind` into
   bits 24-28, and bit 31 is `kind_flag` - and when the flag is set,
   the low field is not a 16-bit vlen at all but `vlen:10 | klen:6`.
   The synthetic blobs were built with the same swapped encoding, so
   the fixture's self-test agreed with its own walker and passed,
   while the real vmlinux desynced at the first `kind_flag`ged
   record. "Green in test, red in the world" is exactly the seam the
   refusal lane exists to catch.
3. **The fix.** The camera's `decode_info`, ported whole - one source
   of decoding truth instead of two implementations that can drift
   apart. The replica now builds its blobs with the real encoding,
   strides a kflagged shape, and walks the sandbox's own vmlinux end
   to end: **129,275 records consume the section exactly**
   (stride-exact - no short read, no overrun), the container resolves
   with **all five members**, and `current_dir` sits at **byte 16**.
   The hide mechanism works, the census catches the disagreement
   (absent from the list, present on direct lookup), the camera
   records it, leg b passes.
4. **The staleness guard earned its keep**, in the same run:
   `── fixtures: the seats resolve but predate the fixture sources -
   forcing the rebuild (a stale pair would run an earlier shape's
   bytes) ──`. The `btf.rs` change made the `4a6c14c`-era seats stale
   against their sources; the guard forced the rebuild before leg b
   ran, so the old shape's bytes never executed. Without the guard,
   this run would have measured stale artifacts and returned a
   verdict that was wrong.

## The legs

| Leg | Name | Result |
| --- | --- | --- |
| a | negative-control (visible writer) | PASS |
| b | pidhide (the real stealth mechanism) | PASS |
| c | silent-deletion (the lanes' disagreement) | PASS |
| d | id-plane (attached estate) | PASS |
| e | honesty (no CAP_SYS_ADMIN) | PASS |

- Attach: `12 programs, 12 links, 8 maps`; off-path truth:
  splice+memory-backed; Lazy Camera recording.
- Detach: `28 pins removed` - nothing left pinned.
- Whole run: about five seconds.

## What this baseline means

Leg b is no longer "green on the CI kernels, on synthetic vmlinux" -
the pidhide mechanism (fentry on `filldir64`, hide via `d_reclen`
absorb, cursor offsets 16/20) is now proven intact on the host's own
kernel, 6.18.60, against real BTF, 129,275 records deep. The refusal
lane, the staleness guard, and the single decode borrowed from the
camera close as one chain: one decoding truth, artifacts guaranteed
fresh, every failure named. The arc `4a6c14c → refusal 0x0A000000 →
fd34b03` is the defense working end to end - detection to closure -
and this file is its record.

## Going forward

- No local changes ride with this note; no commit, benchmark, or
  gate was owed by the code (the main binary is untouched by
  `fd34b03`).
- No manual fixture cleanup is ever needed again: whenever fixture
  sources change, the staleness guard forces the rebuild on its own.
- The full run transcript is preserved verbatim in Appendix A; this
  file quotes its verdict lines and changes none of them.

## Appendix A: the run transcript (2026-11-25 12:37)

```text
── z11 detonation: attach (root, the lane the legs ride) ──
eBPF probes attached successfully (12 programs, 12 links, 8 maps; off-path truth: splice+memory-backed). Lazy Camera is now recording.
── z11 detonation: leg a (negative control, visible writer) ──
SANDBOX-RESULT: z11 leg a-negative-control - PASS
── z11 detonation: leg b (pidhide, the real stealth mechanism) ──
── fixtures: the seats resolve but predate the fixture sources - forcing the rebuild (a stale pair would run an earlier shape's bytes) ──
SANDBOX-RESULT: z11 leg b-pidhide - PASS
── z11 detonation: leg c (silent deletion, the lanes' disagreement) ──
SANDBOX-RESULT: z11 leg c-silent-deletion - PASS
── z11 detonation: leg d (the ID plane, attached estate) ──
SANDBOX-RESULT: z11 leg d-id-plane - PASS
── z11 detonation: leg e (the honesty row, no CAP_SYS_ADMIN) ──
SANDBOX-RESULT: z11 leg e-honesty - PASS
eBPF probes detached (28 pins removed).
SANDBOX-VERDICT: PASS (legs passed: 5)
```

## Appendix B: the info-word decode, before and after

```rust
// BEFORE (swapped):
let kind = info & 0x1f;
let vlen = ((info >> 16) & 0x7fff) as usize;

// AFTER (linux/btf.h - the camera's decode_info, ported whole):
let kind = (info >> 24) & 0x1f;
let vlen = if info & 0x8000_0000 != 0 {
    (info & 0x3ff) as usize          // kind_flag set: vlen:10 | klen:6
} else {
    (info & 0xffff) as usize         // full 16-bit vlen
};
```

<!-- ZEJTRON-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
