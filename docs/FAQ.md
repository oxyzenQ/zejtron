<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron FAQ — Q/A

The quick answers a serious reader asks before trusting the tool on
a real host. Everything here is grounded in the source; where a
deeper document owns the fact, it is linked.

## Root & privileges

### Q: Does zejtron need root?

No — and it never hides which world you are in. Every command runs
unprivileged on the snapshot lane (filesystem metadata plus whatever
the audit log or `journalctl` recorded). The one privileged step is
`sudo zejtron doctor --attach`: a one-shot that plants the kernel
probes under `/sys/fs/bpf/zejtron` and exits — no daemon, no
background agent. While the pins exist, `why`, `holds`, and `touch`
gain `[observed]` rows: the kernel's own record of who opened or
wrote what, pid attributed. `sudo zejtron doctor --detach` unpins
everything. When the pins exist but belong to root, a non-root run
does not fail — it steps down and the Unaccounted block carries the
note saying a stronger lens existed and was out of reach.
`docs/USAGE.md` owns the full privilege picture.

### Q: What capabilities does the attach need?

`CAP_BPF` + `CAP_PERFMON` (root carries both). The doctor's `[eBPF]`
section names the kernel's own verdict — BTF, lockdown, capabilities,
pins — in plain rows, so you never guess why the live lane is dark.

## Kernel & distro support

### Q: Which kernels work?

Linux 5.15 or newer (the documented floor), with kernel BTF present
and security lockdown inactive for the attach lane. The attach
verifies every struct offset against the host's vmlinux BTF and
refuses on missing members rather than reading garbage — a refusal
is an answer, not a crash. The snapshot lane needs only procfs at
`/proc`: any Linux, any distro, containers included.

### Q: Which binaries do I download?

The release matrix ships `linux-amd64-v3-musl` and
`linux-amd64-v4-musl` — fully static, no dynamic dependencies
(`ldd` says "not a dynamic executable"), so the same tarball runs on
glibc and musl distros alike. `zejtron -V` names the shape you are
holding: `Build: pro-linux-amd64-v3-musl` for a downloaded release
binary, `Build: local-...` for anything built on the machine you are
standing on (see `docs/VERIFY_RELEASE.md`).

## Where the eBPF objects come from

### Q: Does zejtron compile eBPF at install time? Do I need nightly?

No. The kernel objects ride INSIDE the binary (`include_bytes!`) on
both lanes: a git checkout source-builds them through a nested
nightly invocation at compile time, and a crates.io install
(`cargo install zejtron`) stages the maintainer-built,
manifest-verified object from `ebpf-prebuilt/` — the same bytes the
release binaries embed, BLAKE3-pinned in
`ebpf-prebuilt/manifest.toml`. Either way the TARGET machine needs
no nightly toolchain, no bpf-linker, no clang, and no separate
object files. `-V`'s `Signature: Pure eBPF builtin` line is the
lane-honest claim that the objects are in there.

## The JSON lane

### Q: Is there machine-readable output?

Every data surface speaks typed JSON through `--print-json` — one
line, byte-deterministic, jq-ready
(`zejtron port --tcp --print-json | jq '.[] | select(.state=="LISTEN")'`).
The serializer is hand-written and std-only (no serde in the graph,
by the dependency law — see `docs/DEPENDENCY_AUDIT.md`); absent
facts serialize as JSON null, never empty strings, and the
`docs/EVIDENCE-LEDGER.md` specification owns the row grammar.

## Privacy & telemetry

### Q: Does zejtron phone home?

Only when you ask it to: `--check-update` is the one network call
(it shells out to `curl` against the GitHub release feed), and it
never runs implicitly. Everything else reads the local host —
`/proc`, `/sys`, the audit log, optional `journalctl` — and prints
to stdout. No daemon, no background agent, no writes to disk, no
telemetry, no config files.

## Colors

### Q: Can I turn the purple off?

Yes. The brand purple (#A855F7) renders only on a TTY that
advertises color; piped output is plain bytes by construction, so
ANSI codes never leak into scripts or logs. `NO_COLOR` or
`CLICOLOR=0` forces plain everywhere; `CLICOLOR_FORCE=1` re-arms
color for captured runs. The build facts under `-V`'s header are
always plain — they are the data a script greps.

## Verifying a release

### Q: How do I verify a downloaded binary?

Every release ships three checksum files per archive (SHA-512,
BLAKE3, SHAKE256) and, when configured, a detached GPG signature.
`docs/VERIFY_RELEASE.md` owns the exact commands, and the `Build:`
line contract for naming the artifact you are holding.

## Deployment shapes: desktop, server, ultra scale

### Q: Is zejtron a desktop tool or a server tool?

Both, without carrying two personalities. On a server it is the
primary ground: one statically linked binary, dropped on the host or
into a container, that runs, prints, and exits — deterministic UTC
output means two runs print the same bytes, so a report can be
diffed, attached to a post-mortem, or filed as a compliance record.
On a desktop the same binary answers the local questions — which
process holds port 3000, what last modified that config, where the
RAM went. There is no daemon to enable, no service to configure, and
no state directory: the host is unchanged by an investigation,
which is what makes it safe during an active incident.

### Q: What holds at ultra scale (huge process trees, many open files)?

The three core readers stay within their wall-clock budgets, and the
claim is tested, not aspirational: `scripts/bench/scale-audit.sh`
spawns a synthetic busy host (1,000 processes and 1,000 open-file
holders by default) and gates the worst of three cold-start runs of
`zejtron proc --me`, `zejtron holds <target>`, and
`zejtron doctor --symptom ram` against a 500 ms budget — a miss is a
hard fail, and every scaledown note is printed, never swallowed.
The knobs scale the audit to your host:
`ZEJTRON_SCALE_PROCS`, `ZEJTRON_SCALE_FDS`, `ZEJTRON_SCALE_HOLDERS`,
and `ZEJTRON_SCALE_BUDGET_MS`. The eBPF lane holds its shape under
event pressure by construction — the Lazy Camera records into
bounded rings in the kernel and never streams to userspace
(`docs/EBPF_LIFECYCLE.md`), so a busy host pays nothing until a
window is actually drained. The honest boundary: zejtron is an
investigative CLI, not a monitoring daemon — at any scale it
collects evidence and exits; if you need continuous real-time
streams, this is the wrong tool.

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
