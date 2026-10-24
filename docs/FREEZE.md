<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# The v80.0.0 LTS Freeze Declaration

v80.0.0 is the LTS stable baseline. The beta gate is closed: the
`80.0.0-beta.N` and `80.0.0-alpha.N` pre-release ladder ends here,
and the version carries no pre-release suffix from this point on.

What the freeze means, exactly:

- The CLI surface is frozen. No breaking changes to commands, flags,
  or output format from v80.0.0 on - the same contract the README's
  Stable API section states, now effective. The nine surfaces
  (`path`, `recent`, `port`, `proc`, `holds`, `touch`, `why`, `net`,
  `doctor`) keep their spellings, flags, and output bytes.
- The Evidence Ledger Specification v3 is frozen with it
  ([docs/EVIDENCE-LEDGER.md](EVIDENCE-LEDGER.md)), including the
  JSON surface (`--print-json`) and its field map - automation
  written against it keeps working. v3 flattened the JSON row and
  typed the actor (the last pre-freeze corrections rc.1 carries;
  v2 had typed the row's `action` field); v2 and v1 remain
  citable inside the spec document's archive.
- Future releases carry bug fixes, procfs/sysfs compatibility, and
  internal performance only. Additive changes (new flags, new
  sections) ride minor versions without breaking the contract.
- The release matrix is the two fully static musl shapes
  (`linux-amd64-v3-musl`, `linux-amd64-v4-musl`); the GNU builds are
  retired (night-badass-1) and do not return.
- The dependency law holds: exactly three runtime crates (`clap`,
  `regex-lite`, `aya`), `chrono` banned, no `serde`, no `tokio`, no
  `libbpf` - new surfaces cost zero crates, as the hand-written JSON
  serializer proves.

Version mirror law at freeze time: root `Cargo.toml`,
`ebpf/Cargo.toml`, `Cargo.lock`, `ebpf/Cargo.lock`, and the prebuilt
lane's `[contract]` version all say `80.0.0`; the manifest's tree pin
matches the committed `ebpf/` tree (verified by
`scripts/dev/regenerate-ebpf-prebuilt.sh --check`). The release
ledger records `v80.0.0` newest-first in `CHANGELOG.md`.

What the freeze does NOT mean:

- It does not close development - the LTS baseline still takes fixes
  and additive work through the normal gated flow.
- It does not publish to crates.io by itself: the owner runs the
  manual publish lane ([PUBLISH-CHECKLIST.md](../PUBLISH-CHECKLIST.md)).
- It does not tag the release: `git tag -a v80.0.0 -m "v80.0.0"` is
  the owner's hand (see
  [docs/workflow/about-ci.md](workflow/about-ci.md)).

### The Architecture Scope (The AMD64 Baseline)

The freeze applies to the x86_64 (amd64) architecture. It is the
only shape zejtron compiles, ships, and verifies end-to-end: the
two musl release shapes run the full Supermassive E2E suite on real
hardware before a release ships, and no architecture outside that
lane is claimed alongside them.

The honesty splits cleanly across the two layers:

- The eBPF object is architecture-independent. It is bpfel
  bytecode - compiled once for the BPF ISA, one object for every
  host microarchitecture (the One Object Law,
  [EBPF_LIFECYCLE.md](EBPF_LIFECYCLE.md)) - and the running kernel
  JITs it to the native CPU at attach time. The kernel probes
  therefore work on any CPU that runs the kernel.
- The userspace binary (the CLI) is compiled and verified only for
  x86_64. That is where the line sits: we do not ship binaries we
  cannot run through the full E2E suite ourselves.

There is no ARM64, ppc64le, or RISC-V lane in the release matrix,
no cross-compilation target in the build config, and no "coming
soon" promise. If your infrastructure runs another architecture,
build from source (pure Rust, GPL-3.0), or request an officially
verified build through the enterprise license: we compile the
shape, run the full test suite, and provide the verified artifact.
