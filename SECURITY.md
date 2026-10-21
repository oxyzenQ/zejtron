<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security Policy

zejtron is a read-only introspection tool that renders kernel and
filesystem state to a terminal — security is part of the product, not
an afterthought. This file is the security foundation: how to report,
what we support, what counts as a vulnerability, and where the audit
trail lives.

## Supported versions

| Version | Branch | Status |
|---------|--------|--------|
| 11.x (main) | `main` | **supported** — active maintenance (bug fixes, kernel compatibility, hardening) |

Pre-release channels (`dev`, `nightly`, `alpha`, `beta`) are
development artifacts: reports against them are welcome and triaged,
but fixes land on `main` first.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Use GitHub's **private vulnerability reporting** on this repository:
*Security tab → "Report a vulnerability"*. If that button is disabled
on your view, open a **draft security advisory** instead
(*Security → Advisories → New draft security advisory*) — both routes
reach the maintainer privately.

Please include:

- the affected command/flag or code path (`zejtron -V` output helps),
- a minimal reproduction (commands, expected vs. observed),
- impact assessment — who can trigger it and what it costs.

You will get an acknowledgment within a reasonable window; fixes ship
as patch releases on `main` with credit in the changelog unless you
prefer to stay anonymous. Coordinated disclosure: we ask for up to
90 days before public disclosure, and we will not pursue anyone who
acts in good faith.

## Scope

In scope:

- The Rust CLI and everything it executes (`src/`), including the
  curl-backed `--check-update` surface.
- The release pipeline and artifacts: workflows (`.github/workflows/`),
  tarballs, checksums, install scripts.
- The security-relevant UX contract: privilege guards, error surfaces,
  the update-check guardrails.
- The eBPF attach lane (`doctor --attach` / `doctor --detach`) — the
  one surface that changes state, planting kernel pins under
  `/sys/fs/bpf/zejtron` and removing them again.
- The hostile-text display boundary: process names, cmdlines, audit
  comm values, cwd and symlink targets, and scanned filenames are
  attacker-controlled bytes; the neutralizer that keeps them from
  weaponizing the terminal (`src/system/mod.rs`'s
  `sanitize_display`) is security surface.

Out of scope (by design, not neglect):

- **Anything requiring the attacker to already be root.** The operator
  running zejtron owns the machine; the tool reports what the kernel
  already exposes to the reading user — hardening root's view is a
  hardening task, not a zejtron bug.
- **Evasion of introspection by design.** zejtron reports the procfs,
  sysfs, and audit/journal surfaces as the kernel presents them to the
  reading user; a process that hides from the kernel hides from
  zejtron. Visibility gaps are the kernel's disclosure model, not an
  enforcement failure.
- **Denial of service by a user who can already run processes on the
  machine against their own session**, unless it degrades other users
  or the host.
- Unmaintained versions, and social-engineering/phishing.

## What we treat as a vulnerability

Concrete classes we care about, with the current posture of each:

| Class | Posture |
|-------|---------|
| Privilege confusion (root used where it is not needed, or the inverse) | Guarded — `--check-update` refuses root with a drop-sudo tip; every read surface works unprivileged |
| Injection (command, path, format-string, CI script) | Audited — argv-array command invocation, kernel-generated paths rendered through the sanitizer boundaries, env-isolated CI scripts |
| Terminal escape injection | Guarded — the CWE-150 pass (night-total-lts-3): /proc-derived strings (comm, cmdline), audit comm values, cwd and symlink targets, and scanned filenames cross the trust boundary through the shared neutralizer (`system::sanitize_display`), which renders every control character as its printable `\u{..}` form; the release tag is refused outright (fail-closed); the color ladder degrades to plain text, never renders untrusted bytes as control sequences. Verified live with a `prctl(PR_SET_NAME)` process carrying ESC bytes |
| Panic surfaces reachable from user input | Pinned by the unit surface — clap-typed arguments and the per-verb target parsers reject malformed targets with labeled errors; `src/` carries zero `unwrap`/`expect`/`panic!` reachable from input |
| Supply chain (dependency compromise) | 4 direct deps, `cargo audit` + `cargo deny` in CI, chrono banned, every dep justified in [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md) |
| Release artifact tampering | SHA-512 + BLAKE3 + SHAKE256 checksums + GPG detached signatures; verify per [docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md) |

The full audit trail — findings, verdicts, and accepted risks — lives
in the docs tree ([docs/README.md](docs/README.md) indexes it) and is
updated with every security pass.

## Hardening posture (already shipped)

- Root is refused where it is a hazard: the one network surface
  (`--check-update`) refuses euid 0 before any network I/O with a
  drop-sudo tip — the network path must never ride root privileges.
- Read-only discipline: the command surface never modifies system
  state — no kill, no close, no service control, and since the v80
  surface reduction (night-improve-0) no filesystem writes at all:
  the read-only claim is literal. The lone state-changer is the
  opt-in eBPF attach lane, which plants and removes its own pins
  under `/sys/fs/bpf/zejtron` and nothing else. The `pathguard`
  module stays as the tested foundation for any future lane that
  would reintroduce state I/O.
- CodeQL + dependency audit (cargo audit, cargo deny) + the wholesale
  gate-keepers run in CI on every change.
- No config files, no daemons, no background network surface: the
  binary makes at most one outbound connection per invocation, in
  `--check-update`, time-boxed (`--max-time 15`), argv-array curl
  (no shell interpolation), and root-refused. The response is
  untrusted input too: a release tag carrying control characters is
  rejected fail-closed before it can reach the terminal — a MITM'd
  or compromised proxy response cannot inject escape sequences
  (OSC 52 clipboard rewrites, output forging).
- Every external invocation rides an argv array; /proc-derived values
  are data, never command fragments.
- CodeQL alert triage (2026-10-19, night-improve-33): the
  `rust/cleartext-logging` finding on `proc`'s snapshot print is
  by-design disclosure, not a defect. The rule's Rust source model
  is a NAME heuristic - identifiers whose spellings match
  `passwd`/`uid`/token-like patterns are treated as credential
  material. The data that reaches the terminal is the account name,
  uid, pid, and the cmdlines of kernel-exposed processes: exactly
  what ps(1) prints, into the invoking user's interactive terminal,
  not a persisted log (CWE-532 is a logging-sink rule), and never
  anything the kernel hides from the invoking uid. Renaming the
  honest domain vocabulary (`passwd_entries`, `*_uid`) to dodge the
  heuristic was rejected as self-deceiving; the alert is dismissed
  as a false positive by the owner. The finding re-surfaces as a
  fresh alert whenever a render refactor changes the query's flow
  fingerprint (first re-detection 2026-10-20 as alert #6, after the
  night-improve-37 render wiring); the verdict does not move, each
  re-detection is closed with the same fixed verdict by the CodeQL
  triage lane (codeql-triage.yml: a rule-id plus exact-path filter
  dismisses every open match right after each analysis, and no other
  rule or path is ever touched), and the rename stays rejected.

## Forensics scope (DFIR)

DFIR — digital forensics and incident response — is the use where
the read-only law matters most: zejtron can run during an active
incident without altering the evidence it is collecting. This
section states that claim and its boundary together.

What the tool offers an investigator:

- Read-only collection. The command surface writes nothing: no
  files created, modified, or deleted, so the mtime/ctime of the
  evidence stand as the kernel holds them. `zejtron touch` is not
  shell `touch` — it reads the timestamps, never sets them.
- Provenance on every row. The Evidence Ledger tags each row
  `[observed]` (kernel event), `[measured]` (snapshot read),
  `[inferred]` (log replay), or `[unaccounted]` (the honest gap) —
  the analyst knows which evidence is direct and which is
  circumstantial without re-deriving it.
- Deterministic, UTC-stamped output. Two runs against the same
  state print the same bytes, and no timestamp carries a
  local-timezone ambiguity — the report diffs against an earlier
  run and files into the incident record without translation.

What the tool is not:

- Not a write-blocker or an acquisition tool. zejtron takes no
  disk images and preserves no chain of custody — it prints
  evidence to the operator's terminal; filing the output is the
  operator's act.
- Not a rootkit hunter. A process that hides from the kernel hides
  from zejtron (evasion of introspection is out of scope by
  design, see Scope above).
- Not host-wide from inside a container. zejtron reads the /proc
  of the namespace it runs in; host processes stay invisible
  unless the container shares the host's pid namespace.

One residual, named: the opt-in eBPF attach lane
(`doctor --attach` / `doctor --detach`) plants and removes its own
pins under `/sys/fs/bpf/zejtron` — the single state-changing
surface. An analyst preserving a byte-exact host image should not
run it; every other surface leaves the host as it found it.

## Easy to use, by construction

Security that costs usability gets switched off by users. zejtron keeps
the two aligned: no keys, no config, no new workflow steps — the
hardening is invisible (guards, CI isolation) and the one behavioral
rule that matters is a clear error message, not a foot-gun
(`--check-update` tells you to drop sudo instead of failing
cryptically).
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
