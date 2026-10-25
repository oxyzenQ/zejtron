<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron Future Roadmap

> **Status:** v10.0.0 released. This document is for future development.
> **Last updated:** 2026-07-01
> **Maintainer:** rezky_nightky (oxyzenQ)

---

## Locked Principles

| Principle | Detail |
|-----------|--------|
| **Linux first** | amd64 Linux binaries (musl, fully static) |
| **Minimal deps** | Keep dependency count low (currently 4 - the count's one home: [DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md)) |
| **Fast** | Introspection must be instant |
| **No daemon** | CLI tool, not a service |

---

## Completed

| Version | Focus | Highlights |
|---------|-------|-----------|
| v10.0.0 | Architecture Alignment | amd64 only, musl static binary, polished release |

---

## Future Phases

### Phase 1: v10.1.0 — Polish & Features

| Feature | Complexity |
|---------|-----------|
| Shell completions (bash/zsh/fish via clap_complete) | Low |
| Man page generation (clap_mangen) | Low |
| JSON output mode (--json) for all subcommands | Medium |
| Color output with NO_COLOR support | Medium |
| Config file (~/.config/zejtron/config.toml) | Medium |

### Phase 2: v10.2.0 — Intelligence

| Feature | Complexity |
|---------|-----------|
| Process tree visualization (ASCII tree) | Medium |
| Port connection graph (which process connects where) | Medium |
| File descriptor leak detection | Medium |
| Service dependency graph | High |
| Real-time watch mode (--watch with adaptive refresh) | Medium |

### Phase 3: v11.0.0 — Ecosystem

| Feature | Complexity |
|---------|-----------|
| Plugin system (Lua scripts for custom inspectors) | High |
| Prometheus metrics export (--metrics) | Low |
| Audit log (JSONL of all introspection queries) | Low |
| Cross-platform (FreeBSD, macOS source support) | Medium |

---

## Explicitly Rejected

| Feature | Why |
|---------|-----|
| ~~aarch64 cross-compile~~ | amd64 only per policy |
| ~~Background daemon~~ | CLI tool, not a service |
| ~~GUI~~ | Terminal tool |
| ~~Cloud features~~ | Local introspection only |

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
