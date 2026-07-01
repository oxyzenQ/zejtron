# Changelog

All notable changes to zejtron.

## [v10.0.0] — 2026-07-01

### Architecture Alignment

### Changed — amd64 Only + Static musl Binary
- Release binaries: amd64 Linux only (gnu + musl) per project policy
- Removed aarch64 cross-compile target
- Added x86_64-unknown-linux-musl (static binary, zero dynamic deps)
- Both archives served on GitHub Release page automatically

### Verified
- 240 tests PASS
- clippy: 0 warnings
- Binary size: 1.5 MB (3 deps: chrono, clap, ctrlc)
- All CI checks PASS (fmt, clippy, test, codespell, yamllint, actionlint)

## [v5.0.2] — Previous release

- Unified Linux introspection toolkit
- Paths, ports, processes, files, services, diagnostics
- 240 tests, 3 dependencies
