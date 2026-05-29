# Changelog

## v2.4.1

- Maintenance release.
- Tighten repository and workflow consistency.
- Sync project descriptions across Cargo, README, CLI help, and AUR metadata.
- Make command and help order consistent.
- Harden AUR sync validation and SSH cleanup.
- Make `version-to.sh` update the README version badge.
- Add Dependabot maintenance PRs for Rust and GitHub Actions dependencies.

## v2.4.0

- Add `zejtron doctor`.
- Merge selected Zenlixem doctor capability checks into Zejtron.
- Report Linux, procfs, proc-net, journal, systemctl, and build readiness.

## v2.3.0

- Add `zejtron why`.
- Merge selected Zenlixem `whyopen` functionality into Zejtron.
- Add read-only narrative explanation for path and port evidence.

## v2.2.0

- Add `zejtron touch`.
- Merge selected Zenlixem `lasttouch` functionality into Zejtron.
- Add read-only path modification evidence inspection.

## v2.1.0

- Add `zejtron holds`.
- Merge selected Zenlixem `whoholds` functionality into Zejtron.
- Add path, device, and port holder inspection.

## v2.0.0

- Add `zejtron proc`.
- Merge pidnest process tree functionality into Zejtron.
- Zejtron becomes unified Linux introspection command center.

## v1.0.0 Stable

- Stable CLI release.
- Includes `path`, `recent`, `port`, `env`, and `service`.
- Includes GitHub Release and AUR automation for `zejtron-bin`.

## v0.4.0

- Added the read-only systemd service inspector.

## v0.3.0

- Added environment variable snapshot and diff commands.

## v0.2.2

- Polished empty-result output for `port`.

## v0.2.1

- Added grouped `port` output.

## v0.2.0

- Added the Linux `/proc` port inspector.

## v0.1.0

- Added the initial `path` and `recent` MVP commands.
