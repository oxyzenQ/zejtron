<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

<p align="center">
  <img src="assets/zejtron-logo-new.png" alt="zejtron logo" width="260">
</p>

<h1 align="center">zejtron</h1>

<p align="center">
  <strong>Boring and serious. A Linux introspection command center for operators, engineers, and incident work.</strong>
</p>

<p align="center">
  Trace commands, ports, process trees, file holders, service evidence, and host readiness from one disciplined terminal interface.
</p>

<p align="center">
  <a href="https://ko-fi.com/rezky">
    <img src="https://img.shields.io/badge/Ko--fi-support-7C3AED?style=flat-square&logo=kofi&logoColor=white&labelColor=111827" alt="Support on Ko-fi">
  </a>
</p>

## Philosophy

**The boring and serious.**

Zejtron stays out of the operator's way while doing serious investigative
work underneath. The interface rarely changes. Output is deterministic and
read-only by design. Every release makes it slightly more stable, slightly
sharper, and slightly easier to maintain.

## What Is Zejtron?

Zejtron is a Linux-first command center for terminal introspection.
It consolidates functionality from pidnest and Zenlixem into one binary with one release flow.

| Origin | Zejtron command |
| --- | --- |
| pidnest | `zejtron proc` |
| Zenlixem `whoholds` | `zejtron holds` |
| Zenlixem `lasttouch` | `zejtron touch` |
| Zenlixem `whyopen` | `zejtron why` |
| Zenlixem `doctor` | `zejtron net` |
| Zenlixem `envpath` | covered by `zejtron path` |

## Demo

<!-- Capture assets: rendered from real zejtron output on an
     unprivileged container host, so port owners show as "unknown"
     without sudo and audit/journal evidence is best-effort there.
     The text output is the contract; the captures follow it. -->

<p align="center">
  <img src="assets/demo-doctor.png"
       alt="zejtron doctor readiness report"
       width="800"
       style="border-radius:24px; box-shadow:0 4px 20px rgba(0,0,0,0.15);">
</p>

<p align="center">
  <img src="assets/demo-why.png"
       alt="zejtron why evidence report for /etc/resolv.conf"
       width="800"
       style="border-radius:24px; box-shadow:0 4px 20px rgba(0,0,0,0.15);">
</p>

<p align="center">
  <video src="assets/demo-proc-live.webm"
         width="640"
         autoplay
         loop
         muted
         style="border-radius:24px; box-shadow:0 4px 20px rgba(0,0,0,0.15);">
  </video>
</p>

## Install

### AUR

```sh
paru -S zejtron-bin
yay -S zejtron-bin
```

### GitHub Release

The release matrix ships exactly four shapes: the x86-64-v3/v4
microarch levels for both libc flavors (v3 covers Haswell 2013+,
v4 covers AVX-512-era 2017+; musl builds are fully static).

```sh
TAG=v11.0.0
SHAPE=linux-amd64-v3-gnu   # or v4-gnu / v3-musl / v4-musl
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-${TAG}-${SHAPE}.tar.gz"
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-${TAG}-${SHAPE}.tar.gz.sha512sum"
sha512sum --check "zejtron-${TAG}-${SHAPE}.tar.gz.sha512sum"
tar -xzf "zejtron-${TAG}-${SHAPE}.tar.gz"
install -Dm755 zejtron "$HOME/.local/bin/zejtron"
```

Each release also ships quantum-resistant checksums (BLAKE2b +
SHAKE256) and, when the release key is configured, a detached GPG
signature per archive. See [docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md)
for full instructions, and the arch-baseline alias commands
(`cargo pro-linux-amd64-v3-gnu` and friends) that reproduce the
release optimization tier bit-for-bit.

### crates.io

```sh
cargo install zejtron
```

### From Source

```sh
git clone https://github.com/oxyzenQ/zejtron
cd zejtron
cargo install --path .
```

## Command Overview

| Command | Purpose |
| --- | --- |
| `path` | Trace command origin |
| `recent` | Show recently modified files |
| `port` | Inspect ports and process owners |
| `proc` | Inspect process trees by user or UID |
| `holds` | Show processes holding a file, device, or port |
| `touch` | Inspect last modification evidence for a path |
| `why` | Explain visible evidence for a path or port |
| `env` | Snapshot and diff environment variables |
| `service` | Inspect systemd services |
| `shell` | Inspect current shell context |
| `net`   | Inspect network interfaces and routing |
| `git`   | Inspect git repository context |
| `doctor` | Check Zejtron system capability/readiness |

## Quick Examples

```sh
zejtron path sh
zejtron port --tcp --group
zejtron proc --me --depth 1
zejtron holds 53
sudo zejtron holds 53
zejtron touch /etc/resolv.conf
zejtron why /etc/resolv.conf
zejtron doctor
zejtron -V
zejtron --check-update
```

`-V` and `--version` print complete version, build, build-time (UTC),
license, and source metadata. `--check-update` checks the latest
upstream GitHub release; the `--check-updated` alias is accepted too.
Evidence timestamps shown by `touch` and `path --verbose` render in
UTC with an explicit marker, identical on every host.

## Compatibility

Zejtron is Linux-first and expects procfs at `/proc`. Most commands work without systemd: `path`, `recent`, `port`, `env`, `proc`, `holds`, `touch`, `why`, and `doctor`.

`service` requires systemd and `systemctl`. `touch` and `why` can use filesystem metadata on supported Linux systems, while journal evidence depends on `journalctl` and systemd journal availability. `holds`, `port`, and `proc` may show more complete details with `sudo` on hardened systems. `net` reads from sysfs and procfs without external commands. `git` requires the `git` binary and only invokes read-only subcommands.

## Safety

Zejtron is read-only by design. It does not kill processes, close ports, start or stop services, or modify files. `zejtron touch` inspects file evidence; it is not shell `touch` and does not create files or change timestamps.

## Commands

### `path`

Trace where a command comes from by scanning `PATH`, showing all matches, the active match, executable status, symlink targets, and Arch package ownership when `pacman` is available.

```sh
zejtron path sh
```

### `recent`

Show recently modified files under a path.

```sh
zejtron recent
zejtron recent . --limit 5
zejtron recent ~/src --since 1d
```

### `port`

Show listening TCP/UDP ports and process owners when discoverable.

```sh
zejtron port
zejtron port 3000
zejtron port --tcp --group
zejtron port --udp
zejtron port --all
zejtron port --no-pid
```

### `proc`

Show a clean process tree for a Linux user or UID.

```sh
zejtron proc --me
zejtron proc rezky
zejtron proc root --depth 1
zejtron proc rezky --find python
zejtron proc rezky --no-pid
zejtron proc rezky --live --interval 6
```

### `holds`

Show processes holding a file, device, or specific TCP/UDP port.

```sh
zejtron holds 3000
zejtron holds /etc/resolv.conf
zejtron holds /dev/nvme0n1
```

### `touch`

Inspect last modification evidence for a path. Metadata shows when a path changed, not who changed it; audit and journal evidence is best-effort.

```sh
zejtron touch /etc/resolv.conf
zejtron touch ./README.md
zejtron touch "/path/with spaces/file.txt"
```

### `why`

Explain visible evidence for a path or port without inferring intent.

```sh
zejtron why 53
zejtron why 3000
zejtron why /etc/resolv.conf
zejtron why ./README.md
```

### `env`

Inspect current environment variables, save named snapshots, and diff a saved snapshot against the current terminal environment.

```sh
zejtron env
zejtron env --keys
zejtron env --filter path
zejtron env save base
zejtron env diff base
zejtron env list
zejtron env delete base
```

### `service`

Inspect systemd service units in a read-only view.

```sh
zejtron service
zejtron service --user
zejtron service --failed
zejtron service --all
zejtron service --filter unbound
```

### `doctor`

Check Linux/procfs visibility, visible processes, `/proc/net` socket parsing, holder scan readiness, optional audit and journal evidence, systemctl/systemd availability, and build metadata.

```sh
zejtron doctor
```

### `shell`

Inspect current shell context in a read-only view. Reports the parent process, login shell, terminal, shell-related environment variables, and known config file paths for the detected shell.

```sh
zejtron shell
```

### `net`

Inspect network interfaces and routing context in a read-only view. Reports interfaces from sysfs with state, MTU, and MAC address. Shows default route from procfs and resolver file status.

```sh
zejtron net
```

### `git`

Inspect git repository context in a read-only view. Reports the repository root, branch, working tree status, latest commit, and remote URLs. Only invokes read-only git subcommands. Credentials embedded in remote URLs (e.g. PATs in HTTPS URLs) are redacted as `<redacted>` in output.

```sh
zejtron git
```

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the project roadmap and design direction, or [docs/ROADMAP-current.md](docs/ROADMAP-current.md) for the current design document.

## Migration

`pidnest` and Zenlixem are superseded by Zejtron. See the origin table above for command mapping.

## Development

```sh
./scripts/build.sh
SKIP_CODESPELL=1 ./scripts/build.sh
./scripts/dev/version-to.sh vX.Y.Z
```

## Intellectual Property & Trademark

**zejtron** is the exclusive intellectual property of
**rezky_nightky (oxyzenQ)**.

- Source code: licensed under **GPL-3.0-only** (see [LICENSE](LICENSE)).
  Proprietary/commercial use that cannot meet the GPL is available
  under the commercial license - see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)
  and [NOTICE](NOTICE) for tiers and terms.
- Name, logo, and branding ("the Marks"): governed by
  [TRADEMARK.md](TRADEMARK.md). The Marks are NOT covered by the GPL and
  are reserved by the owner.
- Unauthorized rebranding, relicensing, or source-code theft is strictly
  prohibited.

For trademark licensing or written permission, contact
**rezky_nightky (oxyzenQ)** — https://github.com/oxyzenQ.

---

© 2026 rezky_nightky (oxyzenQ). All rights reserved.
