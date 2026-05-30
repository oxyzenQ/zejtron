<p align="center">
  <img src="assets/zejtron-logo.png" alt="Zejtron logo" width="250">
</p>

<h1 align="center">Zejtron</h1>

<p align="center">
  <strong>Unified Linux introspection toolkit.</strong>
</p>

<p align="center">
  Trace paths, ports, processes, file holders, service evidence, and system readiness from one fast terminal command.
</p>

<p align="center">
  <a href="https://github.com/oxyzenQ/zejtron/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/oxyzenQ/zejtron/ci.yml?branch=main&label=CI&style=flat-square&color=7C3AED&labelColor=111827" alt="CI status">
  </a>
  <img src="https://img.shields.io/badge/version-v2.4.2-7C3AED?style=flat-square&labelColor=111827" alt="Version v2.4.2">
  <img src="https://img.shields.io/badge/license-MIT-6D28D9?style=flat-square&labelColor=111827" alt="MIT license">
  <img src="https://img.shields.io/badge/AUR-zejtron--bin-8B5CF6?style=flat-square&labelColor=111827" alt="AUR package zejtron-bin">
  <img src="https://img.shields.io/badge/Rust-1.85+-A855F7?style=flat-square&labelColor=111827" alt="Rust 1.85+">
  <a href="https://ko-fi.com/rezky">
    <img src="https://img.shields.io/badge/Ko--fi-support-7C3AED?style=flat-square&logo=kofi&logoColor=white&labelColor=111827" alt="Support on Ko-fi">
  </a>
</p>

## What Is Zejtron?

Zejtron is a Linux-first command center for terminal introspection. It brings the useful ideas from pidnest and Zenlixem into one flagship binary with one identity, one release flow, and one command surface.

| Origin | Zejtron command |
| --- | --- |
| pidnest | `zejtron proc` |
| Zenlixem `whoholds` | `zejtron holds` |
| Zenlixem `lasttouch` | `zejtron touch` |
| Zenlixem `whyopen` | `zejtron why` |
| Zenlixem `doctor` | `zejtron doctor` |
| Zenlixem `envpath` | covered by `zejtron path` |

## Install

### AUR

```sh
paru -S zejtron-bin
yay -S zejtron-bin
```

### GitHub Release

```sh
TAG=v2.4.2
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-x86_64.tar.gz"
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-x86_64.tar.gz.sha512"
sha512sum --check "zejtron-bin-${TAG}-linux-x86_64.tar.gz.sha512"
tar -xzf "zejtron-bin-${TAG}-linux-x86_64.tar.gz"
sudo install -Dm755 zejtron /usr/local/bin/zejtron
```

For aarch64 Linux, use `zejtron-bin-${TAG}-linux-aarch64.tar.gz`.

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
```

## Compatibility

Zejtron is Linux-first and expects procfs at `/proc`. Most commands work without systemd: `path`, `recent`, `port`, `env`, `proc`, `holds`, `touch`, `why`, and `doctor`.

`service` requires systemd and `systemctl`. `touch` and `why` can use filesystem metadata on supported Linux systems, while journal evidence depends on `journalctl` and systemd journal availability. `holds`, `port`, and `proc` may show more complete details with `sudo` on hardened systems.

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

## Migration

`pidnest` has moved into Zejtron as `zejtron proc`.

Zenlixem functionality has moved into Zejtron as `holds`, `touch`, `why`, `doctor`, and `path`.

## Development

```sh
./check.sh
SKIP_CODESPELL=1 ./check.sh
./version-to.sh vX.Y.Z
```

## Trademark

The source code is licensed under the MIT License. The Zejtron name and branding are not granted under the MIT License. See [TRADEMARK.md](TRADEMARK.md).
