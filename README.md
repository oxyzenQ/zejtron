<p align="center">
  <img src="assets/zejtron-logo.png" alt="zejtron logo" width="160">
</p>

<h1 align="center">zejtron</h1>

<p align="center">
  <a href="https://github.com/oxyzenQ/zejtron/actions/workflows/ci.yml"><img src="https://github.com/oxyzenQ/zejtron/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://ko-fi.com/rezky"><img src="https://img.shields.io/badge/Ko--fi-rezky-ff5f5f?logo=kofi&logoColor=white" alt="Ko-fi"></a>
</p>

<p align="center">Zejtron v2.4.0 is the unified Linux terminal toolkit for tracing command paths, recent files, ports, holders, reasons, diagnostics, file change evidence, environment variables, systemd services, and process trees.</p>

## Install From AUR

```sh
paru -S zejtron-bin
```

`yay -S zejtron-bin` works too.

## Install From GitHub Release

```sh
TAG=v2.4.0
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-x86_64.tar.gz"
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-x86_64.tar.gz.sha512"
sha512sum --check "zejtron-bin-${TAG}-linux-x86_64.tar.gz.sha512"
tar -xzf "zejtron-bin-${TAG}-linux-x86_64.tar.gz"
sudo install -Dm755 zejtron /usr/local/bin/zejtron
```

For aarch64 Linux, use `zejtron-bin-${TAG}-linux-aarch64.tar.gz`.

## Install From Source

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
| `port` | Inspect ports and owners |
| `holds` | Show processes holding a file, device, or port |
| `touch` | Inspect last modification evidence for a path |
| `why` | Explain visible evidence for a path or port |
| `doctor` | Check Zejtron system capability/readiness |
| `proc` | Inspect process trees by user or UID |
| `env` | Snapshot and diff environment variables |
| `service` | Inspect systemd services |

## Compatibility

Zejtron targets Linux systems with procfs mounted at `/proc`. The `path`, `recent`, `port`, `env`, `proc`, `holds`, `touch`, `why`, and `doctor` commands do not require systemd.

`service` requires `systemd` and `systemctl`, and fails cleanly when they are unavailable or unusable. `touch` and `why` can use filesystem metadata on any supported Linux system; audit and journal evidence is best-effort and depends on audit logs or `journalctl`/systemd journal availability. Metadata shows when a path changed, but it is not proof of actor identity.

## Quick Examples

```sh
zejtron path sh
zejtron recent . --limit 10
zejtron port --tcp --group
zejtron holds 3000
zejtron touch ./README.md
zejtron why /etc/resolv.conf
zejtron doctor
zejtron proc --me
zejtron env save base
zejtron env diff base
zejtron service --filter unbound
```

## Commands

### `path`

Trace where a command comes from by scanning `PATH`, showing all matches, the active match, executable status, symlink targets, and Arch package ownership when `pacman` is available.

```sh
zejtron path sh
```

```text
sh
├── active: /usr/bin/sh -> bash
├── executable: yes
├── package: bash
└── duplicates: none
```

### `recent`

Show recently modified files under a path. By default, `recent` scans the current directory, ignores common noisy directories, and returns 20 files.

```sh
zejtron recent
zejtron recent . --limit 5
zejtron recent ~/src --since 1d
```

### `port`

Show listening TCP/UDP ports and process owners when discoverable. `port` reads Linux `/proc` directly and does not require root, though `sudo` may show more owner details on hardened systems.

```sh
zejtron port
zejtron port 3000
zejtron port --tcp --group
zejtron port --udp
zejtron port --all
zejtron port --no-pid
```

By default, `port` shows TCP listening sockets and UDP bound sockets. Use `--all` to include non-listening TCP connections. Use `--group` to collapse repeated rendered socket rows by protocol, local address, port, state, and owner.

### `holds`

Show processes holding a file, device, or specific TCP/UDP port. `holds` is read-only: it does not mutate files, kill processes, or close ports. It is the successor to Zenlixem `whoholds` inside Zejtron.

```sh
zejtron holds 3000
zejtron holds /etc/resolv.conf
zejtron holds /dev/nvme0n1
```

`holds` reads Linux `/proc` directly and does not require root. On hardened systems, `sudo` may reveal more holders.

### `touch`

Inspect last modification evidence for a path. `touch` is read-only: it does not create files, change timestamps, or behave like shell `touch`. It is the successor to Zenlixem `lasttouch` inside Zejtron.

```sh
zejtron touch /etc/resolv.conf
zejtron touch ./README.md
zejtron touch "/path/with spaces/file.txt"
```

When audit or journal evidence is available, `touch` reports best-effort actor and process evidence. Otherwise it falls back to filesystem metadata, which shows when a path changed but is not proof of who changed it. Audit and journal evidence depend on system configuration and permissions.

### `why`

Explain visible evidence for a path or port. `why` is read-only and is the successor to Zenlixem `whyopen` inside Zejtron.

```sh
zejtron why 53
zejtron why 3000
zejtron why /etc/resolv.conf
zejtron why ./README.md
```

`why` uses best-effort evidence from procfs, socket ownership, and path metadata, audit, or journal evidence. It does not infer intent, and `sudo` may reveal more complete holder explanations on hardened systems. Journal evidence is optional and depends on `journalctl` and the systemd journal.

### `doctor`

Check Zejtron system capability and readiness. `doctor` is read-only, does not require root, and reports optional features as warnings instead of assuming systemd.

```sh
zejtron doctor
```

`doctor` checks Linux/procfs visibility, visible processes, `/proc/net` socket parsing, holder scan readiness, optional audit and journal evidence, systemctl/systemd availability, and build metadata. It is useful on non-systemd Linux because it reports what is available and keeps optional `systemctl` or `journalctl` issues as warnings.

### `proc`

Show a clean process tree for a Linux user or UID. `proc` is the successor to pidnest inside the unified Zejtron toolkit.

```sh
zejtron proc --me
zejtron proc rezky
zejtron proc root --depth 1
zejtron proc rezky --find python
zejtron proc rezky --no-pid
zejtron proc rezky --live --interval 6
```

Live mode refreshes the tree in place. `--watch` is an alias for `--live`; refresh intervals must be between 3 and 60 seconds.

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

Snapshots are stored under `$XDG_DATA_HOME/zejtron/env` when `XDG_DATA_HOME` is set, otherwise `~/.local/share/zejtron/env`.

### `service`

Inspect systemd service units in a read-only view. `service` uses `systemctl`, does not require root, and does not provide start, stop, restart, enable, or disable actions.

```sh
zejtron service
zejtron service --user
zejtron service --failed
zejtron service --all
zejtron service --filter unbound
```

By default, `service` shows running system services plus failed services. Use `--user` for running user services, `--failed` for failed services only, and `--all` for all service units, including exited and inactive units.

## Stability

Zejtron v2.4.0 adds `doctor`, bringing selected Zenlixem capability checks into the unified toolkit.

## Development Checks

```sh
./check.sh
SKIP_CODESPELL=1 ./check.sh
```

## Version Updates

```sh
./version-to.sh v2.4.0
```

## Trademark

The source code is licensed under the MIT License. The Zejtron name and branding are not granted under the MIT License. See [TRADEMARK.md](TRADEMARK.md).
