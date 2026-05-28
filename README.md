# zejtron

![CI](https://github.com/oxyzenQ/zejtron/actions/workflows/ci.yml/badge.svg)

A small Linux terminal toolkit for tracing paths, ports, env, recent files, and services.

## Install From Source

```sh
git clone https://github.com/oxyzenQ/zejtron
cd zejtron
cargo install --path .
```

## Install From GitHub Release

```sh
TAG=v0.4.0
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-x86_64.tar.gz"
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-x86_64.tar.gz.sha512"
sha512sum --check "zejtron-bin-${TAG}-linux-x86_64.tar.gz.sha512"
tar -xzf "zejtron-bin-${TAG}-linux-x86_64.tar.gz"
sudo install -Dm755 zejtron /usr/local/bin/zejtron
```

For aarch64 Linux, use `zejtron-bin-${TAG}-linux-aarch64.tar.gz`.

## Install From AUR

```sh
yay -S zejtron-bin
paru -S zejtron-bin
```

## Usage

```sh
zejtron --version
zejtron env
zejtron env diff base
zejtron path python
zejtron port
zejtron port 3000
zejtron service
zejtron service --failed
zejtron recent .
zejtron recent . --limit 10
zejtron recent . --since 2h
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

When multiple unique matches exist, `path` keeps the active command separate and lists only the other locations under `duplicates`.

### `port`

Show listening TCP/UDP ports and process owners when discoverable. `port` reads Linux `/proc` directly and does not require root, though `sudo` may show more owner details on hardened systems.

```sh
zejtron port
zejtron port 3000
zejtron port --tcp
zejtron port --tcp --group
zejtron port --udp
zejtron port --all
zejtron port --group
zejtron port --no-pid
```

By default, `port` shows TCP listening sockets and UDP bound sockets. Use `--all` to include non-listening TCP connections. Use `--group` to collapse repeated rendered socket rows by protocol, local address, port, state, and owner. Raw summaries count rendered sockets and unique known owner processes; grouped summaries use `groups · sockets · owners`. Unknown owners are not counted. `--numeric` is accepted for numeric output; output is already numeric.

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

Inspect systemd service units in a read-only view. `service` uses `systemctl`, does not require root, and does not provide start, stop, restart, enable, or disable actions in v0.4.0.

```sh
zejtron service
zejtron service --user
zejtron service --failed
zejtron service --all
zejtron service --filter unbound
```

By default, `service` shows running system services plus failed services. Use `--user` for running user services, `--failed` for failed services only, and `--all` for all service units, including exited and inactive units.

### `recent`

Show recently modified files under a path. By default, `recent` scans the current directory, ignores common noisy directories, and returns 20 files.

```sh
zejtron recent
zejtron recent . --limit 5
zejtron recent ~/src --since 1d
```

## Development Checks

```sh
./check.sh
SKIP_CODESPELL=1 ./check.sh
```

## Trademark

The source code is licensed under the MIT License. The Zejtron name and branding are not granted under the MIT License. See [TRADEMARK.md](TRADEMARK.md).

## Version Updates

```sh
./version-to.sh v0.4.0
```

## Roadmap

- JSON output
