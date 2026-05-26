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
TAG=v0.1.0
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
zejtron path python
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

## Version Updates

```sh
./version-to.sh v0.2.0
```

## Roadmap

- `port`
- `env`
- `service`
