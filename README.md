# nestkit

A small Linux terminal toolkit for tracing paths, ports, env, recent files, and services.

## Install From Source

```sh
git clone https://github.com/oxyzenQ/nestkit
cd nestkit
cargo install --path .
```

## Usage

```sh
nestkit --version
nestkit path python
nestkit recent .
nestkit recent . --limit 10
nestkit recent . --since 2h
```

## Commands

### `path`

Trace where a command comes from by scanning `PATH`, showing all matches, the active match, executable status, symlink targets, and Arch package ownership when `pacman` is available.

```sh
nestkit path sh
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
nestkit recent
nestkit recent . --limit 5
nestkit recent ~/src --since 1d
```

## Roadmap

- `port`
- `env`
- `service`
