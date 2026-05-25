# Release Workflow

This project uses GitHub Actions for CI, GitHub Releases, and optional AUR sync for `nestkit-bin`.

## CI

CI runs on pushes and pull requests targeting `main`.

It installs Rust 1.85.0 with `rustfmt` and `clippy`, installs `codespell`, restores the Rust cache, and runs:

```sh
./check.sh
```

## Release

Release builds run for tags matching `v*`. The workflow builds:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

Release archives use a flat layout:

- `nestkit`
- `README.md`
- `LICENSE`

Example release asset flow:

```sh
TAG=v0.1.0
cargo build --release --locked --target x86_64-unknown-linux-gnu
```

The release workflow uploads `nestkit-bin-${TAG}-linux-x86_64.tar.gz`, `nestkit-bin-${TAG}-linux-aarch64.tar.gz`, and matching `.sha512` files.

## AUR Sync

The release workflow dispatches AUR sync only for normal semver tags like `v0.1.0`.

AUR sync can also be run manually with a `tag` input such as `v0.1.0` or `0.1.0`. It updates `aur/nestkit-bin/PKGBUILD`, regenerates `.SRCINFO`, commits as `rezky_nightky <rezky2399@proton.me>`, and pushes to `ssh://aur@aur.archlinux.org/nestkit-bin.git`.

Required secret:

- `AUR_SSH_PRIVATE_KEY`

## Version Bump Flow

```sh
./version-to.sh v0.1.0
./check.sh
```

## Release Command Flow

```sh
./version-to.sh v0.1.0
./check.sh
git add .
git commit -m "chore: prepare v0.1.0 release"
git push origin main
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```
