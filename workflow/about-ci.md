# Release Workflow

This project uses GitHub Actions for CI, GitHub Releases, and optional AUR sync for `zejtron-bin`.

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

- `zejtron`
- `README.md`
- `LICENSE`

Example release asset flow for the v2.2.0 touch inspection tag:

```sh
TAG=v2.2.0
cargo build --release --locked --target x86_64-unknown-linux-gnu
```

The release workflow uploads `zejtron-bin-${TAG}-linux-x86_64.tar.gz`, `zejtron-bin-${TAG}-linux-aarch64.tar.gz`, and matching `.sha512` files.

## AUR Sync

The release workflow dispatches AUR sync only for normal semver tags like `v2.2.0`. Its `aur-sync` job only sends a `repository_dispatch` event with `event_type: aur-sync`; the real AUR push happens in the separate `zejtron - AUR Sync` workflow.

AUR sync can also be run manually with a `tag` input such as `v2.2.0` or `2.2.0`. It updates `aur/zejtron-bin/PKGBUILD`, regenerates `.SRCINFO`, commits as `rezky_nightky <rezky2399@proton.me>`, and pushes to `ssh://aur@aur.archlinux.org/zejtron-bin.git`.

Required repository secret:

- `AUR_SSH_PRIVATE_KEY`

Configure it in GitHub at:

`Settings -> Secrets and variables -> Actions -> Repository secrets -> AUR_SSH_PRIVATE_KEY`

The AUR workflow does not set `environment:`, so environment secrets are not used.

## AUR Troubleshooting

If the release workflow `aur-sync` job succeeds quickly, that only means the dispatch request was sent. Open the Actions list and look for a separate run named `zejtron - AUR Sync`.

If `zejtron - AUR Sync` does not trigger, check:

- `.github/workflows/aur.yml` exists on the default branch, currently `main`
- the release workflow dispatches `event_type: aur-sync`
- the AUR workflow listens to `repository_dispatch` with `types: [aur-sync]`

If `zejtron - AUR Sync` triggers but authentication fails, check that `AUR_SSH_PRIVATE_KEY` is configured as a repository secret, not only as an environment secret.

The AUR workflow runs on `ubuntu-latest`, updates `.SRCINFO` directly from the package metadata, pins the AUR Ed25519 host key, and clones the AUR repository before copying package files. If clone fails because of authentication or host-key verification, the job fails clearly. If the AUR repository is empty or not initialized yet, the workflow bootstraps a local repository and pushes `master`.

## Version Bump Flow

```sh
./version-to.sh v2.2.0
./check.sh
```

## Release Command Flow

```sh
./version-to.sh v2.2.0
./check.sh
git add .
git commit -m "chore: prepare v2.2.0 release"
git push origin main
git tag -a v2.2.0 -m "v2.2.0"
git push origin v2.2.0
```
