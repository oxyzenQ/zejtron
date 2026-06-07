# Release Workflow

This project uses GitHub Actions for CI, GitHub Releases, and optional AUR sync for `zejtron-bin`.

## CI

CI runs on pushes and pull requests targeting `main`.

It installs stable Rust with `rustfmt` and `clippy`, installs `codespell`, restores the Rust cache, and runs:

```sh
./check.sh
```

## Nightbot Maintenance

The `nightbot maintenance` workflow runs every Saturday at 23:00 Asia/Jakarta time and can also be run manually. It checks out the default branch, runs `cargo update`, executes `./check.sh`, and commits the refreshed `Cargo.lock` directly back to the default branch only after validation passes.

Nightbot maintenance commits use:

- `nightbot`
- `nightbot@users.noreply.github.com`

## Release

Release builds run for tags matching `v*`. The workflow builds:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

Release archives use a flat layout:

- `zejtron`
- `README.md`
- `LICENSE`

Example release asset flow for the v2.4.2 maintenance tag:

```sh
TAG=v2.4.4
cargo build --release --locked --target x86_64-unknown-linux-gnu
```

The release workflow uploads `zejtron-bin-${TAG}-linux-x86_64.tar.gz`, `zejtron-bin-${TAG}-linux-aarch64.tar.gz`, and matching `.sha512` files.

## AUR Sync

The release workflow dispatches AUR sync only for normal semver tags like `v2.4.1`. Its `aur-sync` job only sends a `repository_dispatch` event with `event_type: aur-sync`; the real AUR push happens in the separate `zejtron - AUR Sync` workflow. Release-triggered sync checks out the release tag and copies the committed AUR metadata from that tag.

AUR sync can also be run manually. Manual sync checks out `main`, validates that `aur/zejtron-bin/PKGBUILD` and `aur/zejtron-bin/.SRCINFO` have matching `pkgver` and `pkgdesc` values, copies both files as committed, commits as `rezky_nightky <rezky2399@proton.me>`, and pushes to `ssh://aur@aur.archlinux.org/zejtron-bin.git`. Release-triggered sync also verifies that the release tag version matches the committed AUR `pkgver`.

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

The AUR workflow runs on `ubuntu-latest`, validates committed package metadata, pins the AUR Ed25519 host key, and clones the AUR repository before copying both `PKGBUILD` and `.SRCINFO`. If clone fails because of authentication or host-key verification, the job fails clearly. If the AUR repository is empty or not initialized yet, the workflow bootstraps a local repository and pushes `master`.

## Version Bump Flow

```sh
./version-to.sh v2.4.4
./check.sh
```

## Release Command Flow

```sh
./version-to.sh v2.4.4
./check.sh
git add .
git commit -m "chore: prepare v2.4.4 release"
git push origin main
git tag -a v2.4.4 -m "optimize build for release"
git push origin v2.4.4
```
