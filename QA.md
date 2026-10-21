<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron Q&A Record

The claims-discipline companion: the questions a serious reader asks,
answered once, with the source of truth named for every claim. The
sibling project's QA.md owns the format; the answers here are
zejtron-honest - no borrowed feature claims.

<!-- ZEJTRON-DISCLAIMER -->
<!--
  Documentation Disclaimer - read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc - perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`) is the single source of truth. Always
  cross-check against the actual source files before relying on any
  specific number, file path, function name, or config key.

  If you find a discrepancy, please open a PR - the doc is wrong, not
  the source.
-->

## Q1 - What exactly is zejtron?

A unified, read-only Linux introspection toolkit: where a command
comes from (`path`, with package ownership read straight from the
pacman database on Arch), what holds a port or file (`holds`, `port`),
who touched a path (`touch`, `why`), what the process tree looks like
for a user (`proc`), what changed recently (`recent`), the network
context (`net`), and host readiness (`doctor`). One binary, no config
files, no daemons, read-only by design - the claim is literal: zejtron
writes nothing. The tagline is the contract: "Boring and serious."

## Q2 - Is zejtron suitable for a crates.io release?

The manifest carries the full ship set (curated `include`, the
autotests/autobenches/autoexamples axes off, MSRV pinned, categories
validated against the live registry API). The `documentation` field is
withheld until the crate is actually published - the docs.rs link is
verified live before it ships, never pre-claimed. The publish lane
(crates-io.yml) is the CI arm; the owner cuts the actual release.

## Q3 - Why do the commits read "Internal research: ..." instead of
conventional commits (feat:/fix:)?

Because this repository is a research workspace, not a product
backlog: every task is an experiment with a verdict, and the prefix
keeps the history honest about that. The full convention: pure
English, no emoji, one task = one commit (micro-commit-push), and the
`Signed-off-by` trailer pins authorship. Conventional-commit
categories would imply a stability contract the pre-stable versioning
does not carry yet.

## Q4 - Why are the quality standards different from other projects?

The gates are deliberately stricter than the ecosystem default:
tree-wide 600-line cap per `.rs` file (no exemptions, split the same
hour), 1000-line cap per script, SPDX headers on every tracked file,
644/755 permission contract, English-only discipline with a live
detector, repo-wide emoji ban, the version-pin sync check, and the
wholesale gate-keepers run on every push and pull request with no
filters at all. The
reason is compounding: every file that lands over the limit makes the
next change harder to review. Maturity is what does not need to be
refactored later.

## Q5 - How is the documentation organized?

The docs tree (see [docs/README.md](README.md) for the index): the
top-level user docs (BRANDING, RULES, VERIFY_RELEASE, ROADMAP,
DEPENDENCY_AUDIT, LICENSING_FAQ), the workflow note
(docs/workflow/about-ci.md), and the frozen archive
(docs/archive/). The tarball ships only docs/*.md (the lean-half
rule): the repo keeps the full tree readable, the published package
does not carry it.

## Q6 - What is the future?

The roadmap lives in [docs/ROADMAP.md](ROADMAP.md) and
[docs/ROADMAP-current.md](ROADMAP-current.md) and is the Owner's call,
like every version number. The standing constraints: read-only stays
read-only, the dependency set stays boring, and no surface ships a
claim its code cannot back.
