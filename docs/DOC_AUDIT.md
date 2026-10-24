<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Documentation Depth Audit

The master depth audit for the docs estate: one ruleset every
document in the tree is measured against, wherever it lives and
whatever audience it serves. "Master" is the point - a single law
for the whole estate, not a per-doc bar each writer reinvents. The
audit exists because a doc's failure mode is rarely missing words;
it is words in the wrong shape: a conclusion with no mechanism
under it, or a fact told twice so one copy can go stale while the
other stays true. The drift that commissioned this audit was
exactly that - the runtime dependency count, restated across the
estate, went stale the day `libc` joined the graph in
night-dragon-6 while the graph itself was telling the truth.

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

## Scope and exemptions

The audit walks every tracked `*.md` in the tree - the repository
root and the `docs/` tree alike, the crates.io tarball set (the
top-level `*.md` files, the lean-half rule) and the repo-only
subdirectories. The tarball set is the highest-stakes half: it is
the face every source consumer reads.

Two exemptions, both structural:

- `docs/archive/` - the frozen changelog eras, never rewritten;
  exempt for exactly that reason (the header gate exempts the
  archive on the same terms).
- `CHANGELOG.md` - a frozen historical record; the audit reads it
  for precedent, never for corrections.

Source code is the single source of truth, and every doc yields to
it: when a doc disagrees with `src/**`, the doc is wrong, and the
audit's fix edits the doc - never the source to match the doc.

## The rules

1. **Tell once - one home per fact, no duplicates.** Every
   doc-owned fact has exactly one home: the single document that
   owns telling it, named by the registry ([README.md](README.md)'s
   ownership tables). Every other doc that needs the fact links to
   the home and does not restate it. The worst duplicates are the
   volatile facts - counts, versions, sizes, dates, paths that
   move - because a restated number drifts the moment its source
   moves, and nothing fails loudly when it does. When the audit
   finds a second telling, the fix is a link to the home, never a
   re-sync of both copies: a re-sync is just the next drift waiting
   for its day. This is the law the code already speaks - the
   unavailability sentence carries exactly one source in the
   evidence renderer and every surface delegates down to it. Perfect
   sync stops being a burden the moment a fact is only ever edited
   in one place.

2. **Depth is the bar.** A doc's sections carry the mechanism and
   the why, not only the what: what a thing is, how it works, why
   this shape and not the alternatives, and where the truth lives in
   source. A heading followed by a bare conclusion fails; a rule
   list with no reasoning behind it fails; a playbook that shows
   commands without how to read the output fails. Brevity is not
   the sin - a short section that carries its mechanism passes, and
   a long one that only restates conclusions does not. The bar is
   the density of explanation, not the word count.

3. **The registry is the estate.** [README.md](README.md)'s
   ownership tables are the complete map of what exists and what
   each doc owns. A doc not in the registry either gets a row or
   does not belong in the tree; a row with no doc behind it is
   deleted. A fact that fits no owner's charter is either a new
   owner (a new row, decided like any other change) or it does not
   get told - free-floating facts are how orphans and duplicates
   are born.

4. **Same-pass sync.** A change that moves a fact lands in the
   fact's home doc in the same commit - the dependency ledger's law
   generalized (a new dependency lands with its first live call
   site AND its row, one commit, no lag). A pass that changes
   behavior and leaves the home doc for a later docs pass has split
   the truth from its telling; later never comes, and the audit
   inherits a finding.

5. **Findings land as their own commits.** The audit's output is
   not a report nobody reads - it is fixes. Each finding lands as
   its own internal-research commit: the finding named in the
   message, the rule it violated cited in the body, the fix in the
   diff. A finding the owner defers is a decision, not a
   disappearance - it is named somewhere durable with its reason,
   never silently dropped.

## How the audit runs

The audit is a discipline, not a gate script: the rules bind at
review time, the way the unavailability dedup and the dependency
ledger already do. A docs-touching pass runs it against the touched
doc and its neighbors - every rule, every time. A docs series opens
with a full walk: the registry top to bottom, every doc against
every rule, findings landed per rule 5. Green means: every fact has
one home, every section carries its mechanism, the registry and the
tree agree, and no commit in the series moved a fact without its
home doc. The name continues the lineage - the infra depth audit
(night-total-lts-2) and the suite's depth audit (night-improve-43) -
pointed this time at the whole docs estate.
