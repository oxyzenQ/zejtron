# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial

# AXP1-ZnQ (Architect's eXecution Protocol 1)

The maintenance bot's one protocol: no CI lane marries a hardcoded
server again. The owner named the bottleneck from the field record -
hardcoded addresses age badly (timeout, unable to connect, not found),
and every repair was a human editing a workflow under outage pressure.
The answer is a tested address pool the bot curates, not a hardcoded
default the tree prays for.

Identity: **AXP1-ZnQ** stands for **Architect's eXecution Protocol 1**
- the expansion rides the first mention of the name in every file that
carries it, by the owner's standing law (the name was adopted by
night-solid-defense-1 as the Sunday supply-chain sentinel's signature;
night-learning-into-darkness-1 adds the protocol's second half, the
address catalog and its failover). The sentinel voice stays: the
scanner banners, the verdict step and the maintenance lane still sign
as AXP1-ZnQ. This document is the protocol's front door.

## The catalog (repos-for-ci/*.txt)

`repos-for-ci/` at the repo root holds one `.txt` per address family
(`apt-mirrors.txt` ships today). The law of every catalog file:

- one candidate address per line, the whole trimmed line IS the
  address (no trailing comments - a comment occupies its own line,
  starting with `#`);
- `https://archive.ubuntu.com/ubuntu` - an HTTP(S) address, probed
  with a real GET, TLS verified with the runner's own CA store (a
  cert failure is DOWN, never ignored);
- `dns.example.com:53` - a host:port address, probed with a socket
  connect (the DNS-resolver catalog rides this kind when its lane
  adopts the resolver);
- the authored order is the owner's trust ranking - canonical
  archive first, the runner-native azure mirror second, kernel.org's
  edge mirror third, then the wide mirrors. It is never a latency
  leaderboard; see the write law;
- bounded: 10 to 100 active lines per file, the owner's min and max;
- the shipped seed was probe-verified (12 of 19 candidates answered
  HTTP 200 with a same-day InRelease on `dists/noble/InRelease` at
  authoring time, 2026-11-27; the 6 candidates still DOWN on the
  patient re-test were excluded, not guessed alive;
  `security.ubuntu.com` is excluded on purpose - it serves the
  security pocket, not the whole archive, and every apt consumer here
  installs from the full pool).

## The two commands

Both live in `scripts/ci/`, stdlib-only Python (urllib, socket,
concurrent.futures - no third-party dependency joins the maintenance
surface, the LTS law), and share one probe core
(`scripts/ci/axp1znq_probe.py`) so a mirror the resolver picks and a
mirror the refresher keeps are measured the same way.

**The resolver - `axp1znq_resolve.py`** - is the failover half, the
consumer CI lanes call:

```
python3 scripts/ci/axp1znq_resolve.py \
  --file repos-for-ci/apt-mirrors.txt \
  --probe-path dists/noble/InRelease \
  --first
```

It walks the catalog top to bottom, probes each address, narrates
every verdict to stderr (line number, reason, milliseconds - the CI
log keeps the audit trail), prints the first ALIVE address to stdout
and exits 0. Line 1 down, the lane moves on; line 5 answering is the
one the lane uses - the owner's scenario, verbatim, and the shape the
pre-ship verification ran against a live catalog. A catalog with no
live address is exit 1: a lane must never silently fall back to a
dead default. Freshness is reported in the narration but never blocks
the pick - a minutes-old index still serves the lane; curation is the
refresher's job. Report mode (no `--first`) prints the whole table or
`--json` for machines.

**The refresher - `axp1znq_refresh.py`** - is the catalog half, the
Sunday pass the maintenance lane runs:

```
python3 scripts/ci/axp1znq_refresh.py \
  --root repos-for-ci \
  --probe-path dists/noble/InRelease \
  --note-file "${RUNNER_TEMP}/axp1-address-note.txt"
```

It probes every catalog concurrently, keeps an address only when it
answers AND serves a fresh index (the InRelease file's own `Date:`
header is the freshness witness; older than `--max-age-days`, default
14, is STALE - the owner asked for repos that are updated AND connect
stably, and alive-but-frozen is a lie the catalog must not keep), and
writes the survivors back. The write law:

- survivors keep their authored order - the catalog's shape is the
  owner's trust ranking, never a weekly reshuffle a noisy runner
  would churn;
- a dead or stale address becomes a dated tombstone in place
  (`# down 2026-11-27 (unreachable ...) - https://...`), readable
  history the owner can revive by deleting one line;
- the 100-line cap prunes the OLDEST tombstones first; an active
  address is never pruned;
- the never-empty guard: zero live addresses means the file is NOT
  rewritten (a flaky runner probe must never erase the owner's pool)
  - the lane warns (`::warning::` in CI) and the note names CALL THE
  OWNER, the one critical the refresher escalates;
- idempotent: unchanged catalog, unchanged file - no write, no
  commit-note, no churn;
- `--dry-run` reports the verdicts and writes nothing.

## The wiring (the Sunday cadence)

The maintenance lane (`zejtron - Dependency Maintenance`, cron
`0 3 * * 0` - Sunday 03:00 UTC = 10:00 WIB) is a two-job shape: the
validate job runs the refresher as the step right after `Refresh
Cargo dependencies` - the owner's sequencing law, deps first, the
catalog re-probe second - gated on `scan_only != true` like every
ship step. The validated lane artifact carries the catalog beside the
lockfiles and the prebuilt lane; a second artifact carries the
refresher's commit note. The commit job restores both (rsync
`--delete`, so a tombstoned address cannot linger), stages
`repos-for-ci` by explicit path (the staging-wall law, never a glob),
and appends the note to the one weekly commit body - deps AND
addresses in one commit, the note naming which catalog lines moved
and why. The refresher never blocks the ship lane: it exits 0 with
warnings recorded; the red stays the verdict step's (AXP1-ZnQ -
Architect's eXecution Protocol 1 - and its own exit-1 law).

The first wired consumer is the kernel-floor lane's apt fallback: its
repoint target is no longer a hardcoded hostname - the resolver hands
the lane the first catalog address that actually answers on the noble
InRelease path, and a catalog with nothing alive fails the lane loud.
The other lanes adopt incrementally (the netrunner DNS guard and the
container lane's apt are candidates; a lane adopts by swapping its
hardcoded address for a resolver call - no new machinery needed, that
is the point of the pool).

## The honest edges

- Probe verdicts are network-relative: the authoring sandbox verified
  12 of the 12 shipped lines at least once (11 answered on the fast
  pass; `mirror.rackspace.com` needed the patient re-test - slow, not
  dead, and parked last in the authored order). A mirror that only
  answers some hours is exactly what the weekly curation exists to
  judge; a Sunday run on real runners tombstones it when it stops
  answering.
- The fresh-index probe path is `dists/noble/InRelease` - the noble
  LTS the runner fleet runs. When the fleet moves to the next LTS,
  the probe path moves with it (one flag, both commands).
- `--first` worst case on a dead-first catalog is bounded by
  attempts x timeout per address (both are flags); on a runner the
  connect timeout is what bites, on proxied networks the total
  timeout.

<!-- ZEJTRON-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
