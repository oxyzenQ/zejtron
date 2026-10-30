#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zejtron is a Linux-only tool.
#
# ZYLAXION NAME-CASE CHECK (night-improve-20)
# ZEJTRON NAME-CASE CHECK (night-improve-1.5)
#
"""Check the lowercase family-name rule (docs/BRANDING.md section 7).

Both family names — the sibling `zylaxion` and this project's own
`zejtron` — are lowercase in every context they appear in this
repository: prose, titles, headings, code, CLI output, comments,
commit subjects, and file paths — the nginx/curl convention the
owner mandated for the sibling (night-improve-20) and extended to
the project's own name (night-improve-1.5). Until that extension
this gate checked only the sibling name, so a capitalized or
all-caps form of the project's own name passed unnoticed — a gate
gap that would have shipped to the first publish. This gate scans
EVERY tracked file and EVERY tracked path (git ls-files: the .cargo/
and .github/ hidden trees included — nothing excluded) and fails on
any casing outside the two legal families BRANDING section 7
codifies, for either name:

  1. lowercase — the name itself, always;
  2. the identifier family — the all-caps form attached with `_` or
     `-` (an environment-variable prefix such as `ZYLAXION_MODE` or
     `ZEJTRON_BIN_PATH`, a marker such as `ZEJTRON-DISCLAIMER`),
     plus the all-caps banner comment titles heading the scripts/
     gate files (a comment line opening with the all-caps name).

Every other casing — a capitalized first letter, internal capitals,
or all-caps prose — fails with file:line:token. A stray capitalized
or internally-capitalized form of either name in any file is a gate
failure, per the owner's strict reading: a family name never rides
a capital in this repo (this docstring spells no forbidden literal
— the checker must stay self-clean, flagging nothing of its own).

The checker is self-clean by construction: every all-caps form is
built at runtime from the lowercase name, so this file carries no
literal it would flag itself on (the banner comments above are the
one legal all-caps occurrences per name, legal by the banner rule
they document).
"""

from __future__ import annotations

# Bytecode guard (night-dragon-maintenance-T1, the zelynic root-owned
# __pycache__ class): this entry point may run under sudo, and CPython
# writes __pycache__/*.pyc beside every imported module with the
# invoking user's ownership - root-owned caches that later block a
# normal non-root teardown with Permission denied. No repo-local
# bytecode is written at any privilege level; a future repo-local
# import MUST sit below this guard, never above it.
import sys

sys.dont_write_bytecode = True

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("zylaxion", "zejtron")
UPPERS = {name: name.upper() for name in NAMES}
BANNER_RES = {
    name: re.compile(r"^\s*#\s*" + name.upper() + r"(\s|$)") for name in NAMES
}
IDENTIFIER_CHARS = ("_", "-")
BANNER_SUFFIXES = {".sh", ".py"}
MAX_REPORTED = 50


def tracked_paths() -> list[str]:
    """Every path in the index — nothing excluded."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        print("name-case check: FAIL")
        print(f"git ls-files failed (exit {exc.returncode}) — run from a repo checkout")
        raise SystemExit(1) from exc
    return sorted(p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p)


def banner_title(name: str, path: str, line: str) -> bool:
    """True when the line is a banner title heading a scripts/ gate file."""
    if not path.startswith("scripts/"):
        return False
    if Path(path).suffix not in BANNER_SUFFIXES:
        return False
    return BANNER_RES[name].match(line) is not None


def violation_reason(
    name: str, upper: str, path: str, line: str, token: str, prev: str, nxt: str
) -> str | None:
    """None when the occurrence is legal, else the failure reason."""
    if token == name:
        return None
    if token == upper:
        if nxt in IDENTIFIER_CHARS or prev in IDENTIFIER_CHARS:
            return None
        if banner_title(name, path, line):
            return None
        return "all-caps outside the identifier family (docs/BRANDING.md section 7)"
    return "the name is lowercase in every context (docs/BRANDING.md section 7)"


def check_path(path: str, failures: list[str]) -> None:
    """Path tokens: the lowercase name, never a capitalized ride."""
    for name in NAMES:
        lowered = path.lower()
        pos = lowered.find(name)
        while pos != -1:
            end = pos + len(name)
            if path[pos:end] != name:
                bad = path[pos:end]
                failures.append(
                    f"FAIL PATH   {path} '{bad}' — path tokens must be lowercase"
                )
            pos = lowered.find(name, end)


def check_line(
    path: str, lineno: int, line: str, failures: list[str], stats: dict[str, int]
) -> None:
    """Content tokens: lowercase, identifier family, or banner — else fail."""
    for name in NAMES:
        upper = UPPERS[name]
        lowered = line.lower()
        pos = lowered.find(name)
        while pos != -1:
            end = pos + len(name)
            token = line[pos:end]
            prev = line[pos - 1] if pos > 0 else ""
            nxt = line[end] if end < len(line) else ""
            stats["tokens"] += 1
            reason = violation_reason(name, upper, path, line, token, prev, nxt)
            if reason is None:
                if token == name:
                    stats["lowercase"] += 1
                else:
                    stats["family"] += 1
            else:
                failures.append(f"FAIL CASE   {path}:{lineno} '{token}' — {reason}")
            pos = lowered.find(name, end)


def main() -> int:
    failures: list[str] = []
    files = 0
    stats = {"tokens": 0, "lowercase": 0, "family": 0}

    for path in tracked_paths():
        files += 1
        check_path(path, failures)

        target = ROOT / path
        if not target.is_file():
            continue
        try:
            text = target.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            check_line(path, lineno, line, failures, stats)

    print(
        "name-case check (zylaxion, zejtron): " + ("FAIL" if failures else "PASS")
    )
    for failure in failures[:MAX_REPORTED]:
        print(failure)
    if len(failures) > MAX_REPORTED:
        print(f"... and {len(failures) - MAX_REPORTED} more violation(s) not listed")
    print(
        f"Checked {files} tracked file(s) and path(s), {stats['tokens']} name "
        f"token(s): {stats['lowercase']} lowercase, {stats['family']} "
        f"identifier/banner family, {len(failures)} violation(s)."
    )
    if failures:
        print("The rule (docs/BRANDING.md section 7): both family names — zylaxion")
        print("and zejtron — are lowercase in every context; the all-caps identifier")
        print("family (attached with '_' or '-') and the scripts/ banner titles are")
        print("the only uppercase survivors.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
