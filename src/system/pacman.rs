// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Native pacman ownership reader (night-improve-0): the `path`
//! surface no longer shells out to `pacman -Qo` — it reads the
//! package database at `/var/lib/pacman/local/` directly, std-only,
//! no new dependency, one fewer external binary.
//!
//! The database layout is plain text and stable: one directory per
//! installed package (`<name>-<version>-<rel>-<arch>`), containing a
//! `desc` file (keyed sections: `%NAME%`, `%VERSION%`, ...) and a
//! `files` file whose `%FILES%` section lists the package's paths,
//! one per line, relative to `/` and without a leading slash.
//!
//! The query is lazy by design: given one queried file, the reader
//! walks the local directories and stops at the first package whose
//! files list contains the path. No whole-tree index is built — the
//! `path` surface queries one or two paths per invocation, so a
//! full in-memory map would be work the call never asked for.
//!
//! Three-state answer ([`PacmanOwnership`]):
//! - `Absent` — no `/var/lib/pacman` database: not an Arch host. The
//!   caller falls through to the next ownership backend; no error,
//!   no fallback to the pacman binary.
//! - `Owned` — the queried path is listed by exactly one package;
//!   carries the name and version read from the package's `desc`.
//! - `Unowned` — the database exists and answered: the path is in no
//!   package's file list. "Unowned by any package" is the correct
//!   answer on an Arch host, not a lookup failure.
//!
//! Malformed packages (a `desc` without a readable `%NAME%`) are
//! skipped, never fatal: a broken metadata entry must not take down
//! an investigation.

use std::fs;
use std::path::{Path, PathBuf};

/// The default database root; the only filesystem path this reader
/// knows. Tests inject their fixture root through
/// [`pacman_ownership_in`] instead.
pub(crate) const DEFAULT_PACMAN_DB: &str = "/var/lib/pacman";

/// The three-state ownership answer for one queried path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PacmanOwnership {
    /// The path is listed by a package whose `desc` carries a
    /// readable `%NAME%` and `%VERSION%`.
    Owned { name: String, version: String },
    /// The database exists and no package lists the path.
    Unowned,
    /// No pacman database at the root: not an Arch host.
    Absent,
}

/// Ownership of `file` according to the real pacman database at
/// [`DEFAULT_PACMAN_DB`].
pub(crate) fn pacman_ownership(file: &Path) -> PacmanOwnership {
    pacman_ownership_in(Path::new(DEFAULT_PACMAN_DB), file)
}

/// Ownership of `file` according to the database at `root` (the test
/// seam: same walk, injectable root). Deterministic: package
/// directories are visited in sorted order, so a fixture with a
/// malformed package next to a valid one always behaves the same.
pub(crate) fn pacman_ownership_in(root: &Path, file: &Path) -> PacmanOwnership {
    let local = root.join("local");
    if !local.is_dir() {
        return PacmanOwnership::Absent;
    }

    // The files lists store paths relative to `/` without a leading
    // slash ("usr/bin/bash"); the query arrives absolute. Strip the
    // root prefix so both sides compare as plain component lists
    // (Path equality ignores a trailing slash, so directory entries
    // match too).
    let query = file.strip_prefix("/").unwrap_or(file);

    let mut packages: Vec<PathBuf> = match fs::read_dir(&local) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_dir())
            .collect(),
        Err(_) => return PacmanOwnership::Absent,
    };
    packages.sort();

    for package in packages {
        let Ok(files) = fs::read_to_string(package.join("files")) else {
            continue;
        };
        if !files_list_contains(&files, query) {
            continue;
        }
        // The files list answered; the desc decides whether the hit
        // is reportable. A malformed desc skips the package — the
        // walk continues, and an unreported hit degrades to Unowned
        // rather than an error.
        if let Some((name, version)) = parse_desc(&package.join("desc")) {
            return PacmanOwnership::Owned { name, version };
        }
    }

    PacmanOwnership::Unowned
}

/// True when the `%FILES%` section lists `query`. Sections are
/// `%KEY%` lines; the file paths are the non-key lines that follow
/// the `%FILES%` header until the next section.
fn files_list_contains(files: &str, query: &Path) -> bool {
    let mut in_files = false;
    for line in files.lines() {
        if line.starts_with('%') {
            in_files = line.trim() == "%FILES%";
            continue;
        }
        if in_files {
            let entry = line.trim();
            if !entry.is_empty() && Path::new(entry) == query {
                return true;
            }
        }
    }
    false
}

/// The `(name, version)` pair from a package `desc` file, or `None`
/// when either keyed section is missing or unreadable (the malformed
/// shape the caller skips).
fn parse_desc(desc_path: &Path) -> Option<(String, String)> {
    let content = fs::read_to_string(desc_path).ok()?;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut section = String::new();
    for line in content.lines() {
        if let (Some(open), Some(key)) = (line.find('%'), line.rfind('%'))
            && open == 0
            && key == line.len() - 1
            && key >= 2
        {
            section = line[1..key].trim().to_owned();
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        match section.as_str() {
            "NAME" if name.is_none() => name = Some(line.trim().to_owned()),
            "VERSION" if version.is_none() => version = Some(line.trim().to_owned()),
            _ => {}
        }
    }
    Some((name?, version?))
}

#[cfg(test)]
#[path = "../../test/system/pacman_tests.rs"]
mod tests;
