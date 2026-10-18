// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! pacman parser unit pins (night-improve-0). Lives under the single
//! test/ tree (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/system/pacman.rs, so `super::` reaches the module exactly like
//! the inline tests did. The fixtures are a real pacman local-db
//! shape under test/fixtures/pacman/: one valid package (bash, with
//! file entries and directory entries) and one malformed package
//! (a desc missing %NAME%, still carrying a files list) to prove the
//! skip-not-crash contract.

use super::*;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test/fixtures/pacman")
}

#[test]
fn hit_names_the_owning_package_with_its_version() {
    let owned = pacman_ownership_in(&fixture_root(), Path::new("/usr/bin/bash"));
    assert_eq!(
        owned,
        PacmanOwnership::Owned {
            name: "bash".to_owned(),
            version: "5.2.37-1".to_owned()
        }
    );
}

#[test]
fn symlink_and_directory_entries_match_the_same_way() {
    // usr/bin/sh is listed directly (the symlink entry a package
    // ships), and the directory entries carry a trailing slash in
    // the files list - Path equality must make both reachable.
    assert_eq!(
        pacman_ownership_in(&fixture_root(), Path::new("/usr/bin/sh")),
        PacmanOwnership::Owned {
            name: "bash".to_owned(),
            version: "5.2.37-1".to_owned()
        }
    );
    assert_eq!(
        pacman_ownership_in(&fixture_root(), Path::new("/usr/bin")),
        PacmanOwnership::Owned {
            name: "bash".to_owned(),
            version: "5.2.37-1".to_owned()
        }
    );
}

#[test]
fn miss_says_unowned_when_the_database_answered() {
    // The database exists; the path is in no package's files list.
    assert_eq!(
        pacman_ownership_in(&fixture_root(), Path::new("/opt/nothing/here")),
        PacmanOwnership::Unowned
    );
}

#[test]
fn absent_when_no_pacman_database_exists() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test/fixtures/no-such-db");
    assert_eq!(
        pacman_ownership_in(&missing, Path::new("/usr/bin/bash")),
        PacmanOwnership::Absent
    );
}

#[test]
fn malformed_desc_skips_the_package_without_crashing() {
    // broken-1.0-1 lists usr/bin/broken-tool in its files list but
    // its desc carries no %NAME% - the package is skipped, the walk
    // continues, and the queried path degrades to Unowned instead of
    // erroring or reporting an unreadable package.
    assert_eq!(
        pacman_ownership_in(&fixture_root(), Path::new("/usr/bin/broken-tool")),
        PacmanOwnership::Unowned
    );
    // And the valid package beside it is still found: the skip is
    // scoped to the malformed entry, not the whole database.
    assert!(matches!(
        pacman_ownership_in(&fixture_root(), Path::new("/usr/bin/bash")),
        PacmanOwnership::Owned { .. }
    ));
}

#[test]
fn parse_desc_reads_the_keyed_sections() {
    let desc = fixture_root()
        .join("local")
        .join("bash-5.2.37-1")
        .join("desc");
    assert_eq!(
        parse_desc(&desc),
        Some(("bash".to_owned(), "5.2.37-1".to_owned()))
    );
    let missing = fixture_root().join("local").join("no-such-package");
    assert_eq!(parse_desc(&missing), None);
}
