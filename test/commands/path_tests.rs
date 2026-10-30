// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! path unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/path.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use crate::test_tempdir::TempDir;
use std::fs::File;
use std::os::unix::fs::symlink;

fn make_executable(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn finds_all_path_matches_in_order() {
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    let first_cmd = first.path().join("tool");
    let second_cmd = second.path().join("tool");
    File::create(&first_cmd).unwrap();
    File::create(&second_cmd).unwrap();
    make_executable(&first_cmd);
    make_executable(&second_cmd);

    let path_env = env::join_paths([first.path(), second.path()]).unwrap();
    let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].path, first_cmd);
    assert_eq!(matches[1].path, second_cmd);
    assert!(matches.iter().all(|path_match| path_match.executable));
}

#[test]
fn duplicate_path_directories_do_not_create_duplicate_matches() {
    let directory = TempDir::new().unwrap();
    let command = directory.path().join("tool");
    File::create(&command).unwrap();
    make_executable(&command);

    let path_env = env::join_paths([directory.path(), directory.path()]).unwrap();
    let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].path, command);
}

#[test]
fn equivalent_path_directories_keep_first_display_path() {
    let root = TempDir::new().unwrap();
    let real_directory = root.path().join("real");
    let linked_directory = root.path().join("linked");
    fs::create_dir(&real_directory).unwrap();
    symlink(&real_directory, &linked_directory).unwrap();

    let command = real_directory.join("tool");
    File::create(&command).unwrap();
    make_executable(&command);

    let path_env = env::join_paths([&linked_directory, &real_directory]).unwrap();
    let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].path, linked_directory.join("tool"));
}

#[test]
fn report_uses_duplicates_none_for_single_match() {
    let matches = vec![PathMatch {
        path: PathBuf::from("/usr/bin/tool"),
        executable: true,
        symlink_chain: Vec::new(),
    }];

    assert_eq!(
        format_path_report_with("tool", &matches, &|_| None),
        "tool\n├── active: /usr/bin/tool\n├── executable: yes\n├── package: unknown\n└── duplicates: none"
    );
}

#[test]
fn report_lists_only_non_active_duplicates() {
    let matches = vec![
        PathMatch {
            path: PathBuf::from("/usr/bin/tool"),
            executable: true,
            symlink_chain: Vec::new(),
        },
        PathMatch {
            path: PathBuf::from("/home/rezky/.local/bin/tool"),
            executable: true,
            symlink_chain: Vec::new(),
        },
    ];

    assert_eq!(
        format_path_report_with("tool", &matches, &|_| None),
        "tool\n├── active: /usr/bin/tool\n├── executable: yes\n├── package: unknown\n└── duplicates:\n    └── /home/rezky/.local/bin/tool\n       ├── executable: yes\n       └── package: unknown"
    );
}

#[test]
fn resolves_symlink_chain() {
    let directory = TempDir::new().unwrap();
    let target = directory.path().join("tool-real");
    let link = directory.path().join("tool");
    File::create(&target).unwrap();
    make_executable(&target);
    symlink("tool-real", &link).unwrap();

    let path_env = env::join_paths([directory.path()]).unwrap();
    let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].symlink_chain, vec![PathBuf::from("tool-real")]);
    assert!(matches[0].executable);
}

// The JSON lane (night-badass-9): the same resolution, typed.

#[test]
fn json_resolution_carries_the_active_match_and_duplicates() {
    let matches = vec![
        PathMatch {
            path: PathBuf::from("/usr/bin/sh"),
            executable: true,
            symlink_chain: vec![PathBuf::from("/usr/bin/bash")],
        },
        PathMatch {
            path: PathBuf::from("/home/rezky/.local/bin/sh"),
            executable: false,
            symlink_chain: Vec::new(),
        },
    ];
    let out = super::path_json("sh", &matches, &|_| Some("bash (pacman)".to_owned()));
    // The active match first, the duplicates after, the queried
    // command pinned as the subject.
    assert!(out.starts_with("{\"command\":\"sh\""));
    assert!(out.contains("\"found\":true"));
    assert!(out.contains("\"active\":{\"path\":\"/usr/bin/sh\""));
    assert!(out.contains("\"executable\":true"));
    assert!(out.contains("\"symlink_chain\":[\"/usr/bin/bash\"]"));
    assert!(out.contains("\"package\":\"bash (pacman)\""));
    assert!(out.contains("\"duplicates\":[{\"path\":\"/home/rezky/.local/bin/sh\""));
    assert!(out.contains("\"executable\":false"));
    assert!(out.contains("\"symlink_chain\":[]"));
    assert!(!out.contains('\n'));
}

#[test]
fn json_resolution_not_found_is_typed_absence() {
    let out = super::path_json("nope", &[], &|_| None);
    // The same verdict the text's "command not found in PATH" line
    // renders: found false, no active match, no duplicates.
    assert_eq!(
        out,
        "{\"command\":\"nope\",\"found\":false,\"active\":null,\"duplicates\":[]}"
    );
}

#[test]
fn json_package_absence_is_null_not_the_unknown_word() {
    let matches = vec![PathMatch {
        path: PathBuf::from("/usr/bin/tool"),
        executable: true,
        symlink_chain: Vec::new(),
    }];
    let out = super::path_json("tool", &matches, &|_| None);
    // The text's "unknown" is a display verdict; the JSON wire
    // carries the typed absence.
    assert!(out.contains("\"package\":null"));
}
