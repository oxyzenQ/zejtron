// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! path unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/path.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use std::fs::File;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

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
        format_path_report("tool", &matches),
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
        format_path_report("tool", &matches),
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
