// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_DISPLAYED_SYMLINKS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatch {
    pub path: PathBuf,
    pub executable: bool,
    pub symlink_chain: Vec<PathBuf>,
}

pub fn run(command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let matches = find_in_path(command, env::var_os("PATH").as_deref())?;

    if matches.is_empty() {
        println!("command not found in PATH: {command}");
        return Ok(());
    }

    let report = format_path_report(command, &matches, pacman_available().as_deref());
    println!("{report}");

    Ok(())
}

pub fn format_path_report(command: &str, matches: &[PathMatch], pacman: Option<&Path>) -> String {
    let Some((active, duplicates)) = matches.split_first() else {
        return format!("command not found in PATH: {command}");
    };

    let mut lines = vec![command.to_owned()];

    lines.push(format!("├── active: {}", display_match_path(active)));
    lines.push(format!("├── executable: {}", yes_no(active.executable)));
    lines.push(format!(
        "├── package: {}",
        package_owner(&active.path, pacman).unwrap_or_else(|| "unknown".to_owned())
    ));

    if duplicates.is_empty() {
        lines.push("└── duplicates: none".to_owned());
        return lines.join("\n");
    }

    lines.push("└── duplicates:".to_owned());
    for (index, path_match) in duplicates.iter().enumerate() {
        let prefix = if index + 1 == duplicates.len() {
            "    └──"
        } else {
            "    ├──"
        };
        let detail_prefix = if index + 1 == duplicates.len() {
            "       "
        } else {
            "    │  "
        };

        lines.push(format!("{prefix} {}", display_match_path(path_match)));
        lines.push(format!(
            "{detail_prefix}├── executable: {}",
            yes_no(path_match.executable)
        ));
        lines.push(format!(
            "{detail_prefix}└── package: {}",
            package_owner(&path_match.path, pacman).unwrap_or_else(|| "unknown".to_owned())
        ));
    }

    lines.join("\n")
}

pub fn find_in_path(command: &str, path_env: Option<&OsStr>) -> io::Result<Vec<PathMatch>> {
    let Some(path_env) = path_env else {
        return Ok(Vec::new());
    };

    let mut matches = Vec::new();
    let mut seen = HashSet::new();
    for directory in env::split_paths(path_env) {
        if directory.as_os_str().is_empty() {
            continue;
        }

        let candidate = directory.join(command);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
                let key = dedup_key(&candidate);
                if !seen.insert(key) {
                    continue;
                }

                matches.push(PathMatch {
                    executable: fs::metadata(&candidate)
                        .map(|metadata| metadata.is_file() && is_executable(&metadata))
                        .unwrap_or(false),
                    symlink_chain: resolve_symlink_chain(&candidate),
                    path: candidate,
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    Ok(matches)
}

fn dedup_key(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

fn resolve_symlink_chain(path: &Path) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut current = path.to_path_buf();

    for _ in 0..16 {
        let Ok(target) = fs::read_link(&current) else {
            break;
        };

        chain.push(target.clone());
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .map(|parent| parent.join(&target))
                .unwrap_or(target)
        };
    }

    chain
}

fn display_match_path(path_match: &PathMatch) -> String {
    let mut value = path_match.path.display().to_string();
    for target in path_match.symlink_chain.iter().take(MAX_DISPLAYED_SYMLINKS) {
        value.push_str(" -> ");
        value.push_str(&target.display().to_string());
    }
    if path_match.symlink_chain.len() > MAX_DISPLAYED_SYMLINKS {
        value.push_str(" -> ...");
    }
    value
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn pacman_available() -> Option<PathBuf> {
    let path_env = env::var_os("PATH")?;
    find_in_path("pacman", Some(path_env.as_os_str()))
        .ok()?
        .into_iter()
        .find(|path_match| path_match.executable)
        .map(|path_match| path_match.path)
}

fn package_owner(path: &Path, pacman: Option<&Path>) -> Option<String> {
    let pacman = pacman?;
    let output = Command::new(pacman).args(["-Qo"]).arg(path).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    parse_pacman_owner(&stdout)
}

fn parse_pacman_owner(stdout: &str) -> Option<String> {
    let (_, owner) = stdout.split_once(" is owned by ")?;
    owner.split_whitespace().next().map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
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
            format_path_report("tool", &matches, None),
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
            format_path_report("tool", &matches, None),
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

    #[test]
    fn parses_pacman_owner() {
        assert_eq!(
            parse_pacman_owner("/usr/bin/python is owned by python 3.13.3-1\n"),
            Some("python".to_owned())
        );
    }
}
