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
    let path_env = env::var_os("PATH");
    let matches = find_in_path(command, path_env.as_deref())?;

    if matches.is_empty() {
        println!("command not found in PATH: {command}");
        return Ok(());
    }

    let report = format_path_report(command, &matches);
    println!("{report}");

    Ok(())
}

pub fn format_path_report(command: &str, matches: &[PathMatch]) -> String {
    let Some((active, duplicates)) = matches.split_first() else {
        return format!("command not found in PATH: {command}");
    };

    let mut lines = vec![command.to_owned()];

    lines.push(format!("├── active: {}", display_match_path(active)));
    lines.push(format!("├── executable: {}", yes_no(active.executable)));
    let pkg = package_owner_multi(&active.path);
    lines.push(format!(
        "├── package: {}",
        pkg.as_deref().unwrap_or("unknown")
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
            package_owner_multi(&path_match.path)
                .as_deref()
                .unwrap_or("unknown")
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

/// Multi-backend package owner lookup. Tries each backend in order of
/// availability: pacman (Arch), dpkg (Debian/Ubuntu), rpm (Fedora/RHEL),
/// apk (Alpine). Returns the first match.
fn package_owner_multi(path: &Path) -> Option<String> {
    if let Some(pkg) = try_pacman(path) {
        return Some(format!("{pkg} (pacman)"));
    }
    if let Some(pkg) = try_dpkg(path) {
        return Some(format!("{pkg} (dpkg)"));
    }
    if let Some(pkg) = try_rpm(path) {
        return Some(format!("{pkg} (rpm)"));
    }
    if let Some(pkg) = try_apk(path) {
        return Some(format!("{pkg} (apk)"));
    }
    None
}

fn try_pacman(path: &Path) -> Option<String> {
    let output = Command::new("pacman")
        .args(["-Qo", "--quiet"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().to_owned().into()
}

fn try_dpkg(path: &Path) -> Option<String> {
    let output = Command::new("dpkg")
        .args(["-S", "--"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // dpkg -S output: "package: /path/to/file" — take first colon-separated
    stdout
        .lines()
        .next()?
        .split(':')
        .next()?
        .trim()
        .to_owned()
        .into()
}

fn try_rpm(path: &Path) -> Option<String> {
    let output = Command::new("rpm")
        .args(["-qf", "--queryformat", "%{NAME}"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pkg = stdout.trim();
    if pkg.is_empty() || pkg.contains("not installed") {
        None
    } else {
        pkg.to_owned().into()
    }
}

fn try_apk(path: &Path) -> Option<String> {
    let output = Command::new("apk")
        .args(["info", "--who-owns", "--quiet"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().to_owned().into()
}

#[cfg(test)]
#[path = "../../test/commands/path_tests.rs"]
mod tests;
