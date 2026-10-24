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

pub fn run(command: &str, print_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path_env = env::var_os("PATH");
    let matches = find_in_path(command, path_env.as_deref())?;

    // The renderer branch (night-badass-9): the JSON lane speaks the
    // same resolution - the same match set, the same owner lookup -
    // as one typed line; the text lane renders the tree.
    if print_json {
        println!("{}", path_json(command, &matches, &package_owner_multi));
        return Ok(());
    }

    if matches.is_empty() {
        // The empty-result line: the verdict text rides grey (the
        // locked scheme's secondary content - the same class as the
        // "no events" line), the queried command is the value and
        // stays unwrapped.
        println!(
            "{} {command}",
            crate::output::grey_out("command not found in PATH:")
        );
        return Ok(());
    }

    let report = format_path_report(command, &matches);
    println!("{report}");

    Ok(())
}

pub fn format_path_report(command: &str, matches: &[PathMatch]) -> String {
    format_path_report_with(command, matches, &package_owner_multi)
}

/// The path resolution as one JSON line (night-badass-9): the same
/// match set the text tree renders, typed. The active match and each
/// duplicate carry the full symlink chain (the text lane's display
/// truncates at three hops - the JSON wire carries what the kernel
/// answered), and a package no backend named is JSON null - the
/// text's "unknown" word is a display verdict, not a fact.
pub(crate) fn path_json(
    command: &str,
    matches: &[PathMatch],
    owner: &dyn Fn(&Path) -> Option<String>,
) -> String {
    use crate::evidence::json::{write_array, write_string};
    fn match_json(
        out: &mut String,
        path_match: &PathMatch,
        owner: &dyn Fn(&Path) -> Option<String>,
    ) {
        out.push_str("{\"path\":");
        write_string(out, &path_match.path.display().to_string());
        out.push_str(",\"executable\":");
        out.push_str(if path_match.executable {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"symlink_chain\":");
        write_array(out, path_match.symlink_chain.len(), |out, index| {
            write_string(out, &path_match.symlink_chain[index].display().to_string());
        });
        out.push_str(",\"package\":");
        match owner(&path_match.path) {
            Some(package) => write_string(out, &package),
            None => out.push_str("null"),
        }
        out.push('}');
    }

    let mut out = String::with_capacity(256);
    out.push_str("{\"command\":");
    write_string(&mut out, command);
    out.push_str(",\"found\":");
    out.push_str(if matches.is_empty() { "false" } else { "true" });
    out.push_str(",\"active\":");
    match matches.first() {
        Some(active) => match_json(&mut out, active, owner),
        None => out.push_str("null"),
    }
    out.push_str(",\"duplicates\":");
    let duplicates = matches.get(1..).unwrap_or(&[]);
    write_array(&mut out, duplicates.len(), |out, index| {
        match_json(out, &duplicates[index], owner);
    });
    out.push('}');
    out
}

/// The test seam: the same renderer with the owner lookup injected,
/// so the render pins stay hermetic on every host's package
/// databases (the real chain answers differently on an Arch host
/// than on Debian - the row shape must not depend on either).
pub(crate) fn format_path_report_with(
    command: &str,
    matches: &[PathMatch],
    owner: &dyn Fn(&Path) -> Option<String>,
) -> String {
    let Some((active, duplicates)) = matches.split_first() else {
        // The test seam's empty shape - the same roles as run()'s:
        // grey verdict text, white command value.
        return format!(
            "{} {command}",
            crate::output::grey_out("command not found in PATH:")
        );
    };

    // Roles (night-improve-37): the queried command rides green (the
    // report's subject header), the tree glyphs ride grey (grammar),
    // the field labels ride green, the values (paths, verdicts,
    // packages) stay unwrapped - white, the terminal default. In Mono
    // every wrap is the identity, byte-identical to the pinned shape.
    let mut lines = vec![crate::output::ok_out(command)];

    lines.push(format!(
        "{} {} {}",
        crate::output::grey_out("├──"),
        crate::output::ok_out("active:"),
        display_match_path(active)
    ));
    lines.push(format!(
        "{} {} {}",
        crate::output::grey_out("├──"),
        crate::output::ok_out("executable:"),
        yes_no(active.executable)
    ));
    let pkg = owner(&active.path);
    lines.push(format!(
        "{} {} {}",
        crate::output::grey_out("├──"),
        crate::output::ok_out("package:"),
        pkg.as_deref().unwrap_or("unknown")
    ));

    if duplicates.is_empty() {
        // The absence token rides grey (the "no events" class).
        lines.push(format!(
            "{} {} {}",
            crate::output::grey_out("└──"),
            crate::output::ok_out("duplicates:"),
            crate::output::grey_out("none")
        ));
        return lines.join("\n");
    }

    lines.push(format!(
        "{} {}",
        crate::output::grey_out("└──"),
        crate::output::ok_out("duplicates:")
    ));
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

        lines.push(format!(
            "{} {}",
            crate::output::grey_out(prefix),
            display_match_path(path_match)
        ));
        lines.push(format!(
            "{} {} {}",
            crate::output::grey_out(&format!("{detail_prefix}├──")),
            crate::output::ok_out("executable:"),
            yes_no(path_match.executable)
        ));
        lines.push(format!(
            "{} {} {}",
            crate::output::grey_out(&format!("{detail_prefix}└──")),
            crate::output::ok_out("package:"),
            owner(&path_match.path).as_deref().unwrap_or("unknown")
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
/// availability: the native pacman database reader (Arch, no binary
/// invoked), dpkg (Debian/Ubuntu), rpm (Fedora/RHEL), apk (Alpine).
/// Returns the first answer. A pacman `Unowned` verdict is terminal
/// (the database exists and answered); an `Absent` verdict (no
/// /var/lib/pacman - not an Arch host) falls through to the next
/// backend unchanged.
fn package_owner_multi(path: &Path) -> Option<String> {
    if let Some(pkg) = try_pacman(path) {
        return Some(pkg);
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

/// The pacman backend reads /var/lib/pacman/local directly
/// (night-improve-0): the binary is no longer invoked. The database's
/// existence is the Arch signal - `Absent` falls through to the
/// other backends, `Unowned` is the database's own answer, an owned
/// path names the package (backend label kept for the row shape).
fn try_pacman(path: &Path) -> Option<String> {
    match crate::system::pacman::pacman_ownership(path) {
        crate::system::pacman::PacmanOwnership::Owned { name, .. } => {
            Some(format!("{name} (pacman)"))
        }
        crate::system::pacman::PacmanOwnership::Unowned => {
            Some("unowned by any package".to_owned())
        }
        crate::system::pacman::PacmanOwnership::Absent => None,
    }
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
