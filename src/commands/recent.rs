// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::cmp::Reverse;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const IGNORED_DIRECTORIES: &[&str] = &[".git", "target", "node_modules", ".cache"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentFile {
    pub path: PathBuf,
    pub modified: SystemTime,
    pub changed: SystemTime,
    pub size: u64,
    pub uid: u32,
    pub perms: u32,
}

pub fn run(
    path: &Path,
    limit: usize,
    since: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let since = since.map(parse_duration).transpose()?;
    let files = select_recent_files(scan_recent_files(path)?, limit, since, SystemTime::now());

    if files.is_empty() {
        // The empty-result line rides grey (the "no events" class).
        println!("{}", crate::output::grey_out("no modified files found"));
        return Ok(());
    }

    let now = SystemTime::now();
    let rows: Vec<(String, String, String)> = files
        .iter()
        .map(|file| {
            let owner = crate::system::lookup_username(file.uid);
            (
                display_relative_path(path, &file.path),
                rough_age(now, file.modified),
                format!(
                    "{} {} {:04o}",
                    human_size(file.size),
                    owner,
                    file.perms & 0o7777
                ),
            )
        })
        .collect();
    let width = rows
        .iter()
        .map(|(path, _, _)| path.chars().count())
        .max()
        .unwrap_or(0);

    // Roles (night-improve-37): the section header rides green, the
    // tree glyphs and the age column (timestamps) ride grey, the
    // values (paths, sizes, owners, perms) stay unwrapped - white.
    println!("{}", crate::output::ok_out("modified files:"));
    for (index, (path, age, meta)) in rows.iter().enumerate() {
        let prefix = if index + 1 == rows.len() {
            "└──"
        } else {
            "├──"
        };
        println!(
            "{p} {path:<width$}  {a}  {meta}",
            p = crate::output::grey_out(prefix),
            a = crate::output::grey_out(age)
        );
    }

    Ok(())
}

pub fn parse_duration(input: &str) -> Result<Duration, String> {
    if input.len() < 2 {
        return Err(format!("invalid duration: {input}"));
    }

    let (amount, unit) = input.split_at(input.len() - 1);
    let amount: u64 = amount
        .parse()
        .map_err(|_| format!("invalid duration: {input}"))?;

    match unit {
        "m" => Ok(Duration::from_secs(amount * 60)),
        "h" => Ok(Duration::from_secs(amount * 60 * 60)),
        "d" => Ok(Duration::from_secs(amount * 24 * 60 * 60)),
        _ => Err(format!("invalid duration: {input}")),
    }
}

pub fn sort_newest_first(files: &mut [RecentFile]) {
    files.sort_by_key(|file| Reverse(file.modified));
}

fn select_recent_files(
    mut files: Vec<RecentFile>,
    limit: usize,
    since: Option<Duration>,
    now: SystemTime,
) -> Vec<RecentFile> {
    sort_newest_first(&mut files);

    if let Some(since) = since {
        files.retain(|file| {
            now.duration_since(file.modified)
                .map(|age| age <= since)
                .unwrap_or(true)
        });
    }

    files.truncate(limit);
    files
}

fn scan_recent_files(path: &Path) -> io::Result<Vec<RecentFile>> {
    let mut files = Vec::new();
    scan_path(path, &mut files, true)?;
    Ok(files)
}

fn scan_path(path: &Path, files: &mut Vec<RecentFile>, is_root: bool) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if is_skippable_error(&error) && !is_root => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
        Err(error) => return Err(error),
    };

    if metadata.is_file() {
        if let Ok(modified) = metadata.modified() {
            let changed = SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64);
            files.push(RecentFile {
                path: path.to_path_buf(),
                modified,
                changed,
                size: metadata.len(),
                uid: metadata.uid(),
                perms: metadata.permissions().mode(),
            });
        }
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if is_skippable_error(&error) => return Ok(()),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let entry_path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        if file_type.is_dir() {
            if should_ignore_directory(&entry_path) {
                continue;
            }
            scan_path(&entry_path, files, false)?;
        } else if file_type.is_file() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            let changed = SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64);
            files.push(RecentFile {
                path: entry_path,
                modified,
                changed,
                size: metadata.len(),
                uid: metadata.uid(),
                perms: metadata.permissions().mode(),
            });
        }
    }

    Ok(())
}

fn is_skippable_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn should_ignore_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| IGNORED_DIRECTORIES.contains(&name))
        .unwrap_or(false)
}

fn display_relative_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn rough_age(now: SystemTime, modified: SystemTime) -> String {
    let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
    let seconds = age.as_secs();

    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 60 * 60 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h ago", seconds / (60 * 60))
    } else {
        format!("{}d ago", seconds / (24 * 60 * 60))
    }
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

#[cfg(test)]
#[path = "../../test/commands/recent_tests.rs"]
mod tests;
