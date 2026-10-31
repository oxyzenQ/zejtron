// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
// NON_LATIN_FIXTURE: the parser comments quote the literal
// multibyte crash inputs (`5分`) the char-boundary fix names.

use std::cmp::Reverse;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    print_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let since = since.map(parse_duration).transpose()?;
    let files = select_recent_files(scan_recent_files(path)?, limit, since, SystemTime::now());

    // The renderer branch (night-badass-9): the JSON lane speaks the
    // same selection - the same limit, the same window, the same
    // newest-first order - as one typed line; the text lane renders
    // the tree. One scan, two renderers, no second walk.
    if print_json {
        // One passwd read for the whole report - the text lane's own
        // law, shared here.
        let users = crate::system::passwd_users().unwrap_or_default();
        println!("{}", files_json(path, &files, &users));
        return Ok(());
    }

    if files.is_empty() {
        // The empty-result line rides grey (the "no events" class).
        println!("{}", crate::output::grey_out("no modified files found"));
        return Ok(());
    }

    let now = SystemTime::now();
    // One passwd read for the whole report - not one per row
    // (night-total-lts-3: this loop re-read /etc/passwd per file).
    let users = crate::system::passwd_users().unwrap_or_default();
    let rows: Vec<(String, String, String)> = files
        .iter()
        .map(|file| {
            let owner = crate::system::uid_to_user(file.uid, &users);
            (
                // Scanned trees can hold files other users created; a
                // filename is attacker-controlled bytes, so the
                // displayed column goes through the terminal-safety
                // neutralizer (night-total-lts-3).
                crate::system::sanitize_display(&display_relative_path(path, &file.path)),
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
    // The unit is the final CHARACTER, never the final byte
    // (night-dragon-lts-1, the same law the port window parser
    // carries): str::split_at panics when its index lands inside a
    // multibyte character, so a `--since 5分` - any input whose
    // last byte is not a char boundary - crashed the CLI instead
    // of being rejected. Peeling the last char off through chars()
    // keeps every multibyte unit a clean parse error, and an empty
    // or one-char input fails structurally (no last char, or an
    // empty amount that parse() refuses).
    let Some(unit) = input.chars().next_back() else {
        return Err(format!("invalid duration: {input}"));
    };
    let amount = &input[..input.len() - unit.len_utf8()];
    let amount: u64 = amount
        .parse()
        .map_err(|_| format!("invalid duration: {input}"))?;

    // Saturating on purpose (night-total-lts-1): the u64 amount times
    // the unit multiplier can overflow (the day arm multiplies by
    // 86400 - a five-digit-exponent ask wraps), and a wrapped
    // Duration silently filters the wrong file set. Saturating sends
    // every absurd ask to u64::MAX seconds - the honest "older than
    // everything" answer for an age request no filesystem can outlive;
    // debug builds (the test lane) panicked on the same input before
    // the fix. The port window parser (window.rs) carries the same
    // law for the same reason.
    match unit {
        'm' => Ok(Duration::from_secs(amount.saturating_mul(60))),
        'h' => Ok(Duration::from_secs(
            amount.saturating_mul(60).saturating_mul(60),
        )),
        'd' => Ok(Duration::from_secs(
            amount
                .saturating_mul(24)
                .saturating_mul(60)
                .saturating_mul(60),
        )),
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
            // The panic-free signed construction (night-dragon-lts-T1):
            // a negative ctime used to wrap through `as u64` into a
            // SystemTime-addition overflow panic.
            let changed = crate::info::clock::system_time_from_unix_secs(metadata.ctime());
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
            // The panic-free signed construction (night-dragon-lts-T1):
            // a negative ctime used to wrap through `as u64` into a
            // SystemTime-addition overflow panic.
            let changed = crate::info::clock::system_time_from_unix_secs(metadata.ctime());
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

/// The recent-files report as one JSON line (night-badass-9): the
/// same selection the text renders, typed. Paths carry the raw bytes
/// JSON-escaped (the terminal lane's display neutralizer is a render
/// concern; the JSON wire's escaping is [`write_string`]'s), the
/// timestamps are unix seconds (the ledger's own convention), and an
/// owner the passwd read cannot name rides the raw uid text - the
/// same fallback [`uid_to_user`] renders.
pub(crate) fn files_json(
    base: &Path,
    files: &[RecentFile],
    users: &std::collections::HashMap<u32, String>,
) -> String {
    use crate::evidence::json::{write_array, write_string};
    let mut out = String::with_capacity(256 * files.len().max(1));
    out.push_str("{\"path\":");
    write_string(&mut out, &base.display().to_string());
    out.push_str(",\"files\":");
    write_array(&mut out, files.len(), |out, index| {
        let file = &files[index];
        out.push_str("{\"path\":");
        write_string(out, &display_relative_path(base, &file.path));
        out.push_str(",\"mtime_unix_secs\":");
        let _ = write!(out, "{}", unix_secs(file.modified));
        out.push_str(",\"changed_unix_secs\":");
        let _ = write!(out, "{}", unix_secs(file.changed));
        out.push_str(",\"size_bytes\":");
        let _ = write!(out, "{}", file.size);
        out.push_str(",\"uid\":");
        let _ = write!(out, "{}", file.uid);
        out.push_str(",\"owner\":");
        write_string(out, &crate::system::uid_to_user(file.uid, users));
        out.push_str(",\"perms\":");
        let _ = write!(out, "\"{:04o}\"", file.perms & 0o7777);
        out.push('}');
    });
    out.push('}');
    out
}

/// The unix seconds of a timestamp, saturating at the epoch: a clock
/// before 1970 is not a reportable fact, and the ledger's own
/// unix_now rides the same zero fallback.
fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "../../test/commands/recent_tests.rs"]
mod tests;
