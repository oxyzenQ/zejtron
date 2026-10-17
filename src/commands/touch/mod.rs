// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

mod audit;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use audit::{try_audit_log, try_journalctl};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchError(String);

impl fmt::Display for TouchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for TouchError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileMeta {
    pub(crate) file_type: String,
    pub(crate) size: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) perms_octal: String,
    pub(crate) inode: u64,
    pub(crate) dev: u64,
    pub(crate) modified: SystemTime,
    pub(crate) accessed: SystemTime,
    pub(crate) changed: SystemTime,
    pub(crate) is_symlink: bool,
    pub(crate) symlink_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TouchInfo {
    pub(crate) path: PathBuf,
    pub(crate) modified: SystemTime,
    pub(crate) source: EvidenceSource,
    pub(crate) actor: String,
    pub(crate) process: Option<ProcessEvidence>,
    pub(crate) meta: Option<FileMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceSource {
    Metadata,
    Audit,
    Journal,
}

impl EvidenceSource {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Metadata => "filesystem metadata",
            Self::Audit => "audit evidence",
            Self::Journal => "journal evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessEvidence {
    pub(crate) name: String,
    pub(crate) pid: Option<u32>,
}

impl ProcessEvidence {
    pub(crate) fn label(&self) -> String {
        match self.pid {
            Some(pid) => format!("{} pid={pid}", self.name),
            None => self.name.clone(),
        }
    }
}

pub fn run(path: &Path) -> Result<(), Box<dyn Error>> {
    let info = inspect_path(path)?;
    println!("{}", format_report(&info));
    Ok(())
}

pub(crate) fn inspect_path(path: &Path) -> Result<TouchInfo, TouchError> {
    // Use symlink_metadata so we can detect symlinks and report their target
    let symlink_meta = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            TouchError(format!("path not found: {}", path.display()))
        } else {
            TouchError(format!("{}: {error}", path.display()))
        }
    })?;

    // For target metadata (size, type), follow the symlink
    let target_meta = if symlink_meta.file_type().is_symlink() {
        fs::metadata(path).ok()
    } else {
        Some(symlink_meta.clone())
    };

    let modified = symlink_meta
        .modified()
        .map_err(|error| TouchError(format!("{}: {error}", path.display())))?;

    // Build full FileMeta
    let meta = build_file_meta(path, &symlink_meta, target_meta.as_ref());

    let display_path = path.to_path_buf();
    let lookup_path = absolute_path(path).unwrap_or_else(|| path.to_path_buf());
    let users = parse_passwd().unwrap_or_default();

    if let Some(mut info) = try_audit_log(&display_path, &lookup_path, &users) {
        info.meta = Some(meta);
        return Ok(info);
    }

    if let Some(mut info) = try_journalctl(&display_path, &lookup_path, &users) {
        info.meta = Some(meta);
        return Ok(info);
    }

    Ok(TouchInfo {
        path: display_path,
        modified,
        source: EvidenceSource::Metadata,
        actor: "unknown".to_owned(),
        process: None,
        meta: Some(meta),
    })
}

fn build_file_meta(
    path: &Path,
    symlink_meta: &fs::Metadata,
    target_meta: Option<&fs::Metadata>,
) -> FileMeta {
    let is_symlink = symlink_meta.file_type().is_symlink();
    let symlink_target = if is_symlink {
        fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        None
    };

    let m = target_meta.unwrap_or(symlink_meta);
    let file_type = if is_symlink {
        "symlink".to_owned()
    } else if m.is_dir() {
        "directory".to_owned()
    } else if m.is_file() {
        "file".to_owned()
    } else {
        "special".to_owned()
    };

    let perms_octal = format!("{:04o}", m.permissions().mode() & 0o7777);

    FileMeta {
        file_type,
        size: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        perms_octal,
        inode: m.ino(),
        dev: m.dev(),
        modified: m.modified().unwrap_or(UNIX_EPOCH),
        accessed: m.accessed().unwrap_or(UNIX_EPOCH),
        changed: SystemTime::UNIX_EPOCH + Duration::from_secs(m.ctime() as u64),
        is_symlink,
        symlink_target,
    }
}

fn absolute_path(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    std::env::current_dir().ok().map(|cwd| cwd.join(path))
}

fn format_report(info: &TouchInfo) -> String {
    let mut lines = vec![info.path.display().to_string()];

    // Metadata block (size, owner, perms, timestamps, inode)
    if let Some(ref meta) = info.meta {
        let uname = parse_passwd()
            .ok()
            .and_then(|u| u.get(&meta.uid).cloned())
            .unwrap_or_else(|| meta.uid.to_string());
        let gname = parse_passwd()
            .ok()
            .and_then(|u| u.get(&meta.gid).cloned())
            .unwrap_or_else(|| meta.gid.to_string());

        lines.push(format!("├── type: {}", meta.file_type));
        if meta.is_symlink
            && let Some(ref target) = meta.symlink_target
        {
            lines.push(format!("├── symlink-target: {target}"));
        }
        lines.push(format!("├── size: {} bytes", meta.size));
        lines.push(format!(
            "├── owner: {}:{} (uid={} gid={})",
            uname, gname, meta.uid, meta.gid
        ));
        lines.push(format!("├── perms: {}", meta.perms_octal));
        lines.push(format!("├── inode: {} (dev={})", meta.inode, meta.dev));
        lines.push(format!(
            "├── modified: {}",
            format_system_time(meta.modified)
        ));
        lines.push(format!(
            "├── accessed: {}",
            format_system_time(meta.accessed)
        ));
        lines.push(format!(
            "├── changed:  {}",
            format_system_time(meta.changed)
        ));
    } else {
        lines.push(format!(
            "├── modified: {}",
            format_system_time(info.modified)
        ));
    }

    lines.push(format!("├── source: {}", info.source.label()));

    if let Some(process) = &info.process {
        lines.push(format!("├── actor: {}", info.actor));
        lines.push(format!("└── process: {}", process.label()));
    } else {
        lines.push(format!("└── actor: {}", info.actor));
    }

    lines.push(String::new());
    lines.push(match info.source {
        EvidenceSource::Metadata => {
            "note: filesystem metadata shows when the path changed, not who changed it".to_owned()
        }
        EvidenceSource::Audit | EvidenceSource::Journal => {
            "note: actor inference is best-effort and depends on available logs".to_owned()
        }
    });

    lines.join("\n")
}

pub(crate) fn format_system_time(time: SystemTime) -> String {
    crate::info::clock::format_system_time(time)
}

fn parse_passwd() -> io::Result<HashMap<u32, String>> {
    parse_passwd_contents(&fs::read_to_string("/etc/passwd")?)
}

fn parse_passwd_contents(contents: &str) -> io::Result<HashMap<u32, String>> {
    let mut users = HashMap::new();
    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next().filter(|name| !name.is_empty()) else {
            continue;
        };
        fields.next();
        let Some(uid) = fields.next().and_then(|uid| uid.parse::<u32>().ok()) else {
            continue;
        };
        users.insert(uid, name.to_owned());
    }
    Ok(users)
}

pub(super) fn uid_to_user(uid: u32, users: &HashMap<u32, String>) -> String {
    users.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
}

#[cfg(test)]
#[path = "../../../test/commands/touch/touch_tests.rs"]
mod tests;
