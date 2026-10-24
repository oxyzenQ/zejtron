// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The Evidence Ledger row (night-improve-3): one line of evidence.
//! The row grammar is locked - `<UTC timestamp>  <action>  <actor>
//! [<provenance>]` - and the four provenance tiers are the whole
//! vocabulary: no fifth tier, ever. A later pass that needs a new
//! source class must fit it INSIDE one of these four (the log lane
//! is \[inferred] however strong an audit record reads; the tag is
//! the truth about the source, not marketing).
//!
//! The timestamp is unix seconds; `None` renders `unknown` (an
//! absent fact stays absent, never guessed). The (UTC) suffix rule
//! lives in the renderer: the first timestamped row of the report
//! declares the column's clock, the rows after it stay bare.
//!
//! The action is a typed fact, not a string (night-badass-5):
//! [`EvidenceKind`] carries the raw data (the bytes, the uid/gid
//! pair, the inode/dev pair) and owns two renderings - [`
//! EvidenceKind::phrase`] is the locked text grammar ("size 884
//! bytes"), and the JSON lane (json.rs) serializes the same enum
//! into the typed evidence fields at the row's root (night-badass-6:
//! `{"kind":"size","bytes":884}`). The actor is a typed fact too
//! (night-badass-6): [`EvidenceActor`] carries the name/pid/user
//! triple raw, [`Display`] renders the locked text column
//! ("brave (pid 2985, rezky)", the em-dash for pure state), and the
//! JSON lane serializes the same struct into the typed actor object
//! (`{"name":"brave","pid":2985,"user":"rezky"}`, JSON null for
//! pure state). One source, two surfaces, no drift: the text and
//! the JSON are two renderings of the same variants.

/// The four provenance tiers - exactly four, the locked grammar.
/// \[observed] rows come from eBPF kernel events, \[measured] rows
/// from snapshot reads taken at the instant of the command,
/// \[inferred] rows from indirect evidence (the log lane: audit.log
/// and journalctl records, replayed), \[unaccounted] names what the
/// report cannot see (it lives in the Unaccounted block; the tier
/// exists so the vocabulary stays four).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Directly from an eBPF kernel event - the kernel recorded the
    /// action as it happened, with the pid.
    Observed,
    /// From a snapshot read (/proc, /sys, stat) at the instant of
    /// the command.
    Measured,
    /// From indirect evidence - a log replayed, an mtime implying a
    /// write.
    Inferred,
    /// The report cannot see this. Carried by the Unaccounted block
    /// rather than by rows in Phase 3; the variant holds the
    /// vocabulary's fourth seat so no later pass invents a fifth -
    /// the scoped allow is the honest count.
    #[allow(dead_code)]
    Unaccounted,
}

impl Provenance {
    /// The row tag - lowercase, bracketed, the last token on the
    /// line.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Measured => "measured",
            Self::Inferred => "inferred",
            Self::Unaccounted => "unaccounted",
        }
    }
}

/// The row's acting identity (night-badass-6): the typed actor, not
/// a pre-rendered string. Three parts - the process name, the pid,
/// the user - each present only when the source named it: the live
/// holders and the event lane read all three from /proc, the log
/// lane carries what the record said, and pure state (the metadata
/// rows) names no actor at all. Like the kind, the struct owns two
/// renderings: [`Display`] is the locked text grammar's one
/// implementation ("brave (pid 2985, rezky)", the em-dash when no
/// part exists), and the JSON lane (json.rs) serializes the same
/// struct into the typed actor object
/// (`{"name":"brave","pid":2985,"user":"rezky"}`, JSON null when no
/// part exists - the machine-native form of the em-dash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceActor {
    /// The process name, when the source named one.
    pub name: Option<String>,
    /// The process id, when the source carried one.
    pub pid: Option<u32>,
    /// The user name - resolved from the uid, or as the record
    /// spelled it.
    pub user: Option<String>,
}

impl EvidenceActor {
    /// The pure-state actor: the row names no acting identity - the
    /// text column's em-dash, the JSON lane's null.
    pub fn none() -> Self {
        Self {
            name: None,
            pid: None,
            user: None,
        }
    }

    /// The process actor: the live holder's or event's triple, all
    /// three facts read from /proc at the same instant.
    pub fn process(name: impl Into<String>, pid: u32, user: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            pid: Some(pid),
            user: Some(user.into()),
        }
    }

    /// The recorded actor: what a log line carried - the process
    /// name and pid when the record named them, the username it
    /// recorded either way. Each absent part is an honest absence.
    pub fn recorded(name: Option<String>, pid: Option<u32>, user: Option<String>) -> Self {
        Self { name, pid, user }
    }
}

impl std::fmt::Display for EvidenceActor {
    /// The text column's locked grammar, byte-identical to the
    /// pre-typed strings: `name (pid N, user)` when the process and
    /// its account are known, `name (user)` when the record carried
    /// no pid, `name (pid N)` when it carried no account, the bare
    /// name or user when only one part exists, and the em-dash for
    /// pure state. Every shape degrades honestly - never a panic,
    /// never a guessed part.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.name, self.pid, &self.user) {
            (None, None, None) => f.write_str("—"),
            (Some(name), Some(pid), Some(user)) => write!(f, "{name} (pid {pid}, {user})"),
            (Some(name), Some(pid), None) => write!(f, "{name} (pid {pid})"),
            (Some(name), None, Some(user)) => write!(f, "{name} ({user})"),
            (Some(name), None, None) => f.write_str(name),
            (None, Some(pid), Some(user)) => write!(f, "{user} (pid {pid})"),
            (None, Some(pid), None) => write!(f, "pid {pid}"),
            (None, None, Some(user)) => f.write_str(user),
        }
    }
}

/// The action's typed vocabulary (night-badass-5): every fact the
/// ledgers emit, one variant each, carrying the RAW data - the
/// renderer formats, the JSON serializer types. The variant set is
/// the complete action grammar of the three surfaces (holds, touch,
/// why) plus the event lane: a new fact class adds a variant here
/// and an arm to both renderers, or it does not exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    /// `type <file_type>` - the stat(2) file class.
    Type {
        /// The file's own class word ("file", "directory", ...).
        file_type: String,
    },
    /// `symlink-target <target>` - where a symlink points.
    SymlinkTarget {
        /// The link's resolved target string.
        target: String,
    },
    /// `size <N> bytes` - the stat(2) size, raw and typed.
    Size {
        /// The size in bytes.
        bytes: u64,
    },
    /// `owner <user>:<group> (uid <u>, gid <g>)` - the ownership
    /// quadruple: resolved names AND raw ids.
    Owner {
        /// The owner user name (the uid's passwd word, or the decimal
        /// uid when passwd has no entry).
        user: String,
        /// The owner group name (same rule).
        group: String,
        /// The raw uid.
        uid: u32,
        /// The raw gid.
        gid: u32,
    },
    /// `perms <octal>` - the permission bits, octal text ("0644").
    Permissions {
        /// The mode's octal rendering, as stat carried it.
        octal: String,
    },
    /// `inode <id> (dev <dev>)` - the file identity pair the event
    /// lane keys on.
    Inode {
        /// The inode number.
        id: u64,
        /// The device token.
        dev: u64,
    },
    /// `modified` - the mtime fact; `via` names the record that
    /// carries it when the row came from a lane ("audit log"), and
    /// is `None` for the plain metadata row.
    Modified {
        /// The named source qualifier, when the row rode a lane.
        via: Option<&'static str>,
    },
    /// `accessed` - the atime fact.
    Accessed,
    /// `changed` - the ctime fact.
    Changed,
    /// `held via <label>` - one piece of holder evidence (the fd
    /// table or the maps scan), labeled by the holds parser.
    Held {
        /// The evidence label ("fd 3 (rw)", "mmap r-xp").
        via: String,
    },
    /// `cwd <path>` / `cwd (unreadable)` - the holder's working
    /// directory; `None` is the permission boundary, named not
    /// guessed.
    Cwd {
        /// The sanitized working directory, or `None` when unreadable.
        path: Option<String>,
    },
    /// `runs <cmd> (unit <unit>)` / `runs under unit <unit>` /
    /// `runs <cmd>` - the enrichment row: the systemd unit from the
    /// cgroup and the fresh cmdline, each part present only when the
    /// read saw it.
    Runs {
        /// The process cmdline, when fresh (cmd == name adds nothing).
        cmd: Option<String>,
        /// The systemd unit, when the cgroup named one.
        unit: Option<String>,
    },
    /// `opened` - the kernel's own open record (the vfs_open probe).
    Opened,
    /// `wrote` / `wrote (writev)` - the kernel's own write record;
    /// `via` names the syscall family ("writev") when it matters.
    Wrote {
        /// The write-path qualifier, when the probe names one.
        via: Option<&'static str>,
    },
    /// `journal mention` - the journal grep hit, the log lane's
    /// weakest record class.
    JournalMention,
}

impl EvidenceKind {
    /// The JSON kind word - the typed vocabulary's own tag, one
    /// jq-friendly token per variant (no spaces).
    pub fn kind_word(&self) -> &'static str {
        match self {
            Self::Type { .. } => "type",
            Self::SymlinkTarget { .. } => "symlink-target",
            Self::Size { .. } => "size",
            Self::Owner { .. } => "owner",
            Self::Permissions { .. } => "perms",
            Self::Inode { .. } => "inode",
            Self::Modified { .. } => "modified",
            Self::Accessed => "accessed",
            Self::Changed => "changed",
            Self::Held { .. } => "held",
            Self::Cwd { .. } => "cwd",
            Self::Runs { .. } => "runs",
            Self::Opened => "opened",
            Self::Wrote { .. } => "wrote",
            Self::JournalMention => "journal-mention",
        }
    }

    /// The text action phrase - the locked row grammar's middle
    /// column, byte-identical to the pre-typed strings. This is the
    /// ONE renderer of the action's text form; the JSON lane renders
    /// the same variant as the typed object.
    pub fn phrase(&self) -> String {
        match self {
            Self::Type { file_type } => format!("type {file_type}"),
            Self::SymlinkTarget { target } => format!("symlink-target {target}"),
            Self::Size { bytes } => format!("size {bytes} bytes"),
            Self::Owner {
                user,
                group,
                uid,
                gid,
            } => format!("owner {user}:{group} (uid {uid}, gid {gid})"),
            Self::Permissions { octal } => format!("perms {octal}"),
            Self::Inode { id, dev } => format!("inode {id} (dev {dev})"),
            Self::Modified { via } => match via {
                Some(source) => format!("modified ({source})"),
                None => "modified".to_owned(),
            },
            Self::Accessed => "accessed".to_owned(),
            Self::Changed => "changed".to_owned(),
            Self::Held { via } => format!("held via {via}"),
            Self::Cwd { path } => match path {
                Some(path) => format!("cwd {path}"),
                None => "cwd (unreadable)".to_owned(),
            },
            Self::Runs { cmd, unit } => match (cmd, unit) {
                (Some(cmd), Some(unit)) => format!("runs {cmd} (unit {unit})"),
                (None, Some(unit)) => format!("runs under unit {unit}"),
                (Some(cmd), None) => format!("runs {cmd}"),
                // Unreachable by construction (the enrichment builder
                // never emits an empty runs row); the plain word is
                // the honest degradation, never a panic.
                (None, None) => "runs".to_owned(),
            },
            Self::Opened => "opened".to_owned(),
            Self::Wrote { via } => match via {
                Some(family) => format!("wrote ({family})"),
                None => "wrote".to_owned(),
            },
            Self::JournalMention => "journal mention".to_owned(),
        }
    }
}

/// One evidence row. The timestamp is the moment of the fact: the
/// scan instant for state rows, the event's own time for event rows,
/// the mtime for an mtime row. The actor is the acting identity -
/// the typed [`EvidenceActor`] triple for processes, [`
/// EvidenceActor::none`] for pure state that has no actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRow {
    /// Unix seconds of the fact; `None` renders `unknown`.
    pub unix_secs: Option<i64>,
    /// What happened or what holds - the typed fact itself.
    pub kind: EvidenceKind,
    /// Who did it or who holds it - the typed actor; [`
    /// EvidenceActor::none`] when the row is pure state.
    pub actor: EvidenceActor,
    /// Exactly one tier.
    pub provenance: Provenance,
}

impl EvidenceRow {
    /// Build a row; the plain constructor the ledgers use.
    pub fn new(
        unix_secs: Option<i64>,
        kind: EvidenceKind,
        actor: EvidenceActor,
        provenance: Provenance,
    ) -> Self {
        Self {
            unix_secs,
            kind,
            actor,
            provenance,
        }
    }

    /// Render the row line (no leading indent; the renderer adds
    /// it). `mark_utc` is true only for the first timestamped row of
    /// the report - it keeps the ` (UTC)` suffix the clock module
    /// emits; every row after it drops the suffix (the column was
    /// declared once).
    ///
    /// Roles (night-improve-37, the locked scheme): the timestamp
    /// column rides the grey tier (secondary content), the action and
    /// actor stay unwrapped (the values - the facts the user came
    /// for), and the provenance tag rides the strongest-evidence
    /// split: `[observed]` and `[measured]` are green (the strongest
    /// evidence), `[inferred]` and `[unaccounted]` grey (the weaker
    /// evidence). The tag is the last token on the line, exactly four
    /// tiers, unchanged. In Mono every wrap is the identity - the
    /// plain bytes the tests pin.
    pub fn render_line(&self, mark_utc: bool) -> String {
        let timestamp = match self.unix_secs {
            Some(secs) => {
                let full = crate::info::clock::format_unix_secs(secs);
                if mark_utc {
                    full
                } else {
                    full.strip_suffix(" (UTC)")
                        .map(str::to_owned)
                        .unwrap_or(full)
                }
            }
            None => "unknown".to_owned(),
        };
        let tag = format!("[{}]", self.provenance.tag());
        let tag = match self.provenance {
            Provenance::Observed | Provenance::Measured => crate::output::ok_out(&tag),
            Provenance::Inferred | Provenance::Unaccounted => crate::output::grey_out(&tag),
        };
        // The actor renders through Display - the locked text
        // grammar's one implementation, byte-identical to the
        // pre-typed strings.
        format!(
            "{}  {}  {}  {tag}",
            crate::output::grey_out(&timestamp),
            self.kind.phrase(),
            self.actor
        )
    }
}

#[cfg(test)]
#[path = "../../test/evidence/row_tests.rs"]
mod tests;

// The spec drift pin (night-improve-44): docs/EVIDENCE-LEDGER.md is
// the citable Evidence Ledger Specification v1, and this module is
// the clamp between the document and the tier vocabulary defined
// above. Test-only - the release binary is byte-identical.
#[cfg(test)]
#[path = "../../test/evidence/spec_tests.rs"]
mod spec_tests;
