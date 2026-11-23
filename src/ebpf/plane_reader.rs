// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The public ID plane reader (night-frontier-Z11, phase b, D8): the
//! pinned estate reconciled against the kernel's own id enumeration -
//! the two sources of truth the `bpftool` plane answers from.
//!
//! The kernel names every live bpf object twice: per-object, through
//! the pin (BPF_OBJ_GET + BPF_OBJ_GET_INFO_BY_FD on the bpffs path),
//! and publicly, through the id enumeration (BPF_PROG_GET_NEXT_ID and
//! siblings, the list `bpftool` prints). A stealth mechanism that
//! wants a program invisible to `bpftool` must hide it from the
//! enumeration while the object keeps living through its pin - and
//! when one does, the two kernel views of the same estate disagree:
//! the pin resolves, the enumeration does not name its id. That
//! disagreement is what this reader records, with its honest cautions
//! beside it (an id the enumeration withholds is also what a kernel
//! bug or a partial read prints - the row says cross-validate, never
//! the rootkit word).
//!
//! THE CAPABILITY HONESTY: the id enumeration is privileged (the
//! CAP_SYS_ADMIN plane - the one boundary even the record-side pin
//! walk does not cross). A reader without the bit gets the named
//! absence, never a guess and never a panic: the doctor's row reads
//! `unavailable (requires CAP_SYS_ADMIN)`, the same honest shape the
//! Caps row prints for a missing CAP_BPF. The reader never escalates
//! and never shells out to `bpftool` - the same read-the-source
//! discipline the rest of the ebpf module applies, one `bpf(2)`
//! caller, std plus the libc syscall trampoline only.
//!
//! THE ATTR DISCIPLINE: the `bpf(2)` command attribute is a 128-byte
//! union in the uapi; every arm here is zero-initialized as whole
//! bytes before the typed arm rides in (the FileEvent discipline -
//! a pad that rides implicit is a pad a future field reorder can
//! silently un-write), and `core::mem::offset_of!` pins the offsets
//! the answer fields live at, so a uapi shape change cannot slip
//! through silently. The object id sits at offset 4 of the returned
//! info for every info shape this estate pins (prog, map, and link
//! info all open `__u32 type; __u32 id;`) - one read, no per-type
//! guessing.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::path::Path;

/// BPF_OBJ_GET (uapi bpf_cmd): fd for a pinned path.
const BPF_OBJ_GET: u64 = 1;
/// BPF_PROG_GET_NEXT_ID (uapi bpf_cmd 11): the program id enumeration.
const BPF_PROG_GET_NEXT_ID: u64 = 11;
/// BPF_MAP_GET_NEXT_ID (uapi bpf_cmd 12): the map id enumeration.
const BPF_MAP_GET_NEXT_ID: u64 = 12;
/// BPF_OBJ_GET_INFO_BY_FD (uapi bpf_cmd 15): the per-object facts.
const BPF_OBJ_GET_INFO_BY_FD: u64 = 15;
/// BPF_LINK_GET_NEXT_ID (uapi bpf_cmd 30): the link id enumeration.
const BPF_LINK_GET_NEXT_ID: u64 = 30;

/// The uapi `bpf_attr` arms this reader rides. Every arm is a
/// zero-initialized 128-byte whole before the typed arm is written -
/// the kernel reads only the cmd's own prefix, and the discipline
/// keeps the rest explicit.
#[repr(C)]
#[derive(Clone, Copy)]
union BpfAttr {
    /// The zeroed whole the typed arms ride in through.
    bytes: [u8; 128],
    /// GET_NEXT_ID's arm: `start_id` in, `next_id` out (the uapi
    /// shares the storage - one field, two moments).
    next_id: BpfNextId,
    /// BPF_OBJ_GET's arm: the pathname pointer at offset 0.
    obj_get: BpfObjGet,
    /// BPF_OBJ_GET_INFO_BY_FD's arm: fd, buffer length, buffer pointer.
    info: BpfInfoByFd,
}

/// `struct { __u32 start_id; __u32 next_id; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfNextId {
    start_id: u32,
    next_id: u32,
}

/// `struct { __aligned_u64 pathname; __u32 bpf_fd; __u32 file_flags; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfObjGet {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// `struct { __u32 bpf_fd; __u32 info_len; __aligned_u64 info; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInfoByFd {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// One bpf(2) call: `cmd` over the zeroed attr, -1 with errno on
/// refusal. The single syscall site of the whole module.
fn sys_bpf(cmd: u64, attr: &BpfAttr) -> Result<(), std::io::Error> {
    // SAFETY: attr is a fully initialized 128-byte union (the caller
    // zeroed the whole before the typed arm rode in), syscall(2) with
    // the bpf(2) command set reads only the cmd's own prefix, and no
    // pointer field points back into our stack for these commands.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *const BpfAttr, 128u32) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// One enumeration step: the smallest public id above `start`, or
/// `None` past the last one (the kernel answers ENOENT at the end).
fn next_id(cmd: u64, start: u32) -> Result<Option<u32>, std::io::Error> {
    let mut attr = BpfAttr { bytes: [0u8; 128] };
    attr.next_id = BpfNextId {
        start_id: start,
        next_id: 0,
    };
    match sys_bpf(cmd, &attr) {
        Ok(()) => {
            // SAFETY: the typed arm was written this call; reading it
            // back is the uapi's own contract for this command.
            let answer = unsafe { attr.next_id.next_id };
            Ok(Some(answer))
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Every public id of one class, ascending. The walk bound is the
/// honest guard against a wedged kernel answering `next_id == start`
/// forever (an id space wraps at 2^32; a million ids in one plane is
/// already absurd, and the bound turns a kernel bug into a named
/// error instead of a hang).
fn enumerate_class(cmd: u64) -> Result<BTreeSet<u32>, std::io::Error> {
    let mut ids = BTreeSet::new();
    let mut start = 0u32;
    loop {
        let Some(id) = next_id(cmd, start)? else {
            return Ok(ids);
        };
        ids.insert(id);
        start = id;
        if ids.len() >= 1_000_000 {
            return Err(std::io::Error::other(
                "the id enumeration did not terminate",
            ));
        }
    }
}

/// The pin's class in the id plane - derived from the estate's own
/// naming (the map pins' base names, the `_link` suffix, else a
/// program), the same single source `ALL_PINS` spells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PinClass {
    Prog,
    Map,
    Link,
}

impl PinClass {
    /// The class's enumeration command.
    fn next_id_cmd(self) -> u64 {
        match self {
            Self::Prog => BPF_PROG_GET_NEXT_ID,
            Self::Map => BPF_MAP_GET_NEXT_ID,
            Self::Link => BPF_LINK_GET_NEXT_ID,
        }
    }
}

/// The map pins' base names, derived from the estate's own constants
/// (one source of truth: the classification cannot drift from the
/// pins the loader plants).
fn map_pin_names() -> BTreeSet<&'static str> {
    [
        super::PIN_MAP_STATS,
        super::PIN_MAP_SOCK_EVENTS,
        super::PIN_MAP_PROC_EVENTS,
        super::PIN_MAP_TRACKED_INODES,
        super::PIN_MAP_FILE_EVENTS,
        super::PIN_MAP_OFFSETS,
        super::PIN_MAP_DROP_CENSUS,
        super::PIN_MAP_GENERATION,
    ]
    .into_iter()
    .filter_map(|p| Path::new(p).file_name().and_then(|n| n.to_str()))
    .collect()
}

/// A pin's class from its base name. Pure and pinnable: the map set
/// is the estate's own constants, the `_link` suffix is the estate's
/// own convention, everything else plants a program.
pub(crate) fn classify_pin(base_name: &str) -> PinClass {
    if map_pin_names().contains(base_name) {
        return PinClass::Map;
    }
    if base_name.ends_with("_link") {
        return PinClass::Link;
    }
    PinClass::Prog
}

/// One present pin, resolved against the per-object plane. `Err`
/// carries the named refusal (the kernel's own errno text) - the
/// reconciliation treats it as unresolved, never as a verdict.
pub(crate) struct PinObject {
    pub name: &'static str,
    pub class: PinClass,
    pub id: Result<u32, String>,
}

/// The reconciliation verdict: what the two planes said about the
/// same estate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PlaneVerdict {
    /// Every resolved pin id sits in the public enumeration: the two
    /// kernel views agree.
    Verified { pins: usize, public: usize },
    /// At least one resolved pin id the public enumeration does not
    /// name - the disagreement, with the pin names beside it.
    Cloaked {
        pins: usize,
        public: usize,
        cloaked: Vec<&'static str>,
    },
    /// The plane cannot be read by this caller - the reason names it
    /// (the capability boundary, an absent estate, the kernel's own
    /// refusal).
    Unavailable { reason: String },
}

impl PlaneVerdict {
    /// The row's verdict token and detail (unpainted - the doctor's
    /// row paints the token the way its siblings do).
    pub fn label_parts(&self) -> (&'static str, String) {
        match self {
            Self::Verified { pins, public } => {
                ("verified", format!("({pins} pins, {public} public ids)"))
            }
            Self::Cloaked {
                pins,
                public,
                cloaked,
            } => (
                "hidden",
                format!(
                    "({} cloaked: {}) - {pins} pins, {public} public ids",
                    cloaked.len(),
                    cloaked.join(", ")
                ),
            ),
            Self::Unavailable { reason } => ("unavailable", format!("({reason})")),
        }
    }
}

/// The estate's present pins, resolved against the per-object plane:
/// BPF_OBJ_GET on the pin path, then BPF_OBJ_GET_INFO_BY_FD, the id
/// read at its pinned offset. A pin that vanished mid-walk or a
/// refusal at open rides as unresolved, with the kernel's own words.
fn resolve_pins() -> Vec<PinObject> {
    let mut objects = Vec::new();
    for pin in super::ALL_PINS {
        let path = Path::new(pin);
        if !path.exists() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let class = classify_pin(name);
        let id = resolve_one(pin).map_err(|e| e.to_string());
        objects.push(PinObject { name, class, id });
    }
    objects
}

/// One pin's object id: BPF_OBJ_GET then BPF_OBJ_GET_INFO_BY_FD, the
/// id at the pinned offset 4 of every info shape this estate pins.
fn resolve_one(pin: &str) -> Result<u32, std::io::Error> {
    let pathname = CString::new(pin)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "the pin path broke"))?;
    let mut attr = BpfAttr { bytes: [0u8; 128] };
    attr.obj_get = BpfObjGet {
        pathname: pathname.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    sys_bpf(BPF_OBJ_GET, &attr)?;
    // SAFETY: the obj_get arm returned an fd in the command's own
    // field; the uapi hands the same fd back through that arm.
    let fd = unsafe { attr.obj_get.bpf_fd } as i32;

    let mut info = [0u8; 128];
    let mut attr = BpfAttr { bytes: [0u8; 128] };
    attr.info = BpfInfoByFd {
        bpf_fd: fd as u32,
        info_len: info.len() as u32,
        info: info.as_mut_ptr() as u64,
    };
    let result = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr);
    // SAFETY: fd is the raw descriptor BPF_OBJ_GET returned this call
    // and nothing else owns it - one close, whatever the info call did.
    unsafe { libc::close(fd) };
    result?;
    Ok(u32::from_le_bytes([info[4], info[5], info[6], info[7]]))
}

/// The plane reconciliation, end to end: the capability guard first
/// (the enumeration is privileged - a reader without the bit gets
/// the named absence, never a guess), the enumerations second (the
/// kernel's refusals named), the estate walk last. No panic path:
/// every refusal is a verdict.
pub(crate) fn read() -> PlaneVerdict {
    let present = super::ALL_PINS.iter().any(|p| Path::new(p).exists());
    if !present {
        return PlaneVerdict::Unavailable {
            reason: "no pin estate (nothing to reconcile)".to_owned(),
        };
    }
    if !super::cap_bit_present(super::CAP_SYS_ADMIN) {
        return PlaneVerdict::Unavailable {
            reason: "requires CAP_SYS_ADMIN (the id enumeration is privileged)".to_owned(),
        };
    }
    let objects = resolve_pins();
    let mut public = PublicPlane::default();
    for class in [PinClass::Prog, PinClass::Map, PinClass::Link] {
        match enumerate_class(class.next_id_cmd()) {
            Ok(ids) => public.insert(class, ids),
            Err(e) => {
                return PlaneVerdict::Unavailable {
                    reason: format!("the id enumeration refused: {e}"),
                };
            }
        }
    }
    reconcile(&objects, &public)
}

/// The public id plane, per class - what `bpftool`'s enumeration
/// answers from.
#[derive(Default)]
pub(crate) struct PublicPlane {
    progs: BTreeSet<u32>,
    maps: BTreeSet<u32>,
    links: BTreeSet<u32>,
}

impl PublicPlane {
    fn insert(&mut self, class: PinClass, ids: BTreeSet<u32>) {
        match class {
            PinClass::Prog => self.progs = ids,
            PinClass::Map => self.maps = ids,
            PinClass::Link => self.links = ids,
        }
    }

    fn contains(&self, class: PinClass, id: u32) -> bool {
        match class {
            PinClass::Prog => self.progs.contains(&id),
            PinClass::Map => self.maps.contains(&id),
            PinClass::Link => self.links.contains(&id),
        }
    }

    fn total(&self) -> usize {
        self.progs.len() + self.maps.len() + self.links.len()
    }
}

/// The pure reconciliation: every RESOLVED pin id must sit in its
/// class's public set. An unresolved pin rides the notes (the pin's
/// own refusal named) without flipping the verdict - the plane reader
/// says what it could see and what it could not, never a guess.
pub(crate) fn reconcile(objects: &[PinObject], public: &PublicPlane) -> PlaneVerdict {
    let mut cloaked = Vec::new();
    let mut notes = Vec::new();
    for object in objects {
        match object.id {
            Ok(id) => {
                if !public.contains(object.class, id) {
                    cloaked.push(object.name);
                }
            }
            Err(ref refusal) => notes.push(format!("{} unresolved ({refusal})", object.name)),
        }
    }
    let pins = objects.len();
    let public_total = public.total();
    if cloaked.is_empty() {
        PlaneVerdict::Verified {
            pins,
            public: public_total,
        }
    } else {
        PlaneVerdict::Cloaked {
            pins,
            public: public_total,
            cloaked,
        }
    }
}

#[cfg(test)]
#[path = "../../test/ebpf/plane_reader_tests.rs"]
mod tests;
