// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The probe loader - attach and detach (night-improve-1, the
//! zylaxion orchestration lineage; night-improve-2 grows the chain
//! to two tracepoints and a ring buffer; night-improve-3 grows it
//! to four programs and five maps, and teaches attach to verify the
//! struct offsets against the host's own BTF before planting;
//! night-improve-34 shrinks it back to four programs and five maps -
//! the two sched_process lifecycle tracepoints and their ring went
//! with the lifecycle stream surface's removal, and the offsets
//! contract shrinks to the eight file-walk slots; night-improve-42
//! grows it to five programs and the same five maps - the writev
//! probe, whose attach symbol is verified from the host's own BTF
//! before anything is planted, the argument-position sibling of
//! the offsets law; night-improve-47 grows it to six programs and
//! six maps - the post-mortem exit probe (ebpf/src/exits.rs) and its
//! proc_events ring, the drain the doctor's ram symptom reads).
//!
//! This is the privileged one-shot. `doctor --attach` loads the
//! embedded probe object, loads ALL EIGHT programs (phase 1's
//! sched/sched_process_exec counter, phase 2's
//! sock/inet_sock_set_state socket-event probe, phase 3's
//! vfs_open/vfs_write file probes, night-improve-42's vfs_writev
//! vectorized-write probe, night-improve-47's
//! sched/sched_process_exit post-mortem exit probe, night-frontier-2's
//! unlink and rename probes), attaches each,
//! and pins
//! EVERYTHING to bpffs - programs, links, maps - then writes the
//! BTF-parsed struct offsets into the `offsets` map, and the
//! process may exit, because the pinned links keep the probes alive
//! and the pinned maps keep the counters, the rings, the filter
//! map, and the offsets alive. After `attach` returns, nothing of
//! zejtron is resident in userspace. `doctor --detach` unpins
//! everything; the link pins go first so an interrupted cleanup
//! leaves a DETACHED probe, never a half-attached one.
//!
//! Idempotence and self-heal (the zylaxion contract): a complete pin
//! set is already-attached (a success shape - running attach twice is
//! fine); a partial pin set (a crashed attach, a manual rm) is
//! cleaned and replanted. A failed attach cleans every pin it planted
//! - no half state, ever.
//!
//! Every refusal names its reason: the kernel floor, the lockdown
//! mode, the missing capabilities, the unverifiable offsets. No
//! silent fallback.

use aya::Ebpf;

use super::btf;
use super::btf_offpath;
use super::btf_unlink;
use super::btf_writev;
use super::embedded;
use super::plant;
use super::{LaneVerdict, PIN_DIR, any_pin_present, lane_verdict, probe_kernel};
use crate::output::verbose::vlog;

/// The embedded pure-Rust probe object (night-improve-1): the aya-ebpf
/// ELF staged into OUT_DIR by build.rs. It rides inside the
/// AlignedElf wrapper (the NIGHT-hunt-30 lesson - see embedded.rs)
/// so aya's ELF parser reads 8-aligned bytes whatever the linker
/// decided.
pub(crate) static PROBE_ELF: &[u8] =
    &embedded::AlignedElf::new(*include_bytes!(concat!(env!("OUT_DIR"), "/zejtron-ebpf.o"))).bytes;

/// Attach the probe: the privileged one-shot.
///
/// Returns a human-readable summary the doctor prints verbatim; every
/// failure is an error string that names its reason, and no failure
/// leaves a partial pin set.
pub fn attach() -> Result<String, String> {
    // 1. The gate: the same probe and the same verdict the doctor's
    //    [eBPF] section reads - one truth, no drift between surfaces.
    //    The LiveAttached shape is the idempotence case handled below.
    let facts = probe_kernel();
    vlog!(
        "engine",
        "kernel facts probed: release {}, lockdown {}, caps [CAP_BPF: {}, CAP_PERFMON: {}]",
        facts.release_label(),
        facts.lockdown.label(),
        facts.cap_bpf,
        facts.cap_perfmon
    );
    match lane_verdict(&facts) {
        LaneVerdict::Snapshot(reason) => {
            return Err(format!(
                "attach refused: {reason}. The eBPF lane needs kernel >= {} (probed: {}), \
                 lockdown inactive, and CAP_BPF + CAP_PERFMON in the effective set \
                 ({}); re-run under sudo on a capable host",
                super::floor_label(),
                facts.release_label(),
                facts.caps_label()
            ));
        }
        LaneVerdict::LiveAttached => {
            // Idempotence, proven (night-frontier-Z2): a complete pin
            // set IS attached only when its generation stamp says so
            // - same boot, same build. A foreign estate (another
            // build between attach and now, anything that left pins
            // under the one directory) refuses by name with the
            // remedy; a stamped estate is the honest already-shape.
            super::estate::verify_at_drain()?;
            let planted_mask = super::estate::read_offpath_mask()?;
            super::estate::mask_consistency_verdict(planted_mask, &|pin| {
                std::path::Path::new(pin).exists()
            })
            .map_err(|e| {
                format!(
                    "{e}. The estate's off-path mask must describe the pins exactly - \
                         the additive lanes' own law"
                )
            })?;
            let count = super::readback::read_events_counter();
            return Ok(attach_already_summary(
                &count,
                crate::output::verbose::enabled(),
            ));
        }
        LaneVerdict::Live => {
            // A partial pin set rides the same path: the pre-clean
            // below heals it.
        }
    }

    // 1.5. The offsets verification (night-improve-3): parse the
    //      struct offsets from the host's own BTF BEFORE anything is
    //      planted. A wrong hardcoded offset would read garbage
    //      silently - the loudest possible refusal is the only
    //      honest alternative, and it happens here, with zero pins
    //      touched.
    vlog!(
        "engine",
        "verifying struct offsets against the host's own BTF (/sys/kernel/btf/vmlinux)"
    );
    let offsets = btf::parse_probe_offsets().map_err(|e| {
        format!(
            "attach refused: cannot verify the struct offsets from BTF \
             ({e}). The file probes read kernel structs at offsets taken \
             from /sys/kernel/btf/vmlinux - a build without BTF cannot \
             verify them, and a guessed offset goes blind silently. \
             No probe is planted"
        )
    })?;
    // The [btf] trace (night-hunter-4): one line per resolved member,
    // the attach-time answer to "which offset did the host's BTF
    // actually vouch for". It rides the boundary, not the parser -
    // the fuzz harness path-includes btf.rs and compiles it
    // standalone, so the parser stays crate-import-free (the include
    // law in fuzz/Cargo.toml). The pair order mirrors btf.rs's
    // ProbeOffsets slots exactly; a length drift is a bug in this
    // trace table, caught before a line is printed.
    const OFF_TRACE: [(&str, &str); 13] = [
        ("dentry", "d_inode"),
        ("inode", "i_ino"),
        ("file", "f_path"),
        ("file", "f_inode"),
        ("vfsmount", "mnt_sb"),
        ("super_block", "s_dev"),
        ("path", "mnt"),
        ("path", "dentry"),
        ("task_struct", "files"),
        ("files_struct", "fdt"),
        ("fdtable", "max_fds"),
        ("fdtable", "fd"),
        ("inode", "i_sb"),
    ];
    debug_assert_eq!(OFF_TRACE.len(), offsets.len());
    for ((sname, mname), offset) in OFF_TRACE.iter().zip(offsets.iter()) {
        vlog!(
            "btf",
            "resolved struct {sname} -> {mname} at offset {offset}"
        );
    }

    // 1.6. The writev symbol verification (night-improve-42): the
    //      vectorized-write probe probes a symbol whose first argument
    //      must be a pointer to struct file. The symbol and its
    //      argument shape are read from the same host BTF, before
    //      anything is planted - the argument-position sibling of
    //      the offsets law above. A kernel that carries neither
    //      vfs_writev nor do_iter_write under a verifiable shape
    //      refuses here, by name, with zero pins touched.
    let writev_symbol = btf_writev::verify_writev_symbol().map_err(|e| {
        format!(
            "attach refused: cannot verify the vectorized-write probe's attach \
             point from BTF ({e}). The writev probe probes vfs_writev (fallback \
             do_iter_write) at its first argument, and the host's BTF must \
             vouch for that argument being a pointer to struct file - a \
             guessed argument position reads garbage silently. No probe is \
             planted"
        )
    })?;
    vlog!(
        "btf",
        "writev attach symbol verified from BTF: {writev_symbol} (arg0: struct file)"
    );

    // 1.7. The unlink/rename anchor verification (night-frontier-2):
    //      the two forensic kprobes' argument shapes are read from
    //      the same host BTF, before anything is planted - the
    //      parameter-index sibling of the offsets law above. The
    //      vfs_unlink signature churned across the floor (mnt_userns
    //      in 5.12 moved dentry from arg1 to arg2), so the dentry
    //      argument position is DERIVED per host - a signature move
    //      re-derives instead of misreading, and an unrecognizable
    //      shape refuses here, by name, with zero pins touched.
    let lane = btf_unlink::verify_unlink_lane().map_err(|e| {
        format!(
            "attach refused: cannot verify the unlink/rename probes' anchors \
             from BTF ({e}). The unlink probe reads the dentry at the argument \
             position the host's BTF vouches for, and the rename probe walks \
             renamedata.old_dentry at the member offset the same BTF vouches \
             for - a guessed position reads garbage silently. No probe is \
             planted"
        )
    })?;
    vlog!(
        "btf",
        "unlink anchor verified from BTF: vfs_unlink's struct dentry * rides \
         argument {}; rename anchor verified: renamedata.old_dentry at offset {}",
        lane.dentry_arg,
        lane.old_dentry_offset
    );

    // 1.75. The off-path lanes (night-frontier-Z7, D4): the mmap-dirty
    //       anchor ladder, the off-path offsets, and the io_uring
    //       shape, all from the same BTF blob the core parses rode.
    //       These lanes are ADDITIVE - a host that cannot vouch for a
    //       capability NAMES it down here and plants nothing for it;
    //       the core camera's five probes never depend on any of them.
    //       The hard refusals the core lanes carry (wrong-shaped
    //       symbols, missing BTF for the core walk) do not apply to
    //       the additive set: a present-but-moved io_kiocb is a
    //       named-down, not a dead camera.
    let btf_data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("attach refused: cannot read /sys/kernel/btf/vmlinux: {e}"))?;
    let dirty_anchor = match super::btf_offpath::verify_dirty_anchor_in(&btf_data) {
        Ok(anchor) => {
            vlog!(
                "btf",
                "dirty anchor verified from BTF: {symbol} (the mmap-dirty probe rides it)",
                symbol = anchor.symbol
            );
            Some(anchor)
        }
        Err(error) => {
            vlog!("btf", "mmap-dirty capability named down: {error}");
            None
        }
    };
    let offpath_offsets = match btf_offpath::parse_offpath_offsets(&btf_data) {
        Ok(offsets) => {
            vlog!(
                "btf",
                "off-path offsets verified: page.mapping {pm}, address_space.host {host},                  io_kiocb.file {file}",
                pm = offsets.page_mapping.unwrap_or(0),
                host = offsets.address_space_host.unwrap_or(0),
                file = offsets.io_kiocb_file.unwrap_or(0)
            );
            Some(offsets)
        }
        Err(error) => {
            vlog!("btf", "the off-path offsets parse named down: {error}");
            None
        }
    };
    let iouring_lane = match super::btf_offpath::verify_iouring_lane_in(&btf_data) {
        Ok(Some(lane)) => Some(lane),
        Ok(None) => {
            vlog!(
                "btf",
                "io_uring capability named down (no io_kiocb in this kernel's BTF)"
            );
            None
        }
        Err(error) => {
            vlog!("btf", "io_uring capability named down: {error}");
            None
        }
    };

    // 1.8. The mount prerequisites (night-improve-61): the tracepoint
    //      attaches resolve through tracefs and the pins live on
    //      bpffs, and a fresh server mounts NEITHER by default. The
    //      gate above already refused every host that cannot attach,
    //      so by this point a privileged process is expected - the
    //      ensure pair mounts what is missing (the bpftool precedent
    //      for pinned loads) and an unprivileged one gets the exact
    //      mount command in the refusal, not a library's "tracefs
    //      not found" after three programs were already planted.
    //      Refusals above this line touched no mount; a failure here
    //      leaves nothing behind either (the mounts are the kernel's
    //      own seats, not the pin estate).
    let tracefs_seat = super::mounts::ensure_tracefs().map_err(|e| {
        format!("attach refused: {e}. The three tracepoint probes resolve their attach points through tracefs")
    })?;
    vlog!("engine", "tracefs seat: {tracefs_seat}");
    // The io_uring tracepoint's seat (night-frontier-Z7, D4): the
    // BTF shape can vouch for the io_kiocb walk, and the event is
    // still absent on a kernel built without io_uring event tracing.
    // Availability is scanned at the attach boundary, by name.
    let iouring_seated = iouring_lane.is_some()
        && std::path::Path::new("/sys/kernel/tracing/events/io_uring/io_uring_submit_sqe").exists();
    if iouring_lane.is_some() && !iouring_seated {
        vlog!(
            "engine",
            "io_uring capability named down (the io_uring_submit_sqe tracepoint is absent on this kernel)"
        );
    }
    super::mounts::ensure_bpffs().map_err(|e| {
        format!(
            "attach refused: {e}. The probe estate pins its programs, links, and maps into bpffs"
        )
    })?;

    // 2. Self-heal: a partial pin set (a crashed attach, a manual rm)
    //    is cleaned before replanting; a stale pin directory (a prior
    //    mkdir that failed before planting) is removed the same way.
    //    Foreign entries refuse the attach - the sweep belongs to
    //    --detach (the sledgehammer); attach never deletes what it
    //    did not create.
    if any_pin_present() {
        vlog!(
            "engine",
            "partial pin set found - cleaning before replanting"
        );
        clear_pins();
    }
    match std::fs::remove_dir(PIN_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            return Err(format!(
                "{PIN_DIR} holds entries zejtron did not create - run \
                 doctor --detach (the sledgehammer: it sweeps the whole \
                 pin estate) and re-run doctor --attach"
            ));
        }
        Err(e) => {
            return Err(format!(
                "{PIN_DIR} could not be removed (is bpffs mounted?): {e}"
            ));
        }
    }

    // 3. The pin directory must exist before anything pins into it.
    vlog!("engine", "pinning the probe estate at {PIN_DIR}");
    if let Err(e) = std::fs::create_dir(PIN_DIR) {
        return Err(format!("{PIN_DIR} (is bpffs mounted?): {e}"));
    }

    // 4. The alignment preflight (the AlignedElf contract):
    //    structurally impossible now, kept so a regression diagnoses
    //    in one line.
    if let Some(violation) = embedded::alignment_violation(PROBE_ELF, "zejtron-ebpf") {
        return Err(violation);
    }

    // 6. Load the tracepoint programs and the kprobes, attach each
    //    to its point, pin everything. Any failure past this point
    //    must clean the pins it planted - the fail() protocol.
    vlog!(
        "engine",
        "loading embedded BPF object ({} bytes)",
        PROBE_ELF.len()
    );
    let mut bpf =
        Ebpf::load(PROBE_ELF).map_err(|e| fail(format!("the probe object failed to load: {e}")))?;
    vlog!("engine", "probe object loaded - planting eight programs");

    let attach_result = plant::plant(
        &mut bpf,
        writev_symbol,
        dirty_anchor.as_ref(),
        iouring_lane.as_ref().filter(|_| iouring_seated),
    );
    match attach_result {
        Ok(()) => {
            // 6.5. Write the BTF-parsed offsets through the pin - the
            //     last planted piece, and the one the whole file lane
            //     rides on. A failure here cleans everything (the
            //     fail protocol); a probe whose offsets cannot be
            //     written is a probe that must not stay planted.
            if let Err(e) = plant::write_offsets(
                &offsets,
                &lane,
                offpath_offsets.as_ref(),
                iouring_lane.as_ref().filter(|_| iouring_seated),
            ) {
                return Err(fail(e));
            }
            // 6.6. The write probe's own verification (night-improve-59):
            //     record-verify or refuse. The offsets law and the
            //     writev symbol law verify the PARSE; this verifies
            //     the RECORD - a scratch file is tracked, one write
            //     is pushed through the probe, and the drained ring
            //     must carry the scratch's own (inode, device, op).
            //     A silent anchor - the failure class that took the
            //     vfs_write kprobe on the -O3 distro builds and the
            //     stub kprobe everywhere - cannot survive this
            //     door: the attach refuses and the fail protocol
            //     takes the pins down.
            if let Err(e) = super::verify_write::verify_write_probe() {
                // The exact census verdict rides the trace: the
                // furthest-drop stage is the whole point of -v.
                vlog!("engine", "write probe self-verification failed: {e}");
                return Err(fail(e));
            }
            // The off-path record verifications (night-frontier-Z7,
            // D4): every planted capability fires its real action on
            // a tracked scratch and must see its own record back.
            // A failure is NOT an attach refusal - the capability
            // unplants and NAMING carries it (the additive lanes'
            // own law: the core camera never depends on them).
            let dirty_planted = dirty_anchor.is_some() && offpath_offsets.is_some();
            let splice_planted = true; // the sys_enter anchor is the core write probe's own
            let iouring_planted = iouring_lane.is_some() && iouring_seated;
            let verdict = super::verify_offpath::verify_offpath_probes(
                dirty_planted,
                splice_planted,
                iouring_planted,
            )
            .map_err(fail)?;
            super::estate::write_offpath_mask(verdict.mask).map_err(fail)?;
            for reason in &verdict.named_down {
                vlog!("engine", "{reason}");
            }
            let offpath_mask = verdict.mask;
            // 7. The fresh counter read: the verification battery's
            //    N=0 shape. A freshly attached counter reads zero
            //    (the kernel zeroes new maps); the readback proves
            //    the whole chain - the loader CAN read what the
            //    kernel holds. The summary the caller sees rides
            //    the verbosity lane: one quiet success line by
            //    default, the full probe/BTF/pin report under -v
            //    (the quiet-by-default law).
            let count = super::readback::read_events_counter();
            Ok(attach_success_summary(
                &count,
                writev_symbol,
                offpath_mask,
                crate::output::verbose::enabled(),
            ))
        }
        Err(e) => {
            vlog!("engine", "plant failed: {e}");
            Err(fail(e))
        }
    }
}

/// The failure protocol: clean every pin this attempt planted (never
/// half-attached), then hand the original error back. Returns the
/// error text unchanged so the caller wraps it with the cleanup
/// report.
fn fail(error: String) -> String {
    let removed = clear_pins();
    let _ = std::fs::remove_dir(PIN_DIR);
    // The prefix is load-bearing: a plant-layer failure (a kprobe the
    // host cannot attach, a verifier refusal) must read as an attach
    // refusal wherever the message lands - the suite's refusal specs
    // grep for it, and a plant error without the prefix reads as a
    // different class than it is.
    format!(
        "attach refused: {error} (cleaned {} pin(s) - nothing of zejtron remains half-attached)",
        removed
    )
}

/// Unpin everything (best-effort, idempotent). Link first - an
/// interrupted cleanup leaves a DETACHED probe. Returns the number of
/// pins actually removed.
fn clear_pins() -> usize {
    super::ALL_PINS
        .iter()
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

/// Detach the probe: unpin everything, then the sledgehammer - sweep
/// whatever else the pin directory holds (legacy pins from earlier
/// versions, foreign leftovers, partial states) and remove the
/// directory itself, so the next attach always starts fresh. The one
/// button that returns the estate to bare bpffs; no other tool or
/// manual rm is ever needed. Idempotent: if no pins exist and the
/// directory is gone, the honest "nothing to detach" (exit 0 through
/// the doctor's Ok).
pub fn detach() -> Result<String, String> {
    vlog!(
        "engine",
        "detach requested - sweeping the pin estate at {PIN_DIR}"
    );
    if !any_pin_present() && !Path::new(PIN_DIR).exists() {
        return Ok("nothing to detach - no pins present".to_owned());
    }
    let removed = clear_pins();
    // The sledgehammer step: our own pins are gone; count whatever is
    // left (legacy pin names from earlier versions, foreign files),
    // then remove the directory whole. PIN_DIR is zejtron's own
    // constant path - the one directory this tool owns - so nothing
    // outside zejtron's estate can be swept by it.
    let swept = std::fs::read_dir(PIN_DIR)
        .map(|entries| entries.filter_map(|entry| entry.ok()).count())
        .unwrap_or(0);
    match std::fs::remove_dir_all(PIN_DIR) {
        // The directory is gone (or never was): the clean end state,
        // whichever way it was reached.
        Ok(()) => {}
        // A failed remove that left nothing behind is still clean: the
        // guard is the state, not the call.
        Err(_) if !Path::new(PIN_DIR).exists() => {}
        Err(e) => {
            return Err(format!(
                "{PIN_DIR} could not be swept (is bpffs mounted?): {e}"
            ));
        }
    }
    Ok(detach_summary(
        removed,
        swept,
        crate::output::verbose::enabled(),
    ))
}

use super::summary::{attach_already_summary, attach_success_summary, detach_summary};
use std::path::Path;

#[cfg(test)]
#[path = "../../test/ebpf/loader_tests.rs"]
mod tests;
