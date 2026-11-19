// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// zejtron eBPF probe, the actor-identity helper (night-frontier-Z8,
// D5). A dedicated module under the 600-LOC no-mercy cap (the
// exits.rs/write.rs/unlink.rs precedent): the identity fill every
// record constructor shares - the cgroup id, the comm, and the
// network-namespace inode - so "who did this, and from where" rides
// every ring record without a userspace cross-lookup.
//
// THE THREE FACTS, AND WHERE EACH ONE'S TRUTH LIVES:
//
// 1. cgroup_id: `bpf_get_current_cgroup_id` - the kernfs inode
//    number of the current task's default-hierarchy cgroup, the
//    same integer stat(2) reports for the cgroup's directory on the
//    cgroupfs mount and the number a container's pod spec names.
//    The helper is UAPI-stable since 4.18, under the 5.15 kernel
//    floor: no BTF walk, no refusal class, infallible for the
//    current task.
//
// 2. comm: `bpf_get_current_comm` - TASK_COMM_LEN bytes,
//    NUL-terminated by the helper's contract, zeroed past the name
//    (the ProcExitEvent's own precedent, ebpf/src/exits.rs). A
//    failed helper read leaves the field zeroed: the host renders
//    an empty comm as the honest unnamed-actor absence, and the
//    record's core facts (what happened, to which file) stay
//    intact - a passive probe never drops evidence it already
//    holds because one auxiliary field refused.
//
// 3. netns_inum: the one fact no helper serves, so the BTF-walked
//    offsets chain earns its slots: task_struct.nsproxy ->
//    nsproxy.net_ns -> net.ns (the embedded ns_common) -> inum, every
//    offset derived from the host's own BTF at attach and refused
//    by name there when a field is absent (src/ebpf/btf.rs). The
//    result is the number readlink(2) prints in /proc/<pid>/ns/net's
//    `net:[N]` - the identity lsns names, the container boundary the
//    row can now see. Zero means the walk could not resolve on this
//    host - the named unavailability the row renders as such, never
//    a guessed namespace number.
//
// THE INLINE LAW (offpath.rs's own, found live by the C77 root leg):
// a bpf2bpf call into .text leaves an unresolved pseudo-call at
// BPF_PROG_LOAD - the 5.15 runner's verifier refused the splice
// probe with EPERM while the log stopped at instruction zero - so
// every helper here is `#[inline(always)]` and each caller carries
// its own hops in its own section. The cost table's per-program
// counts prove it.

use super::{read_ptr_at, read_u32_at};
use crate::events::{
    OFF_SLOTS, OFF_SLOT_NET_NS, OFF_SLOT_NS_COMMON_INUM, OFF_SLOT_NSPROXY_NET,
    OFF_SLOT_TASK_NSPROXY,
};

/// The actor identity one record carries: the cgroup id, the
/// network-namespace inode number, and the comm - the three facts
/// the D5 record contract appended to every FileEvent and SockEvent.
pub(crate) struct ActorIdentity {
    pub(crate) cgroup_id: u64,
    pub(crate) netns_inum: u32,
    pub(crate) comm: [u8; 16],
}

/// The netns inode walk for one task: task_struct.nsproxy ->
/// nsproxy.net_ns -> net.ns.inum, the last two hops composed into one
/// probe read (net.ns is the embedded ns_common, inum its member -
/// the sum IS the inum's own address). Every offset from the
/// BTF-verified offsets map; every hop probe-read (a bad address
/// returns None, never a fault); zero on any unresolved hop.
///
/// # Safety
/// The caller passes the current task's address and the offset set
/// the host wrote at attach; every dereference is a probe-read
/// helper call the verifier re-proves at load time.
#[inline(always)]
pub(crate) unsafe fn netns_inum_of(task: usize, o: &[u64; OFF_SLOTS as usize]) -> u32 {
    // SAFETY: every hop is a probe-read helper call (bpf_probe_read_kernel
    // beneath, a bad address returns None, never a fault) at a
    // BTF-verified offset from the attach-time map; the verifier
    // re-proves the chain at load time.
    unsafe {
        let Some(nsproxy) = read_ptr_at(task, o[OFF_SLOT_TASK_NSPROXY as usize])
            .filter(|p| *p != 0)
        else {
            return 0;
        };
        let Some(net) = read_ptr_at(nsproxy, o[OFF_SLOT_NSPROXY_NET as usize]).filter(|p| *p != 0)
        else {
            return 0;
        };
        let inum_addr = o[OFF_SLOT_NET_NS as usize] + o[OFF_SLOT_NS_COMMON_INUM as usize];
        read_u32_at(net, inum_addr).unwrap_or(0)
    }
}

/// Fill one record's identity block. `offsets` is the BTF-verified
/// set the caller already holds (the file probes) or None (the sock
/// probe, which reads no offsets on its core path and refuses no
/// record over an identity aid): with `None` the cgroup id and the
/// comm still ride (both helpers), the netns stays zero - the named
/// unavailability, never a guessed namespace number.
///
/// # Safety
/// Every helper call here is aya-ebpf's safe wrapper or an
/// infallible integer helper; the netns walk's own contract is
/// [`netns_inum_of`]'s, reached only through the caller's offset
/// set.
#[inline(always)]
pub(crate) unsafe fn actor_identity(o: Option<&[u64; OFF_SLOTS as usize]>) -> ActorIdentity {
    // SAFETY: bpf_get_current_comm is aya's safe wrapper (an
    // infallible-for-current-task helper behind a Result the code
    // below degrades honestly from); bpf_get_current_cgroup_id is a
    // pure integer helper; the netns walk rides netns_inum_of's
    // probe-read contract when the caller carries an offset set.
    unsafe {
        let mut comm = [0u8; 16];
        if let Ok(name) = aya_ebpf::helpers::bpf_get_current_comm() {
            comm = name;
        }
        let task = aya_ebpf::helpers::bpf_get_current_task() as usize;
        ActorIdentity {
            cgroup_id: aya_ebpf::helpers::bpf_get_current_cgroup_id(),
            netns_inum: match o {
                Some(o) => netns_inum_of(task, o),
                None => 0,
            },
            comm,
        }
    }
}
