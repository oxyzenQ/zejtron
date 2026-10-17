// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! proc's forest algebra (night-improve-18: the 600-line
//! no-mercy cap's split - one concern, one module). Pure move
//! from src/commands/proc.rs: building the process forest from
//! a flat scan, match pruning with ancestor/descendant
//! inclusion, and depth limiting. `super::` is the proc module.

use super::{Process, ProcessForest};
use std::collections::{BTreeMap, BTreeSet};

pub fn build_forest(processes: Vec<Process>) -> ProcessForest {
    let processes: BTreeMap<u32, Process> = processes
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let process_ids: BTreeSet<u32> = processes.keys().copied().collect();
    let mut roots = Vec::new();
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();

    for process in processes.values() {
        if process.ppid != process.pid && process_ids.contains(&process.ppid) {
            children.entry(process.ppid).or_default().push(process.pid);
        } else {
            roots.push(process.pid);
        }
    }

    for child_ids in children.values_mut() {
        child_ids.sort_unstable();
    }
    roots.sort_unstable();

    ProcessForest {
        processes,
        roots,
        children,
    }
}

pub fn matching_process_ids(forest: &ProcessForest, pattern: &str) -> BTreeSet<u32> {
    let pattern = pattern.to_lowercase();
    forest
        .processes
        .values()
        .filter(|process| process.name.to_lowercase().contains(&pattern))
        .map(|process| process.pid)
        .collect()
}

pub fn prune_for_matches(forest: &ProcessForest, matches: &BTreeSet<u32>) -> ProcessForest {
    let mut included = BTreeSet::new();

    for pid in matches {
        include_ancestors(forest, *pid, &mut included);
        include_descendants(forest, *pid, &mut included);
    }

    forest_from_ids(forest, &included)
}

pub fn limit_depth(forest: &ProcessForest, max_depth: Option<usize>) -> ProcessForest {
    let Some(max_depth) = max_depth else {
        return forest.clone();
    };

    if max_depth == 0 {
        return build_forest(Vec::new());
    }

    let mut included = BTreeSet::new();
    for root in &forest.roots {
        include_to_depth(forest, *root, 1, max_depth, &mut included);
    }

    forest_from_ids(forest, &included)
}

pub(super) fn include_ancestors(forest: &ProcessForest, pid: u32, included: &mut BTreeSet<u32>) {
    let mut current_pid = pid;
    while let Some(process) = forest.processes.get(&current_pid) {
        included.insert(process.pid);
        if process.ppid == process.pid || !forest.processes.contains_key(&process.ppid) {
            break;
        }
        current_pid = process.ppid;
    }
}

pub(super) fn include_descendants(forest: &ProcessForest, pid: u32, included: &mut BTreeSet<u32>) {
    included.insert(pid);

    if let Some(children) = forest.children.get(&pid) {
        for child in children {
            include_descendants(forest, *child, included);
        }
    }
}

pub(super) fn include_to_depth(
    forest: &ProcessForest,
    pid: u32,
    depth: usize,
    max_depth: usize,
    included: &mut BTreeSet<u32>,
) {
    if depth > max_depth || !included.insert(pid) {
        return;
    }

    if let Some(children) = forest.children.get(&pid) {
        for child in children {
            include_to_depth(forest, *child, depth + 1, max_depth, included);
        }
    }
}

pub(super) fn forest_from_ids(forest: &ProcessForest, included: &BTreeSet<u32>) -> ProcessForest {
    build_forest(
        included
            .iter()
            .filter_map(|pid| forest.processes.get(pid).cloned())
            .collect(),
    )
}
