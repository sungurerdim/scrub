//! The two stages that only look: recording what is here, and working out what
//! is the same as what.
//!
//! Both open the read-only mode before anything else. That is not politeness
//! towards the sync clients — it is what makes an accidental download
//! impossible at the kernel level rather than by remembering to be careful
//! (DR-11).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use scrub_core::analysis::Settled;
use scrub_core::artifact::{Digest, MachineId, Stage};
use scrub_core::inventory::{Entry, ScanOutcome};
use scrub_store::{Analysis, Body, Inventory};

use crate::{Pass, RunError, Watch, could_not_read, executable_here, header_for};

/// Records what is on this machine, opening and downloading nothing.
///
/// An empty `roots` means this account's home directory.
///
/// # Errors
///
/// Returns a message if the read-only mode could not be entered, if the home
/// directory could not be found, or if the providers could not be detected.
/// A place that could not be read is not an error: it is recorded as unread, so
/// what was missed is part of the answer rather than absent from it (DR-23).
pub fn scan(
    roots: &[PathBuf],
    machine: MachineId,
    watch: &mut dyn Watch,
) -> Result<Inventory, RunError> {
    // Before anything else: ask the platform to make an accidental download
    // impossible. If it refuses, the scan does not start — proceeding would risk
    // pulling someone's archive down over a metered connection (DR-11).
    let mode = scrub_platform::enter_read_only_scan_mode()
        .map_err(|error| RunError::new(error.to_string()))?;

    let home = crate::home_directory()?;
    let map = scrub_platform::detect_cloud_map(&home)
        .map_err(|error| RunError::new(error.to_string()))?;

    let roots: Vec<PathBuf> = if roots.is_empty() {
        vec![home]
    } else {
        roots.to_vec()
    };

    let mut outcome = ScanOutcome::default();
    for root in &roots {
        let found = scrub_platform::walk::walk_reporting(root, &map, &mode, &mut |state| {
            watch.walking(root, state);
        });
        watch.walked(root, &found);
        outcome.entries.extend(found.entries);
        outcome.unread.extend(found.unread);
    }

    let body = Body {
        path_encoding: scrub_core::paths::LOCAL,
        detection: scrub_core::cloud::Detection {
            roots: map.roots().to_vec(),
            links: map.links().to_vec(),
        },
        outcome,
    };

    Ok(Inventory {
        header: header_for(
            Stage::Scan,
            Vec::new(),
            machine,
            scrub_store::scope_digest(&roots),
            scrub_store::content_digest(&body, &[]),
        ),
        body,
    })
}

/// How much of an inventory to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    /// Read only files that share a size with another, which is everything a
    /// duplicate could possibly be.
    Duplicates,
    /// Read everything readable.
    ///
    /// Needed before comparing this machine with another: a file whose size
    /// nothing here shares is never read otherwise, and without a fingerprint it
    /// cannot be recognised on the other machine.
    Thorough,
}

/// Works out what is the same file as what, reading only what is already here.
///
/// # Errors
///
/// Returns a message if the read-only mode could not be entered, if the
/// inventory could not be read, if it came from another machine, or if it spells
/// paths in a way this machine cannot use.
pub fn analyze(
    inventory_path: &Path,
    machine: MachineId,
    depth: Depth,
    watch: &mut dyn Watch,
) -> Result<Analysis, RunError> {
    // Analysis reads file content, so the guard the scan starts under applies
    // here with more force (DR-11).
    let mode = scrub_platform::enter_read_only_scan_mode()
        .map_err(|error| RunError::new(error.to_string()))?;

    let inventory =
        Inventory::read(inventory_path).map_err(|error| could_not_read(inventory_path, error))?;
    executable_here(&inventory.header, machine)?;
    if !inventory.is_native() {
        return Err(RunError::new(
            "this inventory was recorded by a machine that spells paths differently, \
             so its files cannot be read here",
        ));
    }

    let entries = &inventory.body.outcome.entries;
    let parent = inventory.header.content_digest;

    let settled = run_passes(entries, &mode, depth, watch);
    let groups = scrub_core::analysis::group_duplicates(entries, &settled);
    let settled: BTreeMap<_, _> = settled.into_iter().collect();

    Ok(Analysis {
        header: header_for(
            Stage::Analyze,
            vec![parent],
            machine,
            inventory.header.scope_digest,
            scrub_store::analysis_digest(&inventory.body, &groups, &settled),
        ),
        body: inventory.body,
        groups,
        settled,
    })
}

/// How many files a given depth would read, without reading any of them.
///
/// Offered so an interface can say what it is about to do before it starts.
#[must_use]
pub fn candidates(entries: &[Entry], depth: Depth) -> Vec<usize> {
    match depth {
        Depth::Thorough => scrub_core::analysis::all_readable(entries),
        Depth::Duplicates => scrub_core::analysis::readable_candidates(entries),
    }
}

/// Reads in two passes: a little of everything, then all of what is left.
///
/// The first pass reads both ends of each candidate, which separates almost
/// everything at a fraction of the cost. Only files a sample could not tell
/// apart are read through, and only those get called identical.
fn run_passes(
    entries: &[Entry],
    mode: &scrub_platform::ScanMode,
    depth: Depth,
    watch: &mut dyn Watch,
) -> HashMap<usize, Settled> {
    let candidates = candidates(entries, depth);

    watch.pass_begins(Pass::Sampling, candidates.len());
    let sampled = read_pass(entries, &candidates, mode, Pass::Sampling, watch);
    watch.pass_ends(Pass::Sampling);

    // A file small enough to have been read through already has its content
    // digest; a larger one has only a fingerprint, which is not identity.
    let mut settled: HashMap<usize, Settled> = sampled
        .iter()
        .map(|(index, digest)| {
            let complete = entries[*index].logical_size
                <= scrub_platform::digest::SAMPLE_READS_WHOLE_FILE_UP_TO;
            let settled = if complete {
                Settled::Content(*digest)
            } else {
                Settled::DistinctBySample(*digest)
            };
            (*index, settled)
        })
        .collect();

    // Grouping on samples decides only what is worth reading in full. Treating a
    // sample as identity here is safe because nothing acts on the result; the
    // groups that survive are read through before anything is concluded.
    let provisional: HashMap<usize, Settled> = sampled
        .iter()
        .map(|(index, digest)| (*index, Settled::Content(*digest)))
        .collect();
    let confirm: Vec<usize> = scrub_core::analysis::needing_full_read(
        &scrub_core::analysis::group_duplicates(entries, &provisional),
    )
    .into_iter()
    .filter(|index| {
        entries[*index].logical_size > scrub_platform::digest::SAMPLE_READS_WHOLE_FILE_UP_TO
    })
    .collect();

    watch.pass_begins(Pass::Reading, confirm.len());
    for (index, digest) in read_pass(entries, &confirm, mode, Pass::Reading, watch) {
        settled.insert(index, Settled::Content(digest));
    }
    watch.pass_ends(Pass::Reading);

    settled
}

/// One pass over a list of files.
fn read_pass(
    entries: &[Entry],
    indices: &[usize],
    mode: &scrub_platform::ScanMode,
    pass: Pass,
    watch: &mut dyn Watch,
) -> HashMap<usize, Digest> {
    let mut digests = HashMap::with_capacity(indices.len());
    let mut bytes = 0_u64;

    for (done, index) in indices.iter().enumerate() {
        let entry = &entries[*index];
        let outcome = if pass == Pass::Sampling {
            scrub_platform::digest::quick_digest(
                &entry.path,
                &entry.cloud,
                entry.logical_size,
                mode,
            )
        } else {
            scrub_platform::digest::full_digest(&entry.path, &entry.cloud, entry.logical_size, mode)
        };
        // A refusal is not reported loudly here: the file stays unsettled, and
        // the group it belongs to says why.
        if let Ok(digest) = outcome {
            digests.insert(*index, digest);
            bytes += entry.logical_size;
        }
        watch.reading(pass, done + 1, bytes);
    }

    digests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thorough_pass_offers_more_to_read_than_a_duplicate_pass() {
        // The distinction is the whole reason `--thorough` exists: without it a
        // file whose size nothing here shares is never read, and so can never be
        // recognised on another machine.
        let place = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(place.path().join("alone.txt"), b"nothing shares my size").expect("write");
        std::fs::write(place.path().join("twin-a.txt"), b"matched").expect("write");
        std::fs::write(place.path().join("twin-b.txt"), b"matched").expect("write");

        let machine = MachineId::generate();
        let scanned = scan(&[place.path().to_path_buf()], machine, &mut crate::Silent)
            .expect("a scan of a small directory");
        let entries = &scanned.body.outcome.entries;

        let paired = candidates(entries, Depth::Duplicates);
        let everything = candidates(entries, Depth::Thorough);
        assert_eq!(paired.len(), 2, "only the twins share a size");
        assert_eq!(everything.len(), 3, "all three are readable");
    }
}
