//! The two stages that only look: recording what is here, and working out what
//! is the same as what.
//!
//! Both open the read-only mode before anything else. That is not politeness
//! towards the sync clients — it is what makes an accidental download
//! impossible at the kernel level rather than by remembering to be careful
//! (DR-11).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

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

/// Below this many files, one thread does it.
///
/// Spawning costs more than it saves on a handful of files, and the tests are
/// full of handfuls.
const WORTH_SHARING_OUT: usize = 64;

/// How often the progress of a shared-out pass is reported.
const LOOK_IN_EVERY: Duration = Duration::from_millis(80);

/// One pass over a list of files, shared across threads.
///
/// Reading is where the time goes, and it is spent waiting on a disk rather than
/// on a processor: the single-threaded pass measured 31% of one core over two
/// minutes. Several threads waiting at once turn most of that into overlap.
///
/// This is safe only because the kernel policy that forbids downloads is set on
/// the *process*, not on the thread that set it — `setiopolicy_np(3)` says a
/// thread which has set nothing of its own follows the process policy, and that
/// was measured rather than assumed (see `docs/VERIFICATION.md`). Were it
/// otherwise, every worker here would be an unprotected reader.
///
/// The answer does not depend on how the work was divided: each file's digest is
/// a function of that file, and the results are gathered into a map with no
/// order of its own (DR-12).
fn read_pass(
    entries: &[Entry],
    indices: &[usize],
    mode: &scrub_platform::ScanMode,
    pass: Pass,
    watch: &mut dyn Watch,
) -> HashMap<usize, Digest> {
    let hands = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    if hands <= 1 || indices.len() < WORTH_SHARING_OUT {
        let mut digests = HashMap::with_capacity(indices.len());
        let mut bytes = 0_u64;
        for (done, index) in indices.iter().enumerate() {
            if let Some(digest) = read_one(&entries[*index], pass, mode) {
                digests.insert(*index, digest);
                bytes += entries[*index].logical_size;
            }
            watch.reading(pass, done + 1, bytes);
        }
        return digests;
    }

    let taken = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let bytes = AtomicU64::new(0);
    // Counted down as each worker leaves, including one that leaves by
    // panicking. Without it, a panic before the last increment would leave the
    // loop below waiting for progress that is never coming.
    let working = AtomicUsize::new(hands);

    let gathered: Vec<Vec<(usize, Digest)>> = std::thread::scope(|scope| {
        let hired: Vec<_> = (0..hands)
            .map(|_| {
                scope.spawn(|| {
                    let _leaving = Leaving(&working);
                    let mut mine = Vec::new();
                    loop {
                        let next = taken.fetch_add(1, Ordering::Relaxed);
                        let Some(index) = indices.get(next) else {
                            break;
                        };
                        let entry = &entries[*index];
                        // A refusal is not reported loudly: the file stays
                        // unsettled, and the group it belongs to says why.
                        if let Some(digest) = read_one(entry, pass, mode) {
                            mine.push((*index, digest));
                            bytes.fetch_add(entry.logical_size, Ordering::Relaxed);
                        }
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                    mine
                })
            })
            .collect();

        while working.load(Ordering::Relaxed) > 0 {
            watch.reading(
                pass,
                done.load(Ordering::Relaxed),
                bytes.load(Ordering::Relaxed),
            );
            std::thread::sleep(LOOK_IN_EVERY);
        }

        hired
            .into_iter()
            .map(|worker| {
                // A worker only panics on a bug. Carrying the panic out keeps it
                // a crash somebody investigates rather than a quietly short
                // answer that looks like a clean run.
                worker
                    .join()
                    .unwrap_or_else(|reason| std::panic::resume_unwind(reason))
            })
            .collect()
    });

    watch.reading(
        pass,
        done.load(Ordering::Relaxed),
        bytes.load(Ordering::Relaxed),
    );
    gathered.into_iter().flatten().collect()
}

/// Marks a worker as gone, however it goes.
struct Leaving<'a>(&'a AtomicUsize);

impl Drop for Leaving<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Reads one file, as much of it as this pass calls for.
fn read_one(entry: &Entry, pass: Pass, mode: &scrub_platform::ScanMode) -> Option<Digest> {
    let outcome = if pass == Pass::Sampling {
        scrub_platform::digest::quick_digest(&entry.path, &entry.cloud, entry.logical_size, mode)
    } else {
        scrub_platform::digest::full_digest(&entry.path, &entry.cloud, entry.logical_size, mode)
    };
    outcome.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_the_reading_out_does_not_change_the_answer() {
        // Reading is spread across threads, and the order files come back in
        // depends on how the operating system felt at that moment. The answer
        // must not (DR-12) — an analysis that differed run to run would make
        // the artifact undiffable and every review of it worthless.
        //
        // The tree is deliberately over the threshold at which the work is
        // shared out, so this exercises the path that has threads in it.
        let place = tempfile::tempdir().expect("a temporary directory");
        let root = place.path();
        for shape in 0..40 {
            let body = format!("body number {shape}").repeat(20);
            // Three copies of each, so grouping has something to group.
            for copy in 0..3 {
                std::fs::write(root.join(format!("shape{shape}-copy{copy}.txt")), &body)
                    .expect("write");
            }
        }
        assert!(
            std::fs::read_dir(root).expect("read").count() > WORTH_SHARING_OUT,
            "the fixture has to be big enough to be shared out"
        );

        let workspace = tempfile::tempdir().expect("somewhere for the artifacts");
        let machine = MachineId::generate();
        let inventory = scan(&[root.to_path_buf()], machine, &mut crate::Silent).expect("a scan");
        let recorded = workspace.path().join("fixture.inventory");
        inventory
            .write(&recorded, scrub_store::Replace::Never)
            .expect("the inventory writes");

        let once = analyze(&recorded, machine, Depth::Duplicates, &mut crate::Silent)
            .expect("an analysis");
        let twice = analyze(&recorded, machine, Depth::Duplicates, &mut crate::Silent)
            .expect("a second analysis of the same thing");

        assert_eq!(
            once.header.content_digest, twice.header.content_digest,
            "the same inventory read twice has to come to the same answer"
        );
        assert_eq!(once.settled, twice.settled, "down to every single file");
        assert_eq!(once.groups.len(), 40, "forty sets of three");
    }

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
