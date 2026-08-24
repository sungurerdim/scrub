//! Making the changes, one at a time, with a record kept as it goes.
//!
//! The only module in the project that modifies a user's filesystem. Everything
//! it does is a move: nothing is deleted, nothing is overwritten, and every
//! change is recorded before it is attempted so a run that stops part-way leaves
//! something a later run can reconcile (DR-5, DR-6, DR-7).
//!
//! Three checks stand between a graded operation and a file actually moving.
//! Preflight said it was fine; that was some time ago, and this re-checks the
//! subject at the moment of acting, because a machine somebody is using does not
//! hold still. The destination is confirmed free. And the move itself either
//! renames — which is atomic — or copies, verifies the copy by content, and only
//! then removes the original.

use std::path::{Path, PathBuf};

use scrub_core::artifact::Digest;
use scrub_core::cloud::CloudMap;
use scrub_core::journal::{Progress, Step};
use scrub_core::plan::Operation;
use scrub_core::preflight::Impediment;

use crate::{ScanMode, classify, digest, imp};

/// Where a run puts the files it sets aside, and what it has already done there.
pub struct Quarantine {
    root: PathBuf,
}

impl Quarantine {
    /// Prepares a quarantine directory.
    ///
    /// # Errors
    ///
    /// Returns the underlying error if the directory could not be made.
    pub fn at(root: PathBuf) -> Result<Self, std::io::Error> {
        // DR-11-EXEMPT: the tool's own holding area, at a path derived from the
        // artifact the user named, never a path discovered by a scan.
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Where a file would go, keeping enough of its path to tell copies apart.
    ///
    /// Two files called `notes.txt` from different folders must not collide, and
    /// the one that arrived second must not silently replace the first — which
    /// is the very failure this tool exists to prevent. The original path is
    /// rebuilt underneath the quarantine root, so the whole structure is legible
    /// and every file is where its own path says it should be.
    #[must_use]
    pub fn place_for(&self, original: &Path) -> PathBuf {
        let mut destination = self.root.clone();
        for component in original.components() {
            if let std::path::Component::Normal(part) = component {
                destination.push(part);
            }
        }
        destination
    }

    /// The directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Carries out one operation, or explains why it did not.
///
/// Returns what to record. The caller writes the intention down before calling
/// and the outcome afterwards, so a crash in between is visible rather than
/// invisible.
#[must_use]
pub fn perform(
    index: usize,
    operation: &Operation,
    quarantine: &Quarantine,
    map: &CloudMap,
    mode: &ScanMode,
) -> Step {
    let now = jiff::Timestamp::now();

    let (from, destination, content) = match operation {
        Operation::CreateDirectory { path } => {
            return match make_directory(path) {
                Ok(()) => Step {
                    operation: index,
                    progress: Progress::Done,
                    from: path.clone(),
                    // A directory that was created is undone by removing it, and
                    // that is recorded by its absence of a destination rather
                    // than by a move.
                    to: None,
                    content: None,
                    at: now,
                },
                Err(reason) => Step {
                    operation: index,
                    progress: Progress::Failed(reason),
                    from: path.clone(),
                    to: None,
                    content: None,
                    at: now,
                },
            };
        }
        Operation::Move {
            subject,
            destination,
        } => (subject.path.clone(), destination.clone(), subject.content),
        Operation::Quarantine { subject, .. } => (
            subject.path.clone(),
            quarantine.place_for(&subject.path),
            subject.content,
        ),
    };

    // Preflight said this was fine, and that was some time ago. A machine
    // somebody is using does not hold still (DR-8).
    if let Some(impediment) = still_as_expected(&from, content, map, mode) {
        return Step {
            operation: index,
            progress: Progress::Skipped(impediment),
            from,
            to: None,
            content,
            at: now,
        };
    }

    match relocate(&from, &destination, content, map, mode) {
        Ok(()) => Step {
            operation: index,
            progress: Progress::Done,
            from,
            to: Some(destination),
            content,
            at: now,
        },
        Err(Moved::Skipped(impediment)) => Step {
            operation: index,
            progress: Progress::Skipped(*impediment),
            from,
            to: None,
            content,
            at: now,
        },
        Err(Moved::Failed(reason)) => Step {
            operation: index,
            progress: Progress::Failed(reason),
            from,
            to: None,
            content,
            at: now,
        },
    }
}

/// Puts a file back where it came from.
///
/// The same machinery as moving it away, which is what makes undo ordinary
/// rather than a special path with its own bugs (DR-10).
#[must_use]
pub fn reverse(index: usize, step: &Step, map: &CloudMap, mode: &ScanMode) -> Step {
    let now = jiff::Timestamp::now();
    let Some(from) = step.to.clone() else {
        // A created directory. Removing it is only safe if it is empty, and if
        // something has since been put in it, leaving it alone is the right
        // answer rather than the cautious one.
        return match remove_empty_directory(&step.from) {
            Ok(()) => Step {
                operation: step.operation,
                progress: Progress::Done,
                from: step.from.clone(),
                to: None,
                content: None,
                at: now,
            },
            Err(reason) => Step {
                operation: step.operation,
                progress: Progress::Skipped(Impediment::Other(reason)),
                from: step.from.clone(),
                to: None,
                content: None,
                at: now,
            },
        };
    };

    let _ = index;
    match relocate(&from, &step.from, step.content, map, mode) {
        Ok(()) => Step {
            operation: step.operation,
            progress: Progress::Done,
            from,
            to: Some(step.from.clone()),
            content: step.content,
            at: now,
        },
        Err(Moved::Skipped(impediment)) => Step {
            operation: step.operation,
            progress: Progress::Skipped(*impediment),
            from,
            to: None,
            content: step.content,
            at: now,
        },
        Err(Moved::Failed(reason)) => Step {
            operation: step.operation,
            progress: Progress::Failed(reason),
            from,
            to: None,
            content: step.content,
            at: now,
        },
    }
}

/// Why a move did not happen.
///
/// Boxed because an impediment carries the two states it compared, and a large
/// error variant makes every successful call pay for the failure case.
enum Moved {
    Skipped(Box<Impediment>),
    Failed(String),
}

/// Whether the file is still the one the plan meant.
fn still_as_expected(
    path: &Path,
    content: Option<Digest>,
    map: &CloudMap,
    mode: &ScanMode,
) -> Option<Impediment> {
    // DR-11-EXEMPT: stats the path itself without opening or following it.
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Some(Impediment::SourceMissing);
        }
        Err(error) => {
            return Some(Impediment::Other(format!(
                "{:?}",
                imp::classify_io_error(&error)
            )));
        }
    };

    let cloud = classify(map, path, &metadata);
    if cloud.residency.read_may_download() {
        return Some(Impediment::ContentNotPresent);
    }

    let expected = content?;
    match digest::full_digest(path, &cloud, metadata.len(), mode) {
        Ok(actual) if actual == expected => None,
        Ok(_) => Some(Impediment::SourceChanged {
            expected: scrub_core::preflight::Expectation {
                content: Some(expected),
                ..scrub_core::preflight::Expectation::default()
            },
            found: scrub_core::preflight::Expectation::default(),
        }),
        Err(digest::ReadRefusal::WouldDownload { .. }) => Some(Impediment::ContentNotPresent),
        Err(digest::ReadRefusal::Refused(reason)) => Some(Impediment::Other(format!("{reason:?}"))),
    }
}

/// Moves a file, never over anything, and never losing it in between.
fn relocate(
    from: &Path,
    to: &Path,
    content: Option<Digest>,
    map: &CloudMap,
    mode: &ScanMode,
) -> Result<(), Moved> {
    // DR-6, checked once more at the last possible moment. Between preflight and
    // now, something may have taken the name.
    // DR-11-EXEMPT: stats a destination path without opening anything.
    if std::fs::symlink_metadata(to).is_ok() {
        return Err(Moved::Skipped(Box::new(Impediment::DestinationOccupied)));
    }

    if let Some(parent) = to.parent() {
        // DR-11-EXEMPT: creates the tool's own destination folder.
        std::fs::create_dir_all(parent).map_err(|error| {
            Moved::Failed(format!("could not make {}: {error}", parent.display()))
        })?;
    }

    // A rename within one filesystem is atomic: the file is at one path or the
    // other and never at neither.
    // DR-11-EXEMPT: the move this operation exists to perform.
    match std::fs::rename(from, to) {
        Ok(()) => return Ok(()),
        Err(error) if error.raw_os_error() == Some(CROSS_DEVICE) => {}
        Err(error) => return Err(Moved::Failed(format!("could not move: {error}"))),
    }

    // Across filesystems there is no atomic move, so: copy, prove the copy is
    // right, and only then remove the original. Losing the original before the
    // copy is verified is the one outcome that cannot be undone.
    // DR-11-EXEMPT: the copy half of the move.
    std::fs::copy(from, to).map_err(|error| Moved::Failed(format!("could not copy: {error}")))?;

    if let Some(expected) = content {
        let landed = digest::full_digest(to, &scrub_core::cloud::CloudState::not_synced(), 0, mode);
        match landed {
            Ok(actual) if actual == expected => {}
            Ok(_) | Err(_) => {
                // DR-11-EXEMPT: removing the tool's own failed copy, never the
                // original, which is still exactly where it was.
                let _ = std::fs::remove_file(to);
                return Err(Moved::Failed(
                    "the copy did not match the original, so the original was left alone"
                        .to_owned(),
                ));
            }
        }
    }
    let _ = map;

    // DR-11-EXEMPT: removes the original only after the copy has been proven
    // identical. This is the sole place the project removes a file, and it is
    // the second half of a move rather than a deletion.
    std::fs::remove_file(from).map_err(|error| {
        Moved::Failed(format!(
            "copied, but could not remove the original: {error}"
        ))
    })
}

/// `EXDEV`, "cross-device link", the error a rename gives across filesystems.
#[cfg(unix)]
const CROSS_DEVICE: i32 = 18;
/// `ERROR_NOT_SAME_DEVICE`, the Windows equivalent.
#[cfg(windows)]
const CROSS_DEVICE: i32 = 17;

fn make_directory(path: &Path) -> Result<(), String> {
    // DR-11-EXEMPT: creates a directory the plan asked for at a path the user
    // approved.
    std::fs::create_dir_all(path).map_err(|error| format!("could not create: {error}"))
}

fn remove_empty_directory(path: &Path) -> Result<(), String> {
    // DR-11-EXEMPT: removes only an empty directory this run created. A
    // directory somebody has since put something in is left alone, which is why
    // this is `remove_dir` and never `remove_dir_all`.
    std::fs::remove_dir(path).map_err(|error| format!("left in place: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrub_core::plan::{Because, Subject};

    fn quarantine_in(directory: &Path) -> Quarantine {
        Quarantine::at(directory.join("quarantine")).expect("a quarantine directory")
    }

    fn subject_for(path: &Path) -> Subject {
        let metadata = std::fs::symlink_metadata(path).expect("the fixture must exist");
        let content = std::fs::read(path).expect("read the fixture");
        Subject {
            entry: 0,
            path: path.to_path_buf(),
            content: Some(Digest::of(&content)),
            logical_size: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .map(scrub_core::inventory::timestamp_of),
        }
    }

    #[test]
    fn setting_a_file_aside_moves_it_and_keeps_it() {
        // The whole promise in one test: the file leaves its place and is still
        // there afterwards, byte for byte (DR-5).
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("copy.pdf");
        std::fs::write(&path, b"a redundant copy").expect("write");

        let quarantine = quarantine_in(directory.path());
        let operation = Operation::Quarantine {
            subject: subject_for(&path),
            because: Because::Requested,
        };

        let step = perform(0, &operation, &quarantine, &CloudMap::default(), &mode);
        assert_eq!(step.progress, Progress::Done, "{step:?}");
        assert!(!path.exists(), "it left its place");

        let landed = step.to.as_ref().expect("it went somewhere");
        assert_eq!(
            std::fs::read(landed).expect("read it back"),
            b"a redundant copy",
            "and arrived intact"
        );
    }

    #[test]
    fn a_file_that_changed_since_preflight_is_left_alone() {
        // The last check, at the moment of acting. Preflight was some time ago.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("copy.pdf");
        std::fs::write(&path, b"as planned").expect("write");

        let operation = Operation::Quarantine {
            subject: subject_for(&path),
            because: Because::Requested,
        };
        std::fs::write(&path, b"edited in the meantime").expect("edit");

        let quarantine = quarantine_in(directory.path());
        let step = perform(0, &operation, &quarantine, &CloudMap::default(), &mode);

        assert!(matches!(step.progress, Progress::Skipped(_)), "{step:?}");
        assert!(path.exists(), "and it is still exactly where it was");
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"edited in the meantime"
        );
    }

    #[test]
    fn two_files_with_one_name_do_not_collide_in_quarantine() {
        // The failure the user described from doing this by hand, in the one
        // place it would be easiest to reintroduce: two `notes.txt` from
        // different folders, the second silently replacing the first.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir_all(directory.path().join("one")).expect("mkdir");
        std::fs::create_dir_all(directory.path().join("two")).expect("mkdir");

        let first = directory.path().join("one/notes.txt");
        let second = directory.path().join("two/notes.txt");
        std::fs::write(&first, b"the first one").expect("write");
        std::fs::write(&second, b"the second one").expect("write");

        let quarantine = quarantine_in(directory.path());
        for path in [&first, &second] {
            let operation = Operation::Quarantine {
                subject: subject_for(path),
                because: Because::Requested,
            };
            let step = perform(0, &operation, &quarantine, &CloudMap::default(), &mode);
            assert_eq!(step.progress, Progress::Done, "{step:?}");
        }

        let landed_first = quarantine.place_for(&first);
        let landed_second = quarantine.place_for(&second);
        assert_ne!(landed_first, landed_second);
        assert_eq!(
            std::fs::read(&landed_first).expect("read"),
            b"the first one"
        );
        assert_eq!(
            std::fs::read(&landed_second).expect("read"),
            b"the second one"
        );
    }

    #[test]
    fn nothing_is_moved_onto_something_already_there() {
        // DR-6, checked once more at the last possible moment.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let from = directory.path().join("a.pdf");
        let to = directory.path().join("b.pdf");
        std::fs::write(&from, b"moving").expect("write");
        std::fs::write(&to, b"already here").expect("write");

        let operation = Operation::Move {
            subject: subject_for(&from),
            destination: to.clone(),
        };
        let quarantine = quarantine_in(directory.path());
        let step = perform(0, &operation, &quarantine, &CloudMap::default(), &mode);

        assert_eq!(
            step.progress,
            Progress::Skipped(Impediment::DestinationOccupied)
        );
        assert_eq!(
            std::fs::read(&to).expect("read"),
            b"already here",
            "what was there is untouched"
        );
        assert!(from.exists(), "and what was moving is still where it was");
    }

    #[test]
    fn a_move_can_be_undone_exactly() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("copy.pdf");
        std::fs::write(&path, b"went away and came back").expect("write");

        let quarantine = quarantine_in(directory.path());
        let operation = Operation::Quarantine {
            subject: subject_for(&path),
            because: Because::Requested,
        };

        let forward = perform(0, &operation, &quarantine, &CloudMap::default(), &mode);
        assert_eq!(forward.progress, Progress::Done);
        assert!(!path.exists());

        let back = reverse(0, &forward, &CloudMap::default(), &mode);
        assert_eq!(back.progress, Progress::Done, "{back:?}");
        assert_eq!(
            std::fs::read(&path).expect("read it back"),
            b"went away and came back"
        );
    }

    #[test]
    fn undoing_refuses_to_put_a_file_back_onto_another() {
        // Somebody made a new file with the old name while the original was
        // quarantined. Putting it back would destroy their work, which is the
        // one thing undo must never do.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("copy.pdf");
        std::fs::write(&path, b"the original").expect("write");

        let quarantine = quarantine_in(directory.path());
        let operation = Operation::Quarantine {
            subject: subject_for(&path),
            because: Because::Requested,
        };
        let forward = perform(0, &operation, &quarantine, &CloudMap::default(), &mode);
        assert_eq!(forward.progress, Progress::Done);

        std::fs::write(&path, b"something new with the same name").expect("write");

        let back = reverse(0, &forward, &CloudMap::default(), &mode);
        assert_eq!(
            back.progress,
            Progress::Skipped(Impediment::DestinationOccupied)
        );
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"something new with the same name",
            "the newer file is untouched"
        );
    }

    #[test]
    fn a_directory_somebody_has_used_is_not_removed_by_undo() {
        // Undo removes what it made, not what has happened since.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let made = directory.path().join("archive");

        let quarantine = quarantine_in(directory.path());
        let step = perform(
            0,
            &Operation::CreateDirectory { path: made.clone() },
            &quarantine,
            &CloudMap::default(),
            &mode,
        );
        assert_eq!(step.progress, Progress::Done);

        std::fs::write(made.join("someone-elses.txt"), b"put here since").expect("write");

        let back = reverse(0, &step, &CloudMap::default(), &mode);
        assert!(matches!(back.progress, Progress::Skipped(_)), "{back:?}");
        assert!(
            made.join("someone-elses.txt").exists(),
            "and it is still there"
        );
    }
}
