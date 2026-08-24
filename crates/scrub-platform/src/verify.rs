//! Checking a plan against the filesystem, and changing nothing.
//!
//! Every function here reads. None of them writes, creates, moves or removes
//! anything, and that separation is the point: verification and execution are
//! different stages so that every problem is known before the first change is
//! made (DR-19).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use scrub_core::inventory::Entry;
use scrub_core::plan::Operation;
use scrub_core::preflight::{Expectation, Impediment, Rigour, Verdict};

use crate::{ScanMode, classify, digest, imp};
use scrub_core::cloud::CloudMap;

/// Grades every operation of a plan without touching anything.
///
/// `rigour` decides whether each subject's content is read again or only its
/// size and timestamp compared. Reading again is the default because it is the
/// only way to be certain, and this is the last look before anything moves.
#[must_use]
pub fn verify(
    operations: &[Operation],
    entries: &[Entry],
    map: &CloudMap,
    rigour: Rigour,
    mode: &ScanMode,
) -> Vec<Verdict> {
    // Directories this plan creates count as reachable, even though they are not
    // there yet: a plan that makes a folder and then moves into it is ordinary,
    // and calling that unreachable would reject the commonest thing anyone does.
    let will_exist: HashSet<&Path> = operations
        .iter()
        .filter_map(|operation| match operation {
            Operation::CreateDirectory { path } => Some(path.as_path()),
            Operation::Move { .. } | Operation::Quarantine { .. } => None,
        })
        .collect();

    let vacating: HashSet<&Path> = operations
        .iter()
        .filter_map(|operation| operation.subject().map(|subject| subject.path.as_path()))
        .collect();

    operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            grade(
                index,
                operation,
                entries,
                map,
                rigour,
                mode,
                &will_exist,
                &vacating,
            )
        })
        .collect()
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct fact the grade depends on; bundling them into a struct would hide what the decision is made from"
)]
fn grade(
    index: usize,
    operation: &Operation,
    entries: &[Entry],
    map: &CloudMap,
    rigour: Rigour,
    mode: &ScanMode,
    will_exist: &HashSet<&Path>,
    vacating: &HashSet<&Path>,
) -> Verdict {
    if let Operation::CreateDirectory { path } = operation {
        return match look(path) {
            Looked::Missing => Verdict::passing(index, rigour),
            // Already there is not a problem to solve, but it is not something
            // to report as done either; the plan asked for a directory and one
            // exists, so the operation has nothing left to do.
            Looked::Present(metadata) if metadata.is_dir() => Verdict::passing(index, rigour),
            Looked::Present(_) => Verdict::held(index, rigour, Impediment::DestinationOccupied),
            Looked::Refused(impediment) => Verdict::failed(index, rigour, impediment),
        };
    }

    let Some(subject) = operation.subject() else {
        return Verdict::passing(index, rigour);
    };

    let metadata = match look(&subject.path) {
        Looked::Present(metadata) => metadata,
        Looked::Missing => {
            return Verdict::held(index, rigour, Impediment::SourceMissing);
        }
        Looked::Refused(impediment) => return Verdict::failed(index, rigour, impediment),
    };

    // A placeholder can be moved by the provider's own client and not by us:
    // doing it behind the client's back is how a remote copy gets deleted
    // (DR-20). It also cannot be verified without downloading it (DR-11).
    let cloud = classify(map, &subject.path, &metadata);
    if cloud.residency.read_may_download() {
        return Verdict::held(index, rigour, Impediment::ContentNotPresent);
    }

    let expected = Expectation {
        logical_size: Some(subject.logical_size),
        modified_second: subject.modified.map(jiff::Timestamp::as_second),
        content: subject.content,
    };
    let mut found = Expectation {
        logical_size: Some(metadata.len()),
        modified_second: metadata
            .modified()
            .ok()
            .map(|when| scrub_core::inventory::timestamp_of(when).as_second()),
        content: None,
    };

    if expected.logical_size != found.logical_size
        || expected.modified_second != found.modified_second
    {
        return Verdict::held(index, rigour, Impediment::SourceChanged { expected, found });
    }

    if rigour == Rigour::Content && subject.content.is_some() {
        match digest::full_digest(&subject.path, &cloud, metadata.len(), mode) {
            Ok(actual) => {
                found.content = Some(actual);
                if expected.content != found.content {
                    return Verdict::held(
                        index,
                        rigour,
                        Impediment::SourceChanged { expected, found },
                    );
                }
            }
            Err(digest::ReadRefusal::WouldDownload { .. }) => {
                return Verdict::held(index, rigour, Impediment::ContentNotPresent);
            }
            Err(digest::ReadRefusal::Refused(reason)) => {
                return Verdict::failed(index, rigour, Impediment::Other(format!("{reason:?}")));
            }
        }
    }

    if let Some(destination) = operation.destination()
        && let Some(impediment) = destination_trouble(destination, will_exist, vacating)
    {
        return Verdict::held(index, rigour, impediment);
    }

    let _ = entries;
    Verdict::passing(index, rigour)
}

/// Whether a destination is free and reachable.
fn destination_trouble(
    destination: &Path,
    will_exist: &HashSet<&Path>,
    vacating: &HashSet<&Path>,
) -> Option<Impediment> {
    match look(destination) {
        // Occupied, unless the thing occupying it is itself leaving.
        Looked::Present(_) if !vacating.contains(destination) => {
            return Some(Impediment::DestinationOccupied);
        }
        Looked::Refused(impediment) => return Some(impediment),
        Looked::Present(_) | Looked::Missing => {}
    }

    let parent = destination.parent()?;
    if parent.as_os_str().is_empty() || will_exist.contains(parent) {
        return None;
    }
    match look(parent) {
        Looked::Present(metadata) if metadata.is_dir() => None,
        Looked::Present(_) | Looked::Missing => Some(Impediment::DestinationUnreachable),
        Looked::Refused(impediment) => Some(impediment),
    }
}

/// What a path turned out to be.
enum Looked {
    Present(std::fs::Metadata),
    Missing,
    Refused(Impediment),
}

/// Looks at a path without following links or opening anything.
fn look(path: &Path) -> Looked {
    // DR-11-EXEMPT: `symlink_metadata` stats the path itself, never opens it and
    // never follows a link, so it cannot trigger a download.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Looked::Present(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Looked::Missing,
        Err(error) => match imp::classify_io_error(&error) {
            scrub_core::inventory::UnreadReason::PermissionDenied => {
                Looked::Refused(Impediment::PermissionDenied)
            }
            scrub_core::inventory::UnreadReason::WouldRequireDownload => {
                Looked::Refused(Impediment::ContentNotPresent)
            }
            other => Looked::Refused(Impediment::Other(format!("{other:?}"))),
        },
    }
}

/// Where quarantined files are kept, beside the plan that set them aside.
///
/// Deliberately not a system trash: this one belongs to the tool, is never
/// emptied by anything else, and holds a record of where each file came from so
/// that undoing is a matter of reading rather than of remembering (DR-10).
#[must_use]
pub fn quarantine_beside(artifact: &Path) -> PathBuf {
    artifact.with_extension("quarantine")
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrub_core::artifact::Digest;
    use scrub_core::cloud::CloudState;
    use scrub_core::inventory::{EntryKind, timestamp_of};
    use scrub_core::plan::{Because, Subject};
    use scrub_core::preflight::Grade;

    fn entry(path: &Path, size: u64) -> Entry {
        Entry {
            path: path.to_path_buf(),
            kind: EntryKind::File,
            logical_size: size,
            allocated_size: Some(4_096),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState::not_synced(),
        }
    }

    fn subject_for(path: &Path, content: Option<Digest>) -> Subject {
        // DR-11-EXEMPT: a fixture this test created moments ago, never user data.
        let metadata = std::fs::symlink_metadata(path).expect("the fixture must exist");
        Subject {
            entry: 0,
            path: path.to_path_buf(),
            content,
            logical_size: metadata.len(),
            modified: metadata.modified().ok().map(timestamp_of),
        }
    }

    fn quarantine(path: &Path, content: Option<Digest>) -> Operation {
        Operation::Quarantine {
            subject: subject_for(path, content),
            because: Because::Requested,
        }
    }

    #[test]
    fn an_unchanged_file_passes() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("report.pdf");
        std::fs::write(&path, b"unchanged").expect("write");

        let operations = vec![quarantine(&path, Some(Digest::of(b"unchanged")))];
        let verdicts = verify(
            &operations,
            &[entry(&path, 9)],
            &CloudMap::default(),
            Rigour::Content,
            &mode,
        );

        assert_eq!(verdicts[0].grade, Grade::Pass, "{:?}", verdicts[0]);
    }

    #[test]
    fn a_file_that_changed_since_the_plan_is_held() {
        // The check the whole stage exists for. Between planning and running,
        // somebody edited the file; setting it aside now would set aside work
        // that was never accounted for.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("report.pdf");
        std::fs::write(&path, b"as planned").expect("write");

        let operations = vec![quarantine(&path, Some(Digest::of(b"as planned")))];
        std::fs::write(&path, b"edited since").expect("edit it behind the plan's back");

        let verdicts = verify(
            &operations,
            &[entry(&path, 10)],
            &CloudMap::default(),
            Rigour::Content,
            &mode,
        );
        assert_eq!(verdicts[0].grade, Grade::Hold);
        assert!(matches!(
            verdicts[0].impediment,
            Some(Impediment::SourceChanged { .. })
        ));
    }

    #[test]
    fn a_file_that_vanished_is_held_not_failed() {
        // It is a question, not a catastrophe: somebody moved it, and replanning
        // settles it.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("gone.pdf");
        std::fs::write(&path, b"here for now").expect("write");

        let operations = vec![quarantine(&path, Some(Digest::of(b"here for now")))];
        std::fs::remove_file(&path).expect("remove it");

        let verdicts = verify(
            &operations,
            &[entry(&path, 12)],
            &CloudMap::default(),
            Rigour::Content,
            &mode,
        );
        assert_eq!(verdicts[0].grade, Grade::Hold);
        assert_eq!(verdicts[0].impediment, Some(Impediment::SourceMissing));
    }

    #[test]
    fn a_destination_that_is_taken_is_held() {
        // DR-6, checked before anything runs rather than discovered by
        // overwriting something.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let from = directory.path().join("a.pdf");
        let to = directory.path().join("b.pdf");
        std::fs::write(&from, b"moving").expect("write");
        std::fs::write(&to, b"already here").expect("write");

        let operations = vec![Operation::Move {
            subject: subject_for(&from, Some(Digest::of(b"moving"))),
            destination: to.clone(),
        }];

        let verdicts = verify(
            &operations,
            &[entry(&from, 6)],
            &CloudMap::default(),
            Rigour::Content,
            &mode,
        );
        assert_eq!(verdicts[0].grade, Grade::Hold);
        assert_eq!(
            verdicts[0].impediment,
            Some(Impediment::DestinationOccupied)
        );
    }

    #[test]
    fn a_destination_the_plan_is_about_to_create_is_reachable() {
        // Making a folder and then moving into it is the commonest thing anyone
        // plans. Calling the folder unreachable because it does not exist yet
        // would reject nearly every useful plan.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let from = directory.path().join("a.pdf");
        std::fs::write(&from, b"moving").expect("write");
        let archive = directory.path().join("archive");

        let operations = vec![
            Operation::CreateDirectory {
                path: archive.clone(),
            },
            Operation::Move {
                subject: subject_for(&from, Some(Digest::of(b"moving"))),
                destination: archive.join("a.pdf"),
            },
        ];

        let verdicts = verify(
            &operations,
            &[entry(&from, 6)],
            &CloudMap::default(),
            Rigour::Content,
            &mode,
        );
        assert_eq!(verdicts[0].grade, Grade::Pass);
        assert_eq!(verdicts[1].grade, Grade::Pass, "{:?}", verdicts[1]);
    }

    #[test]
    fn a_destination_with_no_parent_at_all_is_held() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let from = directory.path().join("a.pdf");
        std::fs::write(&from, b"moving").expect("write");

        let operations = vec![Operation::Move {
            subject: subject_for(&from, Some(Digest::of(b"moving"))),
            destination: directory.path().join("nowhere/deeper/a.pdf"),
        }];

        let verdicts = verify(
            &operations,
            &[entry(&from, 6)],
            &CloudMap::default(),
            Rigour::Content,
            &mode,
        );
        assert_eq!(verdicts[0].grade, Grade::Hold);
        assert_eq!(
            verdicts[0].impediment,
            Some(Impediment::DestinationUnreachable)
        );
    }

    #[test]
    fn checking_only_metadata_still_catches_an_ordinary_edit() {
        // The fast mode is not a blind mode. An edit changes the size or the
        // timestamp or both, and that is what the great majority of drift is.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("report.pdf");
        std::fs::write(&path, b"as planned").expect("write");

        let operations = vec![quarantine(&path, Some(Digest::of(b"as planned")))];
        std::fs::write(&path, b"a longer edit than before").expect("edit");

        let verdicts = verify(
            &operations,
            &[entry(&path, 10)],
            &CloudMap::default(),
            Rigour::Metadata,
            &mode,
        );
        assert_eq!(verdicts[0].grade, Grade::Hold);
    }

    #[test]
    fn verification_leaves_the_tree_exactly_as_it_found_it() {
        // DR-19 in the most direct form available: the stage that decides
        // whether writing is safe does no writing.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("report.pdf");
        std::fs::write(&path, b"untouched").expect("write");
        let archive = directory.path().join("archive");

        let before: Vec<_> = std::fs::read_dir(directory.path())
            .expect("read")
            .flatten()
            .map(|entry| entry.path())
            .collect();

        let operations = vec![
            Operation::CreateDirectory {
                path: archive.clone(),
            },
            Operation::Move {
                subject: subject_for(&path, Some(Digest::of(b"untouched"))),
                destination: archive.join("report.pdf"),
            },
        ];
        let graded = verify(
            &operations,
            &[entry(&path, 9)],
            &CloudMap::default(),
            Rigour::Content,
            &mode,
        );
        assert_eq!(graded.len(), 2, "both operations were looked at");

        let after: Vec<_> = std::fs::read_dir(directory.path())
            .expect("read")
            .flatten()
            .map(|entry| entry.path())
            .collect();
        assert_eq!(before, after, "nothing was created, moved or removed");
        assert!(!archive.exists(), "the directory was graded, not made");
    }
}
