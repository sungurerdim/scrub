//! Traversal: the only place in the project that walks a user's filesystem.
//!
//! Three properties matter more than speed here.
//!
//! **Nothing is opened.** Every fact comes from a symlink-preserving stat. A
//! file's content is never touched, so a scan cannot download anything and
//! cannot change a timestamp (DR-11).
//!
//! **Symbolic links are recorded, never followed** (DR-22). This prevents three
//! separate failures at once: counting the same bytes once per link, looping
//! forever on a cycle, and — the one that loses files — reporting an
//! unsynchronized folder as backed up because a link to it sits inside a cloud
//! directory.
//!
//! **A place we could not read is never reported as empty** (DR-23). Permission
//! refusals and cloud-only directories are recorded with their reason and
//! carried through to every figure derived from the scan.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use scrub_core::cloud::CloudMap;
use scrub_core::inventory::{Entry, EntryKind, ScanOutcome, Unread, UnreadReason};

use crate::{ScanMode, classify, imp};

/// Walks `root`, recording metadata and reading nothing.
///
/// Requires a [`ScanMode`] by reference: the only way to obtain one is
/// [`crate::enter_read_only_scan_mode`], so traversal cannot begin without the
/// platform having been asked to forbid downloads first.
#[must_use]
pub fn walk(root: &Path, map: &CloudMap, _mode: &ScanMode) -> ScanOutcome {
    let mut outcome = ScanOutcome::default();
    let mut queue = VecDeque::from([root.to_path_buf()]);

    // Breadth-first with an explicit queue rather than recursion: a deep tree,
    // or a directory structure built to be deep, must not exhaust the stack.
    while let Some(directory) = queue.pop_front() {
        let children = match read_children(&directory) {
            Ok(children) => children,
            Err(reason) => {
                outcome.unread.push(Unread {
                    path: directory,
                    reason,
                });
                continue;
            }
        };

        for path in children {
            match entry_for(&path, map) {
                Ok(entry) => {
                    // Descend only into real directories. A symbolic link to a
                    // directory is recorded as a link and left alone.
                    if entry.kind == EntryKind::Directory {
                        queue.push_back(path);
                    }
                    outcome.entries.push(entry);
                }
                Err(reason) => outcome.unread.push(Unread { path, reason }),
            }
        }
    }

    outcome
}

/// Lists a directory's children without following anything.
fn read_children(directory: &Path) -> Result<Vec<PathBuf>, UnreadReason> {
    // DR-11-EXEMPT: enumeration reads directory entries, never file content.
    // Under the read-only scan mode this call reports an error rather than
    // materializing a cloud-only directory, and that error is what becomes the
    // `unread` record instead of a false "empty".
    let entries = std::fs::read_dir(directory).map_err(|error| imp::classify_io_error(&error))?;

    let mut children = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => children.push(entry.path()),
            // One unreadable entry does not abandon its siblings, but it is not
            // silently dropped either: the directory is still listed, and the
            // entry we could not name is recorded against it.
            Err(error) => return Err(imp::classify_io_error(&error)),
        }
    }
    Ok(children)
}

/// Records one path from its metadata alone.
fn entry_for(path: &Path, map: &CloudMap) -> Result<Entry, UnreadReason> {
    // DR-11-EXEMPT: `symlink_metadata` stats the path itself and never opens it
    // or follows a link, so it cannot trigger a download.
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| imp::classify_io_error(&error))?;

    let kind = if metadata.is_symlink() {
        EntryKind::Symlink
    } else if metadata.is_dir() {
        EntryKind::Directory
    } else if metadata.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };

    let link_target = if kind == EntryKind::Symlink {
        // DR-11-EXEMPT: returns the stored target string; the target itself is
        // never touched.
        std::fs::read_link(path).ok()
    } else {
        None
    };

    Ok(Entry {
        path: path.to_path_buf(),
        kind,
        logical_size: metadata.len(),
        allocated_size: imp::allocated_size(&metadata),
        created: metadata
            .created()
            .ok()
            .map(scrub_core::inventory::timestamp_of),
        modified: metadata
            .modified()
            .ok()
            .map(scrub_core::inventory::timestamp_of),
        file_id: imp::file_id(&metadata),
        link_count: imp::link_count(&metadata),
        link_target,
        cloud: classify(map, path, &metadata),
    })
}

/// Maps an unrecognised error to a reason that repeats it verbatim.
#[must_use]
pub(crate) fn other_reason(error: &std::io::Error) -> UnreadReason {
    UnreadReason::Other(error.to_string())
}
