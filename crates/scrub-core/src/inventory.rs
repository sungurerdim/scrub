//! What a scan records about each thing it finds.
//!
//! These are the rows of the inventory artifact. Everything here comes from
//! metadata: no file is opened, no content is read, and nothing a provider would
//! have to fetch is touched (DR-11). Content digests belong to the analyze
//! stage, which decides separately what is worth reading.

use std::path::PathBuf;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::cloud::CloudState;

/// What kind of thing was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// An ordinary file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link. Recorded, never followed (DR-22).
    Symlink,
    /// A socket, device, pipe, or anything else that is not user data.
    Other,
}

/// The filesystem's own identity for an object.
///
/// Two paths sharing a file identity are the same bytes on disk — a hard link or
/// a clone — not two copies. Deleting one frees nothing, so this is what keeps
/// the capacity figures honest (DR-16). It is an identity *within one machine*
/// and one filesystem; it never travels between machines, and it never
/// participates in deciding whether two files have the same content (DR-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId {
    /// The filesystem the object lives on.
    pub volume: u64,
    /// The object's identity within that filesystem.
    pub index: u64,
}

/// One thing a scan found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Where it is. Absolute, and exactly as the filesystem spelled it.
    pub path: PathBuf,
    /// What it is.
    pub kind: EntryKind,
    /// The size the filesystem reports.
    ///
    /// For a file whose content lives with a provider this is the full size of
    /// the content that is *not* here — which is the entire difficulty this tool
    /// exists to handle.
    pub logical_size: u64,
    /// The space actually occupied on this disk, where the platform reports it.
    ///
    /// `None` on platforms where it is not available without opening the file.
    /// Where present, the gap between this and `logical_size` is what separates
    /// a real file from a placeholder, and a clone from a copy.
    pub allocated_size: Option<u64>,
    /// When the filesystem says it was created.
    pub created: Option<Timestamp>,
    /// When the filesystem says it last changed.
    pub modified: Option<Timestamp>,
    /// The filesystem's identity for the object.
    pub file_id: Option<FileId>,
    /// How many names refer to these same bytes.
    ///
    /// Greater than one means deleting this path frees nothing.
    pub link_count: u64,
    /// For a symbolic link, where it points — recorded verbatim, never followed.
    pub link_target: Option<PathBuf>,
    /// Its relationship to any sync provider.
    pub cloud: CloudState,
}

/// Why a place could not be looked into.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnreadReason {
    /// The operating system refused access.
    PermissionDenied,
    /// The content lives with a provider and reading it would download it.
    ///
    /// On macOS the kernel reports this as `EDEADLK` while the scan runs under
    /// the no-materialization policy: the directory exists, it has contents, and
    /// finding out what they are costs a download.
    WouldRequireDownload,
    /// It disappeared between being listed and being examined.
    Vanished,
    /// Something else, reported verbatim.
    Other(String),
}

/// A place the scan could not look into.
///
/// Recorded so that no total silently absorbs it (DR-23). "I could not look
/// inside" and "there is nothing inside" lead to opposite decisions, and only
/// one of them is ever true.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unread {
    /// What could not be read.
    pub path: PathBuf,
    /// Why not.
    pub reason: UnreadReason,
}

/// What a scan produced.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOutcome {
    /// Everything found.
    pub entries: Vec<Entry>,
    /// Everywhere that could not be looked into.
    pub unread: Vec<Unread>,
}

impl ScanOutcome {
    /// Whether the scan saw everything it was asked to see.
    ///
    /// A complete scan and an incomplete one support very different claims. Any
    /// figure derived from an incomplete scan carries this alongside it.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unread.is_empty()
    }

    /// Bytes that would actually be freed by removing every entry once.
    ///
    /// Counts each set of shared bytes a single time and skips content that is
    /// not on this disk, so it never promises space that removal would not
    /// return (DR-16).
    #[must_use]
    pub fn reclaimable_bytes(&self) -> u64 {
        let mut seen = std::collections::HashSet::new();
        self.entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
            .filter(|entry| entry.file_id.is_none_or(|id| seen.insert(id)))
            .filter_map(|entry| entry.allocated_size)
            .sum()
    }
}

/// Converts a platform timestamp, keeping dates before 1970 orderable.
///
/// Scanned archives really do contain files dated before 1970, almost always
/// from a clock that was wrong when they were written. Clamping them all to the
/// epoch would make them indistinguishable from one another, and the timestamp
/// is how the user decides which copy of a duplicate to keep.
#[must_use]
pub fn timestamp_of(time: std::time::SystemTime) -> Timestamp {
    let (seconds, before_epoch) = match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => (since.as_secs(), false),
        Err(error) => (error.duration().as_secs(), true),
    };

    let seconds = i64::try_from(seconds).unwrap_or(i64::MAX);
    let seconds = if before_epoch { -seconds } else { seconds };
    Timestamp::from_second(seconds).unwrap_or(Timestamp::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::{CloudState, Provider, Residency, Retention};

    fn file(path: &str, allocated: Option<u64>, id: Option<(u64, u64)>, links: u64) -> Entry {
        Entry {
            path: PathBuf::from(path),
            kind: EntryKind::File,
            logical_size: 1_000,
            allocated_size: allocated,
            created: None,
            modified: None,
            file_id: id.map(|(volume, index)| FileId { volume, index }),
            link_count: links,
            link_target: None,
            cloud: CloudState::not_synced(),
        }
    }

    #[test]
    fn shared_bytes_are_counted_once() {
        // Two hard links to the same bytes. Removing both frees 4 KiB, not 8 —
        // and a tool that says 8 has lied about the only number the user cares
        // about when deciding whether the cleanup was worth it.
        let outcome = ScanOutcome {
            entries: vec![
                file("/a/report.pdf", Some(4_096), Some((1, 42)), 2),
                file("/b/report.pdf", Some(4_096), Some((1, 42)), 2),
            ],
            unread: Vec::new(),
        };
        assert_eq!(outcome.reclaimable_bytes(), 4_096);
    }

    #[test]
    fn distinct_files_are_counted_separately() {
        let outcome = ScanOutcome {
            entries: vec![
                file("/a/one.pdf", Some(4_096), Some((1, 42)), 1),
                file("/a/two.pdf", Some(8_192), Some((1, 43)), 1),
            ],
            unread: Vec::new(),
        };
        assert_eq!(outcome.reclaimable_bytes(), 12_288);
    }

    #[test]
    fn content_that_is_not_on_this_disk_promises_nothing() {
        // A cloud placeholder reports its full logical size while occupying no
        // space here. Counting it would promise gigabytes that deleting cannot
        // return, because they were never on this machine.
        let mut placeholder = file("/cloud/video.mov", Some(0), Some((1, 44)), 1);
        placeholder.logical_size = 8_000_000_000;
        placeholder.cloud = CloudState {
            provider: Some(Provider::ICloud),
            residency: Residency::Remote,
            retention: Retention::Unspecified,
        };

        let outcome = ScanOutcome {
            entries: vec![placeholder],
            unread: Vec::new(),
        };
        assert_eq!(outcome.reclaimable_bytes(), 0);
    }

    #[test]
    fn a_platform_that_cannot_report_allocation_promises_nothing() {
        // Better to under-report than to invent a figure from logical size.
        let outcome = ScanOutcome {
            entries: vec![file("/a/one.pdf", None, Some((1, 42)), 1)],
            unread: Vec::new(),
        };
        assert_eq!(outcome.reclaimable_bytes(), 0);
    }

    #[test]
    fn directories_do_not_contribute() {
        let mut directory = file("/a", Some(4_096), Some((1, 9)), 1);
        directory.kind = EntryKind::Directory;
        let outcome = ScanOutcome {
            entries: vec![directory],
            unread: Vec::new(),
        };
        assert_eq!(outcome.reclaimable_bytes(), 0);
    }

    #[test]
    fn a_timestamp_before_the_epoch_keeps_its_sign() {
        // The failure this guards: two files dated 1965 and 1969 both collapsing
        // to 1970, so "keep the oldest" picks arbitrarily between them.
        let epoch = std::time::UNIX_EPOCH;
        let older = epoch - std::time::Duration::from_secs(200_000_000);
        let newer = epoch - std::time::Duration::from_secs(100_000_000);
        assert!(timestamp_of(older) < timestamp_of(newer));
        assert!(timestamp_of(newer) < timestamp_of(epoch));
    }

    #[test]
    fn an_ordinary_timestamp_round_trips() {
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(timestamp_of(when).as_second(), 1_700_000_000);
    }

    #[test]
    fn a_date_beyond_the_calendar_falls_back_instead_of_panicking() {
        // Filesystems really do carry dates tens of thousands of years out,
        // usually from a corrupt entry or a dead clock battery. A scan of a
        // hundred thousand files must not die on one of them.
        let far = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(1 << 40))
            .expect("a far future instant the platform can represent");
        assert_eq!(timestamp_of(far), Timestamp::UNIX_EPOCH);
    }

    #[test]
    fn an_unread_place_makes_the_scan_incomplete() {
        // DR-23. Every figure drawn from this scan has to say so.
        let outcome = ScanOutcome {
            entries: vec![file("/a/one.pdf", Some(4_096), Some((1, 42)), 1)],
            unread: vec![Unread {
                path: PathBuf::from("/a/locked"),
                reason: UnreadReason::PermissionDenied,
            }],
        };
        assert!(!outcome.is_complete());
        assert!(ScanOutcome::default().is_complete());
    }
}
