//! Reading file content, and refusing to when reading would cost something.
//!
//! The only place in the project that opens a user's file. Two guards stand in
//! front of every open: the caller must have established that the content is on
//! this machine, and on macOS the process is running under a kernel policy that
//! turns an accidental read of cloud-held content into an error rather than a
//! download (DR-11).
//!
//! Reading is done in two passes, because reading everything is the expensive
//! way to learn what sizes already ruled out. A quick digest reads the two ends
//! of a file; only files whose ends and size agree are read in full. Two large
//! files that merely happen to share a size cost a few kilobytes to separate
//! instead of their whole length.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use scrub_core::artifact::Digest;
use scrub_core::cloud::CloudState;
use scrub_core::inventory::UnreadReason;

use crate::{ScanMode, imp};

/// How much of each end a sample reads.
///
/// Large enough that two different files sharing a size are almost certainly
/// separated by it, small enough that doing it to every candidate is cheap.
const END_BYTES: u64 = 64 * 1024;

/// The size at or below which a sample reads the whole file.
///
/// Seeking around a file this small costs more than reading it, so the sample
/// reads it through — and therefore *is* its content digest, indistinguishable
/// from what a full read would produce. That matters beyond saving a pass:
/// comparing two machines needs a content digest for every file, and for
/// everything under this size the sampling pass has already produced one.
pub const SAMPLE_READS_WHOLE_FILE_UP_TO: u64 = END_BYTES * 2;

/// Why content could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadRefusal {
    /// The content is not on this machine and reading it would fetch it.
    ///
    /// Not an error in the ordinary sense: it is the tool declining to spend the
    /// user's bandwidth without being asked.
    #[error("content lives with a sync provider; reading it would download {bytes} bytes")]
    WouldDownload {
        /// What reading it would pull down.
        bytes: u64,
    },

    /// The system would not let us read it.
    #[error("could not read content: {0:?}")]
    Refused(UnreadReason),
}

/// A digest of the two ends of a file and its length.
///
/// Cheap, and enough to separate almost all files that merely share a size.
/// Never treated as identity on its own: a matching quick digest means the file
/// is worth reading in full, and nothing more (DR-13).
///
/// # Errors
///
/// Returns [`ReadRefusal::WouldDownload`] when the content is not local, and
/// [`ReadRefusal::Refused`] when the system declined.
pub fn quick_digest(
    path: &Path,
    cloud: &CloudState,
    size: u64,
    mode: &ScanMode,
) -> Result<Digest, ReadRefusal> {
    // Small enough to read through, so the sample and the content digest are the
    // same value. Producing a different one here would throw away the only
    // chance to learn a small file's identity for free.
    if size <= SAMPLE_READS_WHOLE_FILE_UP_TO {
        return full_digest(path, cloud, size, mode);
    }

    let mut file = open_local(path, cloud, size, mode)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&size.to_le_bytes());

    let mut head = vec![0_u8; usize::try_from(END_BYTES).unwrap_or(usize::MAX)];
    file.read_exact(&mut head)
        .map_err(|error| refusal(&error))?;
    hasher.update(&head);

    // Negative offsets only; END_BYTES is a small constant, so the conversion
    // cannot lose anything, but saying so beats leaving it to be assumed.
    let from_end = i64::try_from(END_BYTES).unwrap_or(i64::MAX);
    file.seek(SeekFrom::End(-from_end))
        .map_err(|error| refusal(&error))?;
    let mut tail = vec![0_u8; usize::try_from(END_BYTES).unwrap_or(usize::MAX)];
    file.read_exact(&mut tail)
        .map_err(|error| refusal(&error))?;
    hasher.update(&tail);

    Ok(Digest::from_bytes(*hasher.finalize().as_bytes()))
}

/// A digest of a file's entire content.
///
/// This is what identity is decided by, and nothing else is (DR-13).
///
/// # Errors
///
/// As [`quick_digest`].
pub fn full_digest(
    path: &Path,
    cloud: &CloudState,
    size: u64,
    mode: &ScanMode,
) -> Result<Digest, ReadRefusal> {
    let mut file = open_local(path, cloud, size, mode)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 256 * 1024];

    loop {
        let read = file.read(&mut buffer).map_err(|error| refusal(&error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(Digest::from_bytes(*hasher.finalize().as_bytes()))
}

/// Opens a file, but only if its content is already here.
///
/// The check happens before the open rather than after, because on a platform
/// without a process-wide materialization policy the open itself is what
/// triggers the download.
fn open_local(
    path: &Path,
    cloud: &CloudState,
    size: u64,
    _mode: &ScanMode,
) -> Result<File, ReadRefusal> {
    if cloud.residency.read_may_download() {
        return Err(ReadRefusal::WouldDownload { bytes: size });
    }

    // DR-11-EXEMPT: reached only for content the caller has established is on
    // this machine, and on macOS the process additionally runs under a policy
    // that fails rather than materializes. This is the single place the project
    // opens a user's file.
    File::open(path).map_err(|error| ReadRefusal::Refused(imp::classify_io_error(&error)))
}

fn refusal(error: &std::io::Error) -> ReadRefusal {
    // A read that fails partway because the content turned out not to be here
    // is the same finding as declining to start, and is reported as such.
    match imp::classify_io_error(error) {
        UnreadReason::WouldRequireDownload => ReadRefusal::WouldDownload { bytes: 0 },
        other => ReadRefusal::Refused(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrub_core::cloud::{Provider, Residency, Retention};

    fn local() -> CloudState {
        CloudState::not_synced()
    }

    fn remote() -> CloudState {
        CloudState {
            provider: Some(Provider::ICloud),
            residency: Residency::Remote,
            retention: Retention::Unspecified,
        }
    }

    fn write(directory: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, content).expect("write the fixture");
        path
    }

    #[test]
    fn identical_content_digests_identically() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let one = write(directory.path(), "one", b"the same bytes");
        let two = write(directory.path(), "two", b"the same bytes");

        let size = 14;
        assert_eq!(
            full_digest(&one, &local(), size, &mode).expect("digest"),
            full_digest(&two, &local(), size, &mode).expect("digest")
        );
    }

    #[test]
    fn a_single_changed_byte_changes_the_digest() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let one = write(directory.path(), "one", b"the same bytes");
        let two = write(directory.path(), "two", b"the same byteS");

        assert_ne!(
            full_digest(&one, &local(), 14, &mode).expect("digest"),
            full_digest(&two, &local(), 14, &mode).expect("digest")
        );
    }

    #[test]
    fn cloud_content_is_refused_rather_than_fetched() {
        // The refusal that keeps a scan from costing money. It happens before
        // the open, so nothing asks the provider for anything.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = write(directory.path(), "placeholder", b"stand-in");

        let refused = full_digest(&path, &remote(), 8_000_000_000, &mode);
        assert!(matches!(
            refused,
            Err(ReadRefusal::WouldDownload {
                bytes: 8_000_000_000
            })
        ));
    }

    #[test]
    fn a_quick_digest_separates_large_files_that_differ_at_either_end() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let size = END_BYTES * 3;

        let mut head_differs = vec![b'a'; usize::try_from(size).expect("a sane size")];
        let mut tail_differs = head_differs.clone();
        head_differs[0] = b'z';
        let last = tail_differs.len() - 1;
        tail_differs[last] = b'z';

        let one = write(directory.path(), "one", &head_differs);
        let two = write(directory.path(), "two", &tail_differs);
        let three = write(directory.path(), "three", &vec![b'a'; head_differs.len()]);

        let digest = |path: &Path| quick_digest(path, &local(), size, &mode).expect("digest");
        assert_ne!(digest(&one), digest(&three), "a difference at the head");
        assert_ne!(digest(&two), digest(&three), "a difference at the tail");
        assert_ne!(digest(&one), digest(&two));
    }

    #[test]
    fn a_quick_digest_matches_for_files_that_are_actually_identical() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let size = END_BYTES * 3;
        let content = vec![b'a'; usize::try_from(size).expect("a sane size")];

        let one = write(directory.path(), "one", &content);
        let two = write(directory.path(), "two", &content);
        assert_eq!(
            quick_digest(&one, &local(), size, &mode).expect("digest"),
            quick_digest(&two, &local(), size, &mode).expect("digest")
        );
    }

    #[test]
    fn a_quick_digest_is_not_a_full_digest() {
        // Guards against ever treating one as the other: two files whose ends
        // and size match can still differ in the middle, which is why a matching
        // quick digest only means "worth reading in full".
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let size = END_BYTES * 3;

        let mut middle_differs = vec![b'a'; usize::try_from(size).expect("a sane size")];
        let middle = middle_differs.len() / 2;
        middle_differs[middle] = b'z';

        let one = write(directory.path(), "one", &vec![b'a'; middle_differs.len()]);
        let two = write(directory.path(), "two", &middle_differs);

        assert_eq!(
            quick_digest(&one, &local(), size, &mode).expect("digest"),
            quick_digest(&two, &local(), size, &mode).expect("digest"),
            "the ends agree, so the quick pass cannot separate them"
        );
        assert_ne!(
            full_digest(&one, &local(), size, &mode).expect("digest"),
            full_digest(&two, &local(), size, &mode).expect("digest"),
            "reading in full is what actually settles it"
        );
    }

    #[test]
    fn a_small_file_is_read_whole_by_the_sampling_pass() {
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let one = write(directory.path(), "one", b"short but different");
        let two = write(directory.path(), "two", b"short and different");

        assert_ne!(
            quick_digest(&one, &local(), 19, &mode).expect("digest"),
            quick_digest(&two, &local(), 19, &mode).expect("digest")
        );
    }

    #[test]
    fn a_content_digest_is_the_plain_blake3_of_the_file() {
        // So that anyone can check a claim the tool makes about their own file
        // with an ordinary command, rather than taking our word for it.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let content = b"exactly what b3sum would be given";
        let path = write(directory.path(), "file", content);

        assert_eq!(
            full_digest(&path, &local(), content.len() as u64, &mode).expect("digest"),
            Digest::of(content),
            "a file's digest must be the BLAKE3 of its content and nothing else"
        );
    }

    #[test]
    fn a_small_file_samples_to_exactly_its_content_digest() {
        // What makes comparing two machines affordable. Every file under the
        // threshold gets a real content digest out of the cheap pass, so the
        // expensive one is only ever needed for large files.
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = write(directory.path(), "small", b"well under the threshold");
        let size = 24;

        assert_eq!(
            quick_digest(&path, &local(), size, &mode).expect("digest"),
            full_digest(&path, &local(), size, &mode).expect("digest"),
            "below the threshold the two passes must agree exactly"
        );
    }

    #[test]
    fn a_large_file_samples_to_something_that_is_not_its_content_digest() {
        // And above it they must not, or a sample would be mistaken for
        // identity — which is the one thing a sample must never be (DR-13).
        let mode = crate::enter_read_only_scan_mode().expect("scan mode");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let size = SAMPLE_READS_WHOLE_FILE_UP_TO + 1;
        let path = write(
            directory.path(),
            "large",
            &vec![b'a'; usize::try_from(size).expect("a sane size")],
        );

        assert_ne!(
            quick_digest(&path, &local(), size, &mode).expect("digest"),
            full_digest(&path, &local(), size, &mode).expect("digest")
        );
    }
}
