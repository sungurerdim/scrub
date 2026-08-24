//! Windows cloud-state detection.
//!
//! Windows exposes cloud placeholders through file attributes set by the sync
//! provider's filter driver. The rules for reading those attributes live in
//! [`crate::win_attributes`], which is compiled and tested on every platform;
//! this module is the thin part that cannot be: reading the attributes off a
//! real `Metadata`, and finding where the providers put their directories.
//!
//! The important asymmetry with macOS: there is no process-wide policy that
//! makes an accidental download impossible. Windows upholds DR-11 per open,
//! through `FILE_FLAG_OPEN_NO_RECALL`, which means the guarantee holds only
//! because every open goes through this crate. That is exactly why the guard in
//! `scripts/guards.py` rejects direct filesystem access elsewhere.

use std::os::windows::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::PlatformError;
use crate::win_attributes;
use scrub_core::cloud::{CloudRoot, Detection, Provider, Residency, Retention, RootOrigin};
use scrub_core::inventory::{FileId, UnreadReason};

/// Proof that the process is running under the read-only scan policy.
///
/// On Windows this carries no kernel state: the platform offers no process-wide
/// switch equivalent to the macOS I/O policy. It exists so both platforms
/// present the same shape to the stages above, and so a scanner still cannot
/// begin traversal without having come through this crate.
#[derive(Debug)]
pub struct ScanMode {
    _private: (),
}

/// Enters read-only scan mode.
///
/// Always succeeds. The guarantee it stands for is upheld at each open instead,
/// by passing `FILE_FLAG_OPEN_NO_RECALL` and by refusing to open any path whose
/// [`Residency`] says reading it may download.
pub fn enter_read_only_scan_mode() -> Result<ScanMode, PlatformError> {
    Ok(ScanMode { _private: () })
}

/// Where a file's content is, judged from metadata alone.
pub fn residency(metadata: &std::fs::Metadata) -> Residency {
    win_attributes::residency(metadata.file_attributes())
}

/// Whether the user pinned the file locally.
pub fn retention(metadata: &std::fs::Metadata) -> Retention {
    win_attributes::retention(metadata.file_attributes())
}

/// Finds the sync provider roots under `home`.
///
/// # Known gap
///
/// Google Drive for desktop mounts as a virtual drive letter rather than a
/// directory under the user profile, and locating it reliably means reading the
/// client's own configuration. That is not implemented here, and guessing would
/// be worse than the gap: a Drive we failed to find would have its files
/// reported as backed up nowhere, which is a claim a user would act on. Until it
/// is implemented, a Drive mount must be supplied as an explicit scan root.
pub fn detect(home: &Path) -> Result<Detection, PlatformError> {
    let mut roots = Vec::new();

    // OneDrive publishes its location through the environment, once per
    // connected account. `OneDrive` duplicates whichever of the two is primary,
    // so identical paths are collapsed rather than counted twice.
    for (variable, account) in [
        ("OneDriveConsumer", Some("personal")),
        ("OneDriveCommercial", Some("work")),
        ("OneDrive", None),
    ] {
        let Some(value) = std::env::var_os(variable) else {
            continue;
        };
        let path = PathBuf::from(value);
        if !path.is_dir() || roots.iter().any(|root: &CloudRoot| root.path == path) {
            continue;
        }
        roots.push(CloudRoot {
            path,
            provider: Provider::OneDrive,
            account: account.map(str::to_owned),
            origin: RootOrigin::ProviderMount,
        });
    }

    for (name, provider) in [
        ("iCloudDrive", Provider::ICloud),
        ("Dropbox", Provider::Dropbox),
    ] {
        let path = home.join(name);
        if path.is_dir() {
            roots.push(CloudRoot {
                path,
                provider,
                account: None,
                origin: RootOrigin::ProviderMount,
            });
        }
    }

    // Windows sync clients place their content directly in these directories
    // rather than reaching it through a link, so there is nothing here that
    // needs putting to the user (DR-22). Junctions inside a provider directory
    // are handled during traversal, where they are recorded and not followed.
    Ok(Detection {
        roots,
        links: Vec::new(),
    })
}

/// The space the file actually occupies on this disk.
///
/// # Known gap
///
/// Windows reports allocation size through `FILE_STANDARD_INFO`, which needs an
/// open handle, and the standard library does not surface it from a path-based
/// stat. Rather than derive a figure from logical size — which would count every
/// cloud placeholder's full size as space that deleting it would return — this
/// reports nothing, and the capacity figures under-report on Windows until it is
/// implemented. Under-reporting is a disappointment; over-reporting is a lie
/// (DR-16).
pub fn allocated_size(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

/// The filesystem's identity for the object.
///
/// # Known gap
///
/// Windows exposes this through `FILE_ID_INFO`, which needs an open handle. The
/// standard library's accessors for it are still unstable, and opening a handle
/// has to be done with `FILE_FLAG_OPEN_NO_RECALL` and `FILE_FLAG_BACKUP_SEMANTICS`
/// or the open itself hydrates the placeholder — the exact outcome this crate
/// exists to prevent. That is not something to write blind on a machine that
/// cannot run it, so it reports nothing until it can be implemented and verified
/// on Windows.
pub fn file_id(_metadata: &std::fs::Metadata) -> Option<FileId> {
    None
}

/// How many names refer to these same bytes.
///
/// # Known gap
///
/// From the same structure as [`file_id`], and unavailable for the same reason.
/// Reporting one name means hard links are not yet detected on Windows; since
/// [`allocated_size`] also reports nothing there, no capacity figure is derived
/// from either, so the gap under-reports rather than misleads.
pub fn link_count(_metadata: &std::fs::Metadata) -> u64 {
    1
}

/// Turns a traversal failure into the reason it will be reported under (DR-23).
///
/// # Known gap
///
/// Windows has a family of `ERROR_CLOUD_FILE_*` codes for exactly the situation
/// macOS reports as `EDEADLK`, and a service that cannot hydrate receives one of
/// them instead of a plain refusal. Those codes are not mapped here because they
/// could not be verified on a Windows machine, and a wrong constant would file a
/// cloud-only directory under "permission denied" — a reason that would send the
/// user looking in entirely the wrong place. Until then such failures are
/// reported verbatim under `Other`, which is honest if unhelpful.
pub fn classify_io_error(error: &std::io::Error) -> UnreadReason {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => UnreadReason::PermissionDenied,
        std::io::ErrorKind::NotFound => UnreadReason::Vanished,
        _ => crate::walk::other_reason(error),
    }
}
