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

use crate::win_attributes;
use crate::{CloudRoot, Detection, PlatformError, Provider, Residency, Retention, RootOrigin};

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
