//! macOS cloud-state detection.
//!
//! Since Sonoma, iCloud Drive stores files that are not downloaded as *dataless*
//! objects, and Google Drive, OneDrive and Dropbox do the same through File
//! Provider. A dataless file is indistinguishable from an ordinary one at a
//! glance: it has its real name, its real size, its real timestamps, and its
//! extended attributes. What it does not have is content — and reading it makes
//! the system fetch that content from the network.
//!
//! Every constant here was read from the SDK headers on a machine, not recalled:
//! `SF_DATALESS` from `sys/stat.h`, the I/O policy values from `sys/resource.h`,
//! and the `setiopolicy_np` argument order from its manual page.

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::macos::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::{
    CloudRoot, Detection, LinkVerdict, PlatformError, Provider, ProviderLink, Residency, Retention,
    RootOrigin,
};

/// `sys/stat.h`: "file is dataless object".
const SF_DATALESS: u32 = 0x4000_0000;

/// `sys/resource.h`: `IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES`.
const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: c_int = 3;
/// `sys/resource.h`: `IOPOL_TYPE_VFS_ATIME_UPDATES`.
const IOPOL_TYPE_VFS_ATIME_UPDATES: c_int = 2;
/// `sys/resource.h`: `IOPOL_SCOPE_PROCESS`.
const IOPOL_SCOPE_PROCESS: c_int = 0;
/// `sys/resource.h`: `IOPOL_MATERIALIZE_DATALESS_FILES_OFF`.
const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: c_int = 1;
/// `sys/resource.h`: `IOPOL_ATIME_UPDATES_OFF`.
const IOPOL_ATIME_UPDATES_OFF: c_int = 1;

// The only foreign function in the project. Declared here rather than pulled in
// with a binding crate: three constants and one call is a smaller surface to
// audit than an entire libc.
#[allow(
    unsafe_code,
    reason = "the sole FFI declaration, audited at its call site"
)]
unsafe extern "C" {
    /// `setiopolicy_np(int iotype, int scope, int policy)` from `sys/resource.h`.
    fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;

    /// `getxattr` from `sys/xattr.h`.
    ///
    /// Used only to ask whether an attribute is present, never to read a user's
    /// data. Declared here because the standard library has no extended
    /// attribute interface.
    fn getxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
        position: u32,
        options: c_int,
    ) -> isize;
}

/// `sys/xattr.h`: read the attribute from the link itself, not its target.
///
/// The default is the opposite, and the manual page says so outright: "getxattr
/// normally returns information from the target of path if it is a symbolic
/// link." Omitting this flag inverts the answer to the single most consequential
/// question this module asks.
const XATTR_NOFOLLOW: c_int = 0x0001;

/// Set by iCloud on a link to a folder it has detached from synchronization.
///
/// Undocumented by Apple, so it is read in one direction only: present means the
/// target is definitively not backed up; absent means nothing at all.
const XATTR_FILEPROVIDER_IGNORE: &[u8] = b"com.apple.fileprovider.ignore#P\0";

/// Directories a provider creates inside its own storage as working state.
///
/// Their presence at a link's target means the target is that provider's own
/// content — Google Drive in mirror mode points out of its streaming directory
/// exactly this way, with its download staging directory at the far end.
const PROVIDER_MARKERS: [(&str, Provider); 3] = [
    (".tmp.drivedownload", Provider::GoogleDrive),
    (".shortcut-targets-by-id", Provider::GoogleDrive),
    (".dropbox.cache", Provider::Dropbox),
];

/// Proof that the process is running under the read-only scan policy.
///
/// The policy is process-wide and permanent for the life of the process, so this
/// carries no state and needs no teardown. It exists so that a stage cannot
/// begin traversal without having asked for the policy: the scanner takes one by
/// value, and the only way to get one is [`enter_read_only_scan_mode`].
#[derive(Debug)]
pub struct ScanMode {
    _private: (),
}

/// Asks the kernel to make accidental downloads impossible.
///
/// Two policies are set for the whole process:
///
/// - **Dataless materialization off.** A read of a cloud-only file returns
///   `EDEADLK` instead of blocking on a network fetch. This is what turns DR-11
///   from a discipline into a guarantee: no amount of carelessness elsewhere in
///   the codebase can download a file, because the kernel will not do it.
/// - **Access time updates off.** Traversal does not modify `atime`, so scanning
///   leaves no trace on the filesystem at all.
pub fn enter_read_only_scan_mode() -> Result<ScanMode, PlatformError> {
    set_policy(
        IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
        IOPOL_MATERIALIZE_DATALESS_FILES_OFF,
        "dataless materialization",
    )?;
    set_policy(
        IOPOL_TYPE_VFS_ATIME_UPDATES,
        IOPOL_ATIME_UPDATES_OFF,
        "access time updates",
    )?;
    Ok(ScanMode { _private: () })
}

fn set_policy(iotype: c_int, policy: c_int, what: &str) -> Result<(), PlatformError> {
    // SAFETY: `setiopolicy_np` takes three integers and returns an integer. It
    // reads no memory through pointers, so there is nothing for us to keep
    // valid. All three arguments are constants taken from the system headers.
    #[allow(unsafe_code)]
    let outcome = unsafe { setiopolicy_np(iotype, IOPOL_SCOPE_PROCESS, policy) };

    if outcome == 0 {
        return Ok(());
    }
    Err(PlatformError::PolicyRefused {
        detail: format!(
            "could not turn off {what}: {}",
            std::io::Error::last_os_error()
        ),
    })
}

/// Where a file's content is, judged from metadata alone.
pub fn residency(metadata: &std::fs::Metadata) -> Residency {
    if metadata.st_flags() & SF_DATALESS != 0 {
        return Residency::Remote;
    }

    // Corroborating signal for providers that do not set the flag on every
    // object: a file reporting a real size while occupying no blocks has no
    // content on this disk. Directories legitimately report zero blocks, and
    // genuinely empty files report zero size, so both are excluded.
    if metadata.is_file() && metadata.st_blocks() == 0 && metadata.st_size() > 0 {
        return Residency::Remote;
    }

    Residency::Local
}

/// Whether the user pinned the file locally.
///
/// macOS records this in File Provider state rather than in `stat`, and reading
/// it requires asking the provider — which is a per-file round trip we will not
/// pay during a full-disk traversal. Left unspecified until the interface has a
/// use for it that justifies the cost.
pub fn retention(_metadata: &std::fs::Metadata) -> Retention {
    Retention::Unspecified
}

/// Finds the sync provider directories under `home`.
pub fn detect(home: &Path) -> Result<Detection, PlatformError> {
    let mut roots = Vec::new();
    collect_icloud(home, &mut roots)?;
    collect_file_provider(home, &mut roots)?;
    collect_legacy(home, &mut roots);
    collect_home_redirects(home, &mut roots);

    let mut links = Vec::new();
    for root in &roots {
        collect_outward_links(root, &mut links);
    }

    Ok(Detection { roots, links })
}

/// Collects symbolic links at the top of a provider directory.
///
/// Whether these belong to the provider is not decidable here (DR-22); the
/// caller filters out those whose targets turn out to sit inside another known
/// provider directory, and the rest are put to the user.
fn collect_outward_links(root: &CloudRoot, links: &mut Vec<ProviderLink>) {
    // DR-11-EXEMPT: enumerates a provider mount point, which is an ordinary
    // local directory, and reads only link targets — never link contents.
    //
    // A provider directory that vanished between detection and this call, or
    // that refuses to be listed, is not a reason to abandon detection: the root
    // itself is already recorded, and traversal will report the refusal.
    let Ok(entries) = std::fs::read_dir(&root.path) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_symlink() {
            continue;
        }
        // DR-11-EXEMPT: returns the stored target string without touching the
        // target, so it cannot materialize anything.
        let Ok(target) = std::fs::read_link(&path) else {
            continue;
        };
        let target = if target.is_absolute() {
            target
        } else {
            root.path.join(target)
        };
        let verdict = link_verdict(&path, &target);
        links.push(ProviderLink {
            link: path,
            target,
            provider: root.provider.clone(),
            verdict,
        });
    }
}

/// Asks the platform and the provider what a link means, before asking the user.
fn link_verdict(link: &Path, target: &Path) -> LinkVerdict {
    if has_xattr_nofollow(link, XATTR_FILEPROVIDER_IGNORE) {
        return LinkVerdict::ExcludedByProvider;
    }
    if PROVIDER_MARKERS
        .iter()
        .any(|(marker, _)| target.join(marker).exists())
    {
        return LinkVerdict::ProviderOwned;
    }
    LinkVerdict::Unsettled
}

/// Whether an extended attribute is present **on the link itself**.
///
/// Only presence is tested; the value is never read into memory. Any failure —
/// the attribute is missing, the path has a NUL byte, permission is refused —
/// answers `false`, which routes the link to the user rather than to a guess.
fn has_xattr_nofollow(path: &Path, name: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };

    // SAFETY: both pointers address NUL-terminated buffers that outlive the
    // call. A null value pointer with size zero is the documented way to query
    // an attribute's length without retrieving it, so nothing is written back.
    #[allow(unsafe_code)]
    let length = unsafe {
        getxattr(
            path.as_ptr(),
            name.as_ptr().cast::<c_char>(),
            std::ptr::null_mut(),
            0,
            0,
            XATTR_NOFOLLOW,
        )
    };

    length >= 0
}

/// iCloud Drive itself, plus every per-application container beside it.
///
/// The containers matter: this is where Pages documents, WhatsApp backups and
/// GarageBand projects live, and they are a common answer to "what is filling my
/// iCloud" that no ordinary file browser surfaces.
fn collect_icloud(home: &Path, roots: &mut Vec<CloudRoot>) -> Result<(), PlatformError> {
    let ubiquity = home.join("Library/Mobile Documents");
    let Some(entries) = read_dir_if_present(&ubiquity)? else {
        return Ok(());
    };

    for path in entries {
        let name = directory_name(&path);
        let (origin, account) = match name.as_str() {
            "com~apple~CloudDocs" => (RootOrigin::ProviderMount, None),
            // iCloud's own deleted-items area. Its contents still count against
            // the user's quota until Apple expires them, so it is recorded
            // rather than skipped (DR-16).
            ".Trash" => (RootOrigin::ProviderTrash, None),
            _ => (RootOrigin::AppContainer, Some(name)),
        };
        roots.push(CloudRoot {
            path,
            provider: Provider::ICloud,
            account,
            origin,
        });
    }
    Ok(())
}

/// Everything mounted through File Provider, which is where modern versions of
/// Google Drive, OneDrive, Dropbox and Box place their content.
fn collect_file_provider(home: &Path, roots: &mut Vec<CloudRoot>) -> Result<(), PlatformError> {
    let storage = home.join("Library/CloudStorage");
    let Some(entries) = read_dir_if_present(&storage)? else {
        return Ok(());
    };

    for path in entries {
        let (provider, account) = parse_cloud_storage_name(&directory_name(&path));
        roots.push(CloudRoot {
            path,
            provider,
            account,
            origin: RootOrigin::ProviderMount,
        });
    }
    Ok(())
}

/// Splits a `Library/CloudStorage` directory name into provider and account.
///
/// The naming convention is `Provider-Account`, with the account part absent for
/// providers that do not distinguish accounts. An unrecognised prefix is kept
/// verbatim rather than guessed at.
fn parse_cloud_storage_name(name: &str) -> (Provider, Option<String>) {
    // Split on the *first* hyphen only: organisation names contain hyphens, and
    // splitting on the last one would corrupt the label used to tell two
    // accounts of the same provider apart. A trailing hyphen with nothing after
    // it still identifies the provider, and yields no account.
    let (prefix, account) = match name.split_once('-') {
        Some((prefix, rest)) if !rest.is_empty() => (prefix, Some(rest.to_owned())),
        Some((prefix, _)) => (prefix, None),
        None => (name, None),
    };

    let provider = match prefix {
        "GoogleDrive" => Provider::GoogleDrive,
        "OneDrive" => Provider::OneDrive,
        "Dropbox" => Provider::Dropbox,
        "iCloudDrive" => Provider::ICloud,
        other => Provider::Other(other.to_owned()),
    };
    (provider, account)
}

/// Locations older versions of these clients used, which are still in the wild.
fn collect_legacy(home: &Path, roots: &mut Vec<CloudRoot>) {
    let candidates = [
        ("Google Drive", Provider::GoogleDrive),
        ("Dropbox", Provider::Dropbox),
        ("OneDrive", Provider::OneDrive),
    ];

    for (name, provider) in candidates {
        let path = home.join(name);
        // A legacy location is only interesting if it is a real directory: the
        // modern clients often leave a symlink here pointing at the File
        // Provider mount, and recording both would double-count every file.
        if path.is_dir() && !path.is_symlink() {
            roots.push(CloudRoot {
                path,
                provider,
                account: None,
                origin: RootOrigin::LegacyLocation,
            });
        }
    }
}

/// Detects home directories iCloud has redirected into itself.
///
/// When Desktop and Documents syncing is enabled, macOS replaces `~/Desktop` and
/// `~/Documents` with symlinks into iCloud Drive. Users routinely do not know
/// this happened, and it is the single most common answer to "why is my iCloud
/// full". Recording it as its own origin lets the interface say so plainly.
fn collect_home_redirects(home: &Path, roots: &mut Vec<CloudRoot>) {
    for name in ["Desktop", "Documents"] {
        let path = home.join(name);
        if !path.is_symlink() {
            continue;
        }
        // DR-11-EXEMPT: reading a symlink returns the stored target string and
        // never touches the target, so this cannot materialize anything.
        let Ok(target) = std::fs::read_link(&path) else {
            continue;
        };
        if target.starts_with(home.join("Library/Mobile Documents")) {
            roots.push(CloudRoot {
                path: target,
                provider: Provider::ICloud,
                account: Some(name.to_owned()),
                origin: RootOrigin::HomeRedirect,
            });
        }
    }
}

/// Lists a directory, treating "not there" as "nothing to report".
///
/// A machine without iCloud enabled simply has no `Mobile Documents`, and that
/// is an ordinary state rather than an error. Anything else — a permission
/// refusal in particular — is reported, because silently scanning less than the
/// user asked for would make every later count wrong.
fn read_dir_if_present(path: &Path) -> Result<Option<Vec<PathBuf>>, PlatformError> {
    // DR-11-EXEMPT: this enumerates provider mount points, which are ordinary
    // local directories; the process is additionally running under the
    // no-materialize policy by the time any of this is reached.
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(PlatformError::RootDetection {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let mut collected = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| PlatformError::RootDetection {
            path: path.to_path_buf(),
            source,
        })?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collected.push(entry_path);
        }
    }
    Ok(Some(collected))
}

/// The final component of a directory path, lossily decoded.
///
/// Provider directory names are ASCII in practice; a name that is not valid
/// Unicode still yields something we can show and compare, rather than causing
/// the root to be dropped and its files reported as backed up nowhere.
fn directory_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_storage_names_split_into_provider_and_account() {
        assert_eq!(
            parse_cloud_storage_name("GoogleDrive-someone@example.com"),
            (
                Provider::GoogleDrive,
                Some("someone@example.com".to_owned())
            )
        );
        assert_eq!(
            parse_cloud_storage_name("OneDrive-Contoso Ltd"),
            (Provider::OneDrive, Some("Contoso Ltd".to_owned()))
        );
        assert_eq!(
            parse_cloud_storage_name("Dropbox"),
            (Provider::Dropbox, None)
        );
    }

    #[test]
    fn an_unrecognised_provider_is_recorded_verbatim() {
        // Guards against silently dropping a mount we do not model: a file
        // counted under no provider would be reported as "backed up nowhere",
        // which is exactly the claim a user would act on.
        assert_eq!(
            parse_cloud_storage_name("Egnyte-work"),
            (
                Provider::Other("Egnyte".to_owned()),
                Some("work".to_owned())
            )
        );
    }

    #[test]
    fn an_account_containing_a_hyphen_survives_intact() {
        // Organisation names contain hyphens; splitting on the last one, or on
        // every one, would corrupt the label used to tell two accounts apart.
        assert_eq!(
            parse_cloud_storage_name("OneDrive-Acme-Global-Holdings"),
            (Provider::OneDrive, Some("Acme-Global-Holdings".to_owned()))
        );
    }

    #[test]
    fn a_trailing_hyphen_does_not_produce_an_empty_account() {
        assert_eq!(
            parse_cloud_storage_name("Dropbox-"),
            (Provider::Dropbox, None)
        );
    }

    #[test]
    fn read_only_scan_mode_is_accepted_by_this_kernel() {
        // Not a mock: this asks the running kernel to apply the policy the whole
        // design rests on. If macOS ever stops honouring it, this fails here
        // rather than during someone's first scan.
        enter_read_only_scan_mode().expect("macOS must accept the read-only scan policy");
    }
}
