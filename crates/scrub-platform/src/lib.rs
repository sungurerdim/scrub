//! Cloud-state detection and the side-effect-free filesystem access `scrub`
//! is built on.
//!
//! This is the only crate permitted to touch the filesystem directly; a guard in
//! `scripts/guards.py` rejects direct access anywhere else (DR-11). The reason is
//! narrow and specific: on a machine with cloud sync, opening the wrong file can
//! silently pull gigabytes down from a provider, on a metered connection, without
//! anyone asking. Every path into the filesystem goes through here so that the
//! check happens once, in one place, and cannot be forgotten.

#![deny(unsafe_op_in_unsafe_fn)]

use std::path::{Path, PathBuf};

pub use scrub_core::cloud::{
    CloudMap, CloudRoot, CloudState, Detection, LinkVerdict, Provider, ProviderLink, Residency,
    Retention, RootOrigin,
};

pub mod digest;
pub mod execute;
pub mod verify;
pub mod walk;
pub mod win_attributes;

#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    path = "unsupported.rs"
)]
mod imp;

pub use imp::ScanMode;

/// Discovers every sync provider on this machine.
///
/// # Errors
///
/// Returns [`PlatformError::Unsupported`] on a platform with no implementation,
/// or [`PlatformError::RootDetection`] if a directory refused to be examined.
pub fn detect(home: &Path) -> Result<Detection, PlatformError> {
    imp::detect(home)
}

/// Discovers providers and arranges them for lookup.
///
/// # Errors
///
/// As [`detect`].
pub fn detect_cloud_map(home: &Path) -> Result<CloudMap, PlatformError> {
    Ok(CloudMap::from_detection(detect(home)?))
}

/// Everything the scanner records about one path's relationship to the cloud.
///
/// `metadata` must come from a stat that has already been taken; this performs
/// no filesystem access of its own, so it cannot itself trigger a download.
#[must_use]
pub fn classify(map: &CloudMap, path: &Path, metadata: &std::fs::Metadata) -> CloudState {
    let Some(root) = map.owner_of(path) else {
        return CloudState::not_synced();
    };
    CloudState {
        provider: Some(root.provider.clone()),
        residency: imp::residency(metadata),
        retention: imp::retention(metadata),
    }
}

/// Enters the process-wide mode every read-only stage runs under.
///
/// On macOS this is enforced by the kernel: the process asks for dataless files
/// *not* to be materialized and for access times *not* to be updated, so an
/// accidental read of a cloud-only file fails with `EDEADLK` instead of quietly
/// downloading it. On Windows there is no process-wide equivalent and the
/// guarantee is upheld per open instead; see that implementation for detail.
///
/// # Errors
///
/// Returns [`PlatformError::PolicyRefused`] if the platform declined the
/// request. Refusing to continue is the correct response: without this mode a
/// scan can cost the user money.
pub fn enter_read_only_scan_mode() -> Result<ScanMode, PlatformError> {
    imp::enter_read_only_scan_mode()
}

/// A platform-layer failure.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The operating system refused to enter read-only scan mode.
    #[error(
        "the operating system refused read-only scan mode ({detail}). \
         Scanning would risk downloading cloud files without asking, so it will not start."
    )]
    PolicyRefused {
        /// What the platform reported.
        detail: String,
    },

    /// A directory could not be examined while detecting provider roots.
    #[error("could not examine {path} while detecting cloud providers: {source}")]
    RootDetection {
        /// The path being examined.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// This platform has no implementation.
    #[error("scrub supports macOS and Windows; this platform has no cloud-state implementation")]
    Unsupported,
}
