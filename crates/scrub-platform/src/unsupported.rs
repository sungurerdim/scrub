//! Fallback for platforms with no cloud-state implementation.
//!
//! `scrub` targets macOS and Windows. This module exists so the workspace still
//! builds elsewhere — a contributor on Linux can run the pure parts of the test
//! suite — while making it impossible to scan on a platform where we cannot tell
//! a cloud placeholder from an ordinary file.
//!
//! It deliberately does not fall back to "assume everything is local". That
//! guess would let a scan read a placeholder and download it, which is the one
//! outcome the whole design exists to prevent.

use std::path::Path;

use crate::{Detection, PlatformError, Residency, Retention};

/// Never constructed on this platform.
#[derive(Debug)]
pub struct ScanMode {
    _private: (),
}

/// Always refuses.
///
/// # Errors
///
/// Always returns [`PlatformError::Unsupported`].
pub fn enter_read_only_scan_mode() -> Result<ScanMode, PlatformError> {
    Err(PlatformError::Unsupported)
}

/// Reports that residency could not be determined.
///
/// [`Residency::Unknown`] is treated as downloadable everywhere it matters, so
/// no read will proceed on the strength of it.
pub fn residency(_metadata: &std::fs::Metadata) -> Residency {
    Residency::Unknown
}

/// Reports that no retention preference is available.
pub fn retention(_metadata: &std::fs::Metadata) -> Retention {
    Retention::Unspecified
}

/// Always refuses.
///
/// # Errors
///
/// Always returns [`PlatformError::Unsupported`].
pub fn detect(_home: &Path) -> Result<Detection, PlatformError> {
    Err(PlatformError::Unsupported)
}
