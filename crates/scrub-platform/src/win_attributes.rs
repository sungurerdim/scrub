//! Windows file attribute interpretation, as pure arithmetic.
//!
//! This module is compiled on every platform even though the attributes only
//! exist on Windows. Keeping the rules here — rather than inside the Windows
//! implementation — means they are covered by the ordinary test suite on a
//! developer's macOS machine, instead of only wherever a Windows runner exists.
//! The bit values come from Microsoft's file attribute reference.

use crate::{Residency, Retention};

/// The file or directory is not fully present locally; reading fetches the rest.
pub const RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
/// The item has no physical representation locally; it is entirely virtual.
///
/// Shares its value with the internal-use `FILE_ATTRIBUTE_EA`, which Microsoft
/// documents as reserved. We consult it only for paths already known to belong
/// to a sync provider, where the placeholder meaning is the applicable one.
pub const RECALL_ON_OPEN: u32 = 0x0004_0000;
/// The data has been moved to offline storage.
pub const OFFLINE: u32 = 0x0000_1000;
/// The user asked for this to be kept fully present locally.
pub const PINNED: u32 = 0x0008_0000;
/// The user allowed this to be evicted when it is not in use.
pub const UNPINNED: u32 = 0x0010_0000;

/// Where a file's content is, judged from its attributes.
#[must_use]
pub fn residency(attributes: u32) -> Residency {
    // Order matters. A fully virtual item can carry the partial bit as well, and
    // reporting it as merely partial would understate what reading it costs.
    if attributes & (RECALL_ON_OPEN | OFFLINE) != 0 {
        return Residency::Remote;
    }
    if attributes & RECALL_ON_DATA_ACCESS != 0 {
        return Residency::Partial;
    }
    Residency::Local
}

/// Whether the user pinned the file locally.
#[must_use]
pub fn retention(attributes: u32) -> Retention {
    // Both bits set is contradictory and means the provider is mid-transition.
    // Claiming either would be inventing a fact the filesystem did not state.
    match (attributes & PINNED != 0, attributes & UNPINNED != 0) {
        (true, false) => Retention::Pinned,
        (false, true) => Retention::Unpinned,
        _ => Retention::Unspecified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `FILE_ATTRIBUTE_NORMAL`, the plainest possible file.
    const NORMAL: u32 = 0x0000_0080;
    /// `FILE_ATTRIBUTE_ARCHIVE`, set on almost everything in practice.
    const ARCHIVE: u32 = 0x0000_0020;

    #[test]
    fn an_ordinary_file_is_local() {
        assert_eq!(residency(NORMAL), Residency::Local);
        assert_eq!(residency(ARCHIVE), Residency::Local);
        assert_eq!(residency(0), Residency::Local);
    }

    #[test]
    fn a_fully_virtual_file_is_remote_even_when_the_partial_bit_is_also_set() {
        // The failure this guards: reporting a file with no local content as
        // merely "partial". A batch operation trusting that would read it and
        // pull the entire file down over the network.
        assert_eq!(
            residency(RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS | ARCHIVE),
            Residency::Remote
        );
    }

    #[test]
    fn an_offline_file_is_remote() {
        assert_eq!(residency(OFFLINE | ARCHIVE), Residency::Remote);
    }

    #[test]
    fn a_partially_present_file_is_partial() {
        assert_eq!(
            residency(RECALL_ON_DATA_ACCESS | ARCHIVE),
            Residency::Partial
        );
    }

    #[test]
    fn pinning_is_read_from_the_matching_bit() {
        assert_eq!(retention(PINNED | ARCHIVE), Retention::Pinned);
        assert_eq!(retention(UNPINNED | ARCHIVE), Retention::Unpinned);
        assert_eq!(retention(ARCHIVE), Retention::Unspecified);
    }

    #[test]
    fn contradictory_pinning_is_reported_as_unspecified() {
        // A provider mid-transition can leave both bits set. Picking one would
        // put a fact on screen that the filesystem never asserted.
        assert_eq!(retention(PINNED | UNPINNED), Retention::Unspecified);
    }

    #[test]
    fn every_placeholder_state_is_treated_as_downloadable() {
        // Ties the attribute rules back to the promise the rest of the tool
        // relies on: anything not fully local must be flagged before it is read.
        for attributes in [RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS, OFFLINE] {
            assert!(
                residency(attributes).read_may_download(),
                "attributes {attributes:#010x} must be treated as downloadable"
            );
        }
        assert!(!residency(NORMAL).read_may_download());
    }
}
