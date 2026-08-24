//! Recording a path exactly as the filesystem spelled it.
//!
//! Paths are not text. On macOS and Linux they are arbitrary bytes that are
//! usually, but not always, UTF-8; on Windows they are UTF-16 code units that
//! may contain unpaired surrogates. Storing them as strings loses the ones that
//! do not convert — and a path we cannot reproduce byte for byte is a path we
//! cannot act on later, which turns a plan into operations that fail at apply
//! time against files that are perfectly fine.
//!
//! So every path is stored as its original bytes, alongside a lossy rendering
//! for display and the encoding it was written in. The bytes are what the tool
//! acts on; the rendering is what a person reads.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How a machine spells the bytes of a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathEncoding {
    /// Arbitrary bytes, as macOS and Linux use.
    Bytes,
    /// UTF-16 code units, little-endian, as Windows uses.
    Utf16Le,
}

/// The encoding this machine writes.
pub const LOCAL: PathEncoding = if cfg!(windows) {
    PathEncoding::Utf16Le
} else {
    PathEncoding::Bytes
};

/// A path as it was spelled, plus something a person can read.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StoredPath {
    /// The original bytes, in the producing machine's encoding.
    pub bytes: Vec<u8>,
    /// A lossy rendering, for display and for search.
    ///
    /// Never used to reconstruct the path: two different paths can render to the
    /// same string once invalid sequences are replaced.
    pub display: String,
}

impl StoredPath {
    /// Records a path from this machine.
    #[must_use]
    pub fn of(path: &std::path::Path) -> Self {
        Self {
            bytes: encode(path),
            display: path.to_string_lossy().into_owned(),
        }
    }

    /// Whether the readable form reproduces the path exactly.
    ///
    /// True for almost every path anyone has. Storage uses this to keep the
    /// bytes only for the ones where they carry information the text does not,
    /// which on a real machine is a handful out of millions.
    #[must_use]
    pub fn text_is_exact(&self) -> bool {
        encode(std::path::Path::new(&self.display)) == self.bytes
    }

    /// Reconstructs the path, if this machine spells paths the same way.
    ///
    /// Returns `None` for a path recorded on a machine with a different
    /// encoding — a Windows path read on macOS, say. That is not a failure: the
    /// merge stage compares such paths as bytes and shows them as text, and
    /// only the machine that owns them ever needs to act on them.
    #[must_use]
    pub fn to_path(&self, encoding: PathEncoding) -> Option<PathBuf> {
        if encoding != LOCAL {
            return None;
        }
        decode_local(&self.bytes)
    }
}

/// The bytes of a path, in this machine's encoding.
#[must_use]
pub fn encode(path: &std::path::Path) -> Vec<u8> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    }
}

/// Rebuilds a path from bytes this machine wrote.
///
/// The `Option` is real on Windows, where an odd byte count cannot be UTF-16 and
/// refusing beats inventing a path that points somewhere else. It is part of the
/// contract on every platform so that callers handle the case wherever they run.
#[must_use]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the Option is part of the cross-platform contract"
)]
fn decode_local(bytes: &[u8]) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt as _;
        if bytes.len() % 2 != 0 {
            // An odd byte count cannot be UTF-16. Refusing beats inventing a
            // path that points somewhere else.
            return None;
        }
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStringExt as _;
        Some(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn an_ordinary_path_round_trips() {
        let original = Path::new("/home/sungur/papers/notes.txt");
        let stored = StoredPath::of(original);
        assert_eq!(stored.to_path(LOCAL).as_deref(), Some(original));
    }

    #[test]
    fn a_path_that_is_not_ascii_round_trips() {
        let original = Path::new("/home/özet çalışma/📄 plan.md");
        let stored = StoredPath::of(original);
        assert_eq!(stored.to_path(LOCAL).as_deref(), Some(original));
        assert!(stored.display.contains("özet"));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_valid_unicode_survives_intact() {
        // The case that makes this module necessary. A filename holding an
        // invalid UTF-8 sequence is perfectly legal on macOS and Linux, and it
        // renders to a replacement character — so a tool that stored only the
        // rendering could never open that file again.
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let raw = OsString::from_vec(b"/home/broken\xFF\xFEname.txt".to_vec());
        let original = PathBuf::from(raw);

        let stored = StoredPath::of(&original);
        assert_eq!(stored.to_path(LOCAL), Some(original.clone()));
        assert_ne!(
            PathBuf::from(&stored.display),
            original,
            "the display form is lossy, which is exactly why the bytes are kept"
        );
    }

    #[test]
    fn a_path_from_a_differently_spelled_machine_is_not_reconstructed() {
        // Refusing is the point. Rebuilding Windows bytes as a macOS path would
        // produce something that looks like a path and points nowhere.
        let stored = StoredPath::of(Path::new("/home/notes.txt"));
        let foreign = if LOCAL == PathEncoding::Bytes {
            PathEncoding::Utf16Le
        } else {
            PathEncoding::Bytes
        };
        assert!(stored.to_path(foreign).is_none());
    }
}
