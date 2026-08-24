//! Reading and writing artifacts.
//!
//! An artifact is an ordinary SQLite database with a documented schema. That
//! choice is DR-3 made concrete: a person can open one of these in any SQLite
//! client and answer their own questions about their own files, with this tool
//! uninstalled and this project abandoned.
//!
//! The chain digest is taken over the **content**, not over the file's bytes.
//! Two scans of an unchanged tree produce the same digest on any machine and any
//! version of the storage engine, which makes "nothing has changed since last
//! time" a fact the tool can state rather than guess at (DR-12).

#![forbid(unsafe_code)]

mod canonical;
mod schema;

pub use canonical::{content_digest, scope_digest};

use std::path::Path;

use rusqlite::Connection;
use scrub_core::artifact::{ArtifactHeader, Digest};
use scrub_core::cloud::Detection;
use scrub_core::inventory::ScanOutcome;
use scrub_core::paths::PathEncoding;

/// A complete inventory artifact: what a scan found, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    /// Where this artifact sits in the chain.
    pub header: ArtifactHeader,
    /// How the producing machine spells paths.
    pub path_encoding: PathEncoding,
    /// The providers found on that machine.
    pub detection: Detection,
    /// Everything the scan saw, and everywhere it could not look.
    pub outcome: ScanOutcome,
}

impl Inventory {
    /// The digest of this artifact's content, in canonical form.
    ///
    /// Independent of traversal order, of the storage engine, and of the machine
    /// computing it.
    #[must_use]
    pub fn content_digest(&self) -> Digest {
        canonical::content_digest(&self.detection, &self.outcome)
    }

    /// Whether this artifact's paths can be acted on by this machine.
    ///
    /// An artifact from a machine that spells paths differently can be read,
    /// compared, and displayed, but its paths are renderings rather than
    /// originals, so nothing may be executed against them here.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.path_encoding == scrub_core::paths::LOCAL
    }

    /// Writes the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the file could not be created or written.
    pub fn write(&self, path: &Path) -> Result<(), StoreError> {
        // DR-11-EXEMPT: this is the tool's own artifact, in a location the user
        // chose for it, and never a path discovered by a scan.
        let mut connection = Connection::open(path)?;
        schema::create(&connection)?;
        let transaction = connection.transaction()?;
        schema::write_all(&transaction, self)?;
        transaction.commit()?;
        Ok(())
    }

    /// Reads an artifact.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ContentAltered`] if the recorded digest does not
    /// match the content, and [`StoreError::Sqlite`] if the file is not a
    /// readable artifact.
    pub fn read(path: &Path) -> Result<Self, StoreError> {
        // DR-11-EXEMPT: as above — an artifact the tool wrote, not user data.
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        let inventory = schema::read_all(&connection)?;

        // The header names a digest of the body; if the two disagree, something
        // edited the file after it was written. Reporting that is the whole
        // point of recording it.
        let actual = inventory.content_digest();
        if actual != inventory.header.content_digest {
            return Err(StoreError::ContentAltered {
                recorded: inventory.header.content_digest,
                found: actual,
            });
        }
        Ok(inventory)
    }
}

/// A failure reading or writing an artifact.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused the operation.
    #[error("artifact storage failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A value in the artifact could not be understood.
    #[error("artifact field {field} could not be read: {detail}")]
    Malformed {
        /// Which field.
        field: &'static str,
        /// What went wrong.
        detail: String,
    },

    /// The content does not match the digest recorded in the header.
    #[error(
        "this artifact's content no longer matches its recorded digest \
         (recorded {recorded}, found {found}). It was modified after it was written, \
         so nothing downstream will act on it."
    )]
    ContentAltered {
        /// What the header claims.
        recorded: Digest,
        /// What the content actually digests to.
        found: Digest,
    },
}

/// Writes the artifact's content as newline-delimited JSON.
///
/// The companion to the database promised by DR-3, and the form used for
/// diffing: two exports of two scans can be compared with any text tool, which
/// a pair of SQLite files cannot. Lines appear in the artifact's own order, one
/// object per line, each tagged with what it is.
///
/// Paths appear twice, as a rendering and as hexadecimal bytes, for the same
/// reason they are stored twice: the rendering is for reading, the bytes are
/// what a path actually is.
///
/// # Errors
///
/// Returns any error the writer produced.
pub fn write_ndjson(inventory: &Inventory, out: &mut impl std::io::Write) -> std::io::Result<()> {
    use scrub_core::paths::StoredPath;

    fn line(out: &mut impl std::io::Write, record: &serde_json::Value) -> std::io::Result<()> {
        serde_json::to_writer(&mut *out, record)?;
        out.write_all(b"\n")
    }

    fn path_value(path: &std::path::Path) -> serde_json::Value {
        use std::fmt::Write as _;
        let stored = StoredPath::of(path);
        let hex = stored.bytes.iter().fold(
            String::with_capacity(stored.bytes.len() * 2),
            |mut accumulated, byte| {
                let _ = write!(accumulated, "{byte:02x}");
                accumulated
            },
        );
        serde_json::json!({ "text": stored.display, "bytes": hex })
    }

    line(
        out,
        &serde_json::json!({
            "record": "header",
            "header": inventory.header,
            "path_encoding": inventory.path_encoding,
        }),
    )?;

    for root in &inventory.detection.roots {
        line(
            out,
            &serde_json::json!({
                "record": "cloud_root",
                "path": path_value(&root.path),
                "provider": root.provider,
                "account": root.account,
                "origin": root.origin,
            }),
        )?;
    }

    for link in &inventory.detection.links {
        line(
            out,
            &serde_json::json!({
                "record": "cloud_link",
                "link": path_value(&link.link),
                "target": path_value(&link.target),
                "provider": link.provider,
                "verdict": link.verdict,
            }),
        )?;
    }

    for entry in &inventory.outcome.entries {
        line(
            out,
            &serde_json::json!({
                "record": "entry",
                "path": path_value(&entry.path),
                "kind": entry.kind,
                "logical_size": entry.logical_size,
                "allocated_size": entry.allocated_size,
                "created": entry.created.map(|when| when.to_string()),
                "modified": entry.modified.map(|when| when.to_string()),
                "file_id": entry.file_id,
                "link_count": entry.link_count,
                "link_target": entry.link_target.as_deref().map(path_value),
                "cloud": entry.cloud,
            }),
        )?;
    }

    for place in &inventory.outcome.unread {
        line(
            out,
            &serde_json::json!({
                "record": "unread",
                "path": path_value(&place.path),
                "reason": place.reason,
            }),
        )?;
    }

    Ok(())
}
