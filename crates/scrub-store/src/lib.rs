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

pub use canonical::{
    analysis_digest, content_digest, journal_digest, plan_digest, preflight_digest, scope_digest,
};

use std::path::Path;

use rusqlite::Connection;
use std::collections::BTreeMap;

use scrub_core::analysis::{Group, Settled};
use scrub_core::artifact::{ArtifactHeader, Digest};
use scrub_core::cloud::Detection;
use scrub_core::inventory::ScanOutcome;
use scrub_core::journal::Step;
use scrub_core::paths::PathEncoding;
use scrub_core::plan::Operation;
use scrub_core::preflight::Verdict;

/// What a scan found, without regard to which artifact carries it.
///
/// Shared by every artifact downstream of a scan: an analysis carries the whole
/// body forward rather than pointing back at an inventory, so each stage reads
/// exactly one file and a plan can be made on a machine that has neither the
/// files nor the scan that produced them (DR-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    /// How the producing machine spells paths.
    pub path_encoding: PathEncoding,
    /// The providers found on that machine.
    pub detection: Detection,
    /// Everything the scan saw, and everywhere it could not look.
    pub outcome: ScanOutcome,
}

/// A complete inventory artifact: what a scan found, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    /// Where this artifact sits in the chain.
    pub header: ArtifactHeader,
    /// What the scan found.
    pub body: Body,
}

impl Inventory {
    /// The digest of this artifact's content, in canonical form.
    ///
    /// Independent of traversal order, of the storage engine, and of the machine
    /// computing it.
    #[must_use]
    pub fn content_digest(&self) -> Digest {
        canonical::content_digest(&self.body, &[])
    }

    /// Whether this artifact's paths can be acted on by this machine.
    ///
    /// An artifact from a machine that spells paths differently can be read,
    /// compared, and displayed, but its paths are renderings rather than
    /// originals, so nothing may be executed against them here.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.body.is_native()
    }

    /// Writes the artifact.
    ///
    /// Refuses if something is already there. Even the tool's own output is not
    /// overwritten without being asked (DR-6); `replace` says yes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AlreadyThere`] if the path is occupied and
    /// `replace` is false, or [`StoreError::Sqlite`] if the write failed.
    pub fn write(&self, path: &Path, replace: Replace) -> Result<(), StoreError> {
        let mut connection = open_for_writing(path, replace)?;
        schema::create(&connection)?;
        let transaction = connection.transaction()?;
        schema::write_body(&transaction, &self.header, &self.body)?;
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
        let (header, body) = schema::read_body(&connection)?;
        check_schema(&header)?;
        let inventory = Self { header, body };

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

impl Body {
    /// Whether these paths can be acted on by this machine.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.path_encoding == scrub_core::paths::LOCAL
    }
}

/// An analysis artifact: everything a scan found, plus what is the same as what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    /// Where this artifact sits in the chain.
    pub header: ArtifactHeader,
    /// What the scan found, carried forward intact.
    pub body: Body,
    /// Files found to hold, or possibly hold, the same content.
    pub groups: Vec<Group>,
    /// What reading established about each entry it reached.
    ///
    /// Kept per entry rather than only per group, because comparing two machines
    /// needs a fingerprint for every file that was read — including the ones
    /// that matched nothing here. Without it a file unique on one machine could
    /// never be recognised on another without reading everything again.
    pub settled: BTreeMap<usize, Settled>,
}

impl Analysis {
    /// The digest of this artifact's content, in canonical form.
    #[must_use]
    pub fn content_digest(&self) -> Digest {
        canonical::analysis_digest(&self.body, &self.groups, &self.settled)
    }

    /// Whether this artifact's paths can be acted on by this machine.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.body.is_native()
    }

    /// Writes the artifact.
    ///
    /// Refuses if something is already there, as [`Inventory::write`] does.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AlreadyThere`] if the path is occupied and
    /// `replace` is false.
    pub fn write(&self, path: &Path, replace: Replace) -> Result<(), StoreError> {
        let mut connection = open_for_writing(path, replace)?;
        schema::create(&connection)?;
        schema::create_groups(&connection)?;
        let transaction = connection.transaction()?;
        schema::write_body(&transaction, &self.header, &self.body)?;
        schema::write_groups(&transaction, &self.groups)?;
        schema::write_settled(&transaction, &self.settled)?;
        transaction.commit()?;
        Ok(())
    }

    /// Reads an analysis.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ContentAltered`] if the recorded digest does not
    /// match the content.
    pub fn read(path: &Path) -> Result<Self, StoreError> {
        // DR-11-EXEMPT: as above.
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        let (header, body) = schema::read_body(&connection)?;
        check_schema(&header)?;
        let analysis = Self {
            header,
            body,
            groups: schema::read_groups(&connection)?,
            settled: schema::read_settled(&connection)?,
        };

        let actual = analysis.content_digest();
        if actual != analysis.header.content_digest {
            return Err(StoreError::ContentAltered {
                recorded: analysis.header.content_digest,
                found: actual,
            });
        }
        Ok(analysis)
    }
}

/// A plan artifact: what a scan found, and what somebody intends to do about it.
///
/// Carries the whole body forward, so a plan can be reviewed — and its diff
/// read — on a machine that holds neither the files nor the analysis (DR-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Where this artifact sits in the chain.
    pub header: ArtifactHeader,
    /// What the scan found, carried forward intact.
    pub body: Body,
    /// What should happen, in the order it should happen.
    pub operations: Vec<Operation>,
}

impl Plan {
    /// The digest of this artifact's content, in canonical form.
    #[must_use]
    pub fn content_digest(&self) -> Digest {
        canonical::plan_digest(&self.body, &self.operations)
    }

    /// Whether these paths can be acted on by this machine.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.body.is_native()
    }

    /// Places two operations would collide, or that are already taken.
    #[must_use]
    pub fn conflicts(&self) -> Vec<scrub_core::plan::Conflict> {
        scrub_core::plan::conflicts(&self.body.outcome.entries, &self.operations)
    }

    /// What carrying this out would achieve.
    #[must_use]
    pub fn effect(&self) -> scrub_core::plan::Effect {
        scrub_core::plan::effect(&self.body.outcome.entries, &self.operations)
    }

    /// Writes the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AlreadyThere`] if the path is occupied and
    /// `replace` is false.
    pub fn write(&self, path: &Path, replace: Replace) -> Result<(), StoreError> {
        let mut connection = open_for_writing(path, replace)?;
        schema::create(&connection)?;
        schema::create_groups(&connection)?;
        let transaction = connection.transaction()?;
        schema::write_body(&transaction, &self.header, &self.body)?;
        schema::write_operations(&transaction, &self.body.outcome.entries, &self.operations)?;
        transaction.commit()?;
        Ok(())
    }

    /// Reads a plan.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ContentAltered`] if the recorded digest does not
    /// match the content.
    pub fn read(path: &Path) -> Result<Self, StoreError> {
        // DR-11-EXEMPT: the tool's own artifact, never a path discovered by a
        // scan.
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        let (header, body) = schema::read_body(&connection)?;
        check_schema(&header)?;
        let plan = Self {
            header,
            body,
            operations: schema::read_operations(&connection)?,
        };

        let actual = plan.content_digest();
        if actual != plan.header.content_digest {
            return Err(StoreError::ContentAltered {
                recorded: plan.header.content_digest,
                found: actual,
            });
        }
        Ok(plan)
    }
}

/// A preflight artifact: a plan, and what checking it against the disk found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preflight {
    /// Where this artifact sits in the chain.
    pub header: ArtifactHeader,
    /// What the scan found, carried forward intact.
    pub body: Body,
    /// What the plan says should happen.
    pub operations: Vec<Operation>,
    /// What checking each operation found.
    pub verdicts: Vec<Verdict>,
}

impl Preflight {
    /// The digest of this artifact's content, in canonical form.
    #[must_use]
    pub fn content_digest(&self) -> Digest {
        canonical::preflight_digest(&self.body, &self.operations, &self.verdicts)
    }

    /// Whether these paths can be acted on by this machine.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.body.is_native()
    }

    /// How the verdicts came out.
    #[must_use]
    pub fn standing(&self) -> scrub_core::preflight::Standing {
        scrub_core::preflight::standing(&self.verdicts)
    }

    /// The operations that will run, in plan order.
    #[must_use]
    pub fn passing(&self) -> Vec<usize> {
        scrub_core::preflight::passing(&self.verdicts)
    }

    /// Writes the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AlreadyThere`] if the path is occupied and
    /// `replace` is false.
    pub fn write(&self, path: &Path, replace: Replace) -> Result<(), StoreError> {
        let mut connection = open_for_writing(path, replace)?;
        schema::create(&connection)?;
        schema::create_groups(&connection)?;
        let transaction = connection.transaction()?;
        schema::write_body(&transaction, &self.header, &self.body)?;
        schema::write_operations(&transaction, &self.body.outcome.entries, &self.operations)?;
        schema::write_verdicts(&transaction, &self.verdicts)?;
        transaction.commit()?;
        Ok(())
    }

    /// Reads a preflight.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ContentAltered`] if the recorded digest does not
    /// match the content. That check matters more here than anywhere: this is
    /// the artifact that decides what is allowed to touch a user's files.
    pub fn read(path: &Path) -> Result<Self, StoreError> {
        // DR-11-EXEMPT: the tool's own artifact, never a path from a scan.
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        let (header, body) = schema::read_body(&connection)?;
        check_schema(&header)?;
        let preflight = Self {
            header,
            body,
            operations: schema::read_operations(&connection)?,
            verdicts: schema::read_verdicts(&connection)?,
        };

        let actual = preflight.content_digest();
        if actual != preflight.header.content_digest {
            return Err(StoreError::ContentAltered {
                recorded: preflight.header.content_digest,
                found: actual,
            });
        }
        Ok(preflight)
    }
}

/// A journal artifact: a run, recorded as it happened.
///
/// The only artifact written a piece at a time. Every other one is produced
/// whole and then stored; this one has to survive the process being killed
/// halfway through, so each step is written as it is attempted and the header is
/// completed at the end (DR-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    /// Where this artifact sits in the chain.
    pub header: ArtifactHeader,
    /// What the scan found, carried forward intact.
    pub body: Body,
    /// What the plan said should happen.
    pub operations: Vec<Operation>,
    /// What actually happened, in the order it happened.
    pub steps: Vec<Step>,
    /// Whether the run reached its end.
    ///
    /// A journal that was never finished describes a run that stopped part-way.
    /// It is still complete enough to undo, which is the point of writing each
    /// step as it is attempted.
    pub finished: bool,
}

/// The digest an unfinished run carries until it finishes.
const UNFINISHED: [u8; 32] = [0; 32];

impl Journal {
    /// The digest of what this run did.
    #[must_use]
    pub fn content_digest(&self) -> Digest {
        canonical::journal_digest(&self.body, &self.operations, &self.steps)
    }

    /// Whether these paths can be acted on by this machine.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.body.is_native()
    }

    /// How the run came out.
    #[must_use]
    pub fn tally(&self) -> scrub_core::journal::Tally {
        let entries = &self.body.outcome.entries;
        let operations = &self.operations;
        scrub_core::journal::tally(&self.steps, |step| {
            operations
                .get(step.operation)
                .map_or(0, |operation| operation.frees(entries))
        })
    }

    /// Starts a journal, on disk, before anything is done.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AlreadyThere`] if the path is occupied and
    /// `replace` is false.
    pub fn begin(
        path: &Path,
        header: &ArtifactHeader,
        body: &Body,
        operations: &[Operation],
        replace: Replace,
    ) -> Result<Connection, StoreError> {
        let mut connection = open_for_writing(path, replace)?;
        schema::create(&connection)?;
        schema::create_groups(&connection)?;

        let mut opening = header.clone();
        opening.content_digest = Digest::from_bytes(UNFINISHED);

        let transaction = connection.transaction()?;
        schema::write_body(&transaction, &opening, body)?;
        schema::write_operations(&transaction, &body.outcome.entries, operations)?;
        transaction.commit()?;
        Ok(connection)
    }

    /// Records one step as it is attempted.
    ///
    /// # Errors
    ///
    /// Returns the underlying storage error.
    pub fn record(connection: &Connection, sequence: usize, step: &Step) -> Result<(), StoreError> {
        schema::write_step(connection, sequence, step)
    }

    /// Marks a run as having finished.
    ///
    /// # Errors
    ///
    /// Returns the underlying storage error.
    pub fn finish(connection: &Connection, digest: Digest) -> Result<(), StoreError> {
        schema::finalize(connection, digest)
    }

    /// Reads a run back.
    ///
    /// An unfinished run is returned rather than refused: it describes changes
    /// that were made, and refusing to read it would leave them with no way back
    /// (DR-10).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ContentAltered`] if a finished run's record no
    /// longer matches its digest.
    pub fn read(path: &Path) -> Result<Self, StoreError> {
        // DR-11-EXEMPT: the tool's own artifact, never a path from a scan.
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        let (header, body) = schema::read_body(&connection)?;
        check_schema(&header)?;

        let finished = header.content_digest != Digest::from_bytes(UNFINISHED);
        let journal = Self {
            header,
            body,
            operations: schema::read_operations(&connection)?,
            steps: schema::read_steps(&connection)?,
            finished,
        };

        if finished {
            let actual = journal.content_digest();
            if actual != journal.header.content_digest {
                return Err(StoreError::ContentAltered {
                    recorded: journal.header.content_digest,
                    found: actual,
                });
            }
        }
        Ok(journal)
    }
}

/// Whether an artifact may take the place of one already there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replace {
    /// Refuse, and say what is in the way.
    Never,
    /// Remove what is there first. Only ever from an explicit instruction.
    Yes,
}

/// Opens a path for a fresh artifact, refusing to displace one silently.
fn open_for_writing(path: &Path, replace: Replace) -> Result<Connection, StoreError> {
    // DR-11-EXEMPT: the tool's own artifact, at a location the user named for
    // it, and never a path discovered by a scan.
    if path.exists() {
        if replace == Replace::Never {
            return Err(StoreError::AlreadyThere {
                path: path.to_path_buf(),
            });
        }
        // DR-11-EXEMPT: as above. Removing first rather than writing into an
        // existing database, which would append a second set of tables to
        // someone else's file and produce an artifact that is neither.
        std::fs::remove_file(path).map_err(|source| StoreError::CouldNotReplace {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(Connection::open(path)?)
}

/// Rejects an artifact this build cannot read, before anything else is judged.
///
/// Checked ahead of the content digest so that a schema change reports itself as
/// a schema change. An artifact written before the canonical form changed has a
/// digest that no longer matches, and saying "somebody edited your file" about an
/// ordinary version difference would be alarming and wrong.
fn check_schema(header: &ArtifactHeader) -> Result<(), StoreError> {
    if header.schema_version == scrub_core::artifact::SCHEMA_VERSION {
        return Ok(());
    }
    Err(StoreError::WrongSchema {
        expected: scrub_core::artifact::SCHEMA_VERSION,
        found: header.schema_version,
    })
}

/// A failure reading or writing an artifact.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused the operation.
    #[error("artifact storage failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The artifact was written by a build with a different artifact schema.
    #[error(
        "this artifact was written with schema version {found}, and this build \
         reads version {expected}. It is not damaged — the format changed. \
         Produce it again with this build."
    )]
    WrongSchema {
        /// What this build reads.
        expected: u32,
        /// What the artifact declares.
        found: u32,
    },

    /// Something is already at the path the artifact would be written to.
    #[error(
        "{path} already exists, and nothing is overwritten without being asked. \
         Choose another name, or pass --replace to write over it."
    )]
    AlreadyThere {
        /// What is in the way.
        path: std::path::PathBuf,
    },

    /// The existing file could not be removed to make room.
    #[error("could not replace {path}: {source}")]
    CouldNotReplace {
        /// What could not be removed.
        path: std::path::PathBuf,
        /// Why not.
        source: std::io::Error,
    },

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
            "path_encoding": inventory.body.path_encoding,
        }),
    )?;

    for root in &inventory.body.detection.roots {
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

    for link in &inventory.body.detection.links {
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

    for entry in &inventory.body.outcome.entries {
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

    for place in &inventory.body.outcome.unread {
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
