//! The SQLite schema, and the code that fills and reads it.
//!
//! Written to be legible to someone who opens the file in a database browser
//! with no idea what this tool is: tables named after what they hold, one row
//! per thing, and enumerated values stored as their names rather than as
//! numbers nobody can interpret.
//!
//! Paths are stored as text, which reproduces very nearly all of them exactly,
//! plus the original bytes for the few where it would not. `path_text` is
//! therefore always populated and always queryable with `LIKE`; `path` is null
//! unless the text form would lose something, which on a real machine is a
//! handful of entries out of millions. Storing the bytes unconditionally doubled
//! the size of a home-directory artifact and bought nothing.

use rusqlite::{Connection, Transaction, params};
use scrub_core::artifact::{ArtifactHeader, ArtifactKind, Digest, MachineScope, Stage};
use scrub_core::cloud::{CloudRoot, CloudState, Detection, LinkVerdict, Provider, ProviderLink};
use scrub_core::inventory::{Entry, EntryKind, FileId, ScanOutcome, Unread, UnreadReason};
use scrub_core::paths::{PathEncoding, StoredPath};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Inventory, StoreError};

const SCHEMA: &str = "
CREATE TABLE header (
    schema_version INTEGER NOT NULL,
    tool_version   TEXT    NOT NULL,
    stage          TEXT    NOT NULL,
    kind           TEXT    NOT NULL,
    parents        TEXT    NOT NULL,
    machine        TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    scope_digest   TEXT    NOT NULL,
    content_digest TEXT    NOT NULL,
    path_encoding  TEXT    NOT NULL
) STRICT;

CREATE TABLE cloud_root (
    path      BLOB,
    path_text TEXT NOT NULL,
    provider  TEXT NOT NULL,
    account   TEXT,
    origin    TEXT NOT NULL
) STRICT;

CREATE TABLE cloud_link (
    link        BLOB,
    link_text   TEXT NOT NULL,
    target      BLOB,
    target_text TEXT NOT NULL,
    provider    TEXT NOT NULL,
    verdict     TEXT NOT NULL
) STRICT;

CREATE TABLE entry (
    path            BLOB,
    path_text       TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    logical_size    INTEGER NOT NULL,
    allocated_size  INTEGER,
    created         TEXT,
    modified        TEXT,
    file_volume     INTEGER,
    file_index      INTEGER,
    link_count      INTEGER NOT NULL,
    link_target     BLOB,
    link_target_text TEXT,
    cloud           TEXT    NOT NULL
) STRICT;

CREATE INDEX entry_by_path ON entry (path_text);
CREATE INDEX entry_by_size ON entry (logical_size);

CREATE TABLE unread (
    path      BLOB,
    path_text TEXT NOT NULL,
    reason    TEXT NOT NULL
) STRICT;
";

/// Creates an empty artifact.
pub fn create(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(SCHEMA)?;
    Ok(())
}

/// Writes an entire inventory.
pub fn write_all(transaction: &Transaction<'_>, inventory: &Inventory) -> Result<(), StoreError> {
    let header = &inventory.header;
    transaction.execute(
        "INSERT INTO header VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            header.schema_version,
            header.tool_version,
            to_json(&header.stage),
            to_json(&header.kind),
            to_json(&header.parents),
            to_json(&header.machine),
            header.created_at.to_string(),
            header.scope_digest.to_hex(),
            header.content_digest.to_hex(),
            to_json(&inventory.path_encoding),
        ],
    )?;

    let mut roots = transaction.prepare("INSERT INTO cloud_root VALUES (?1, ?2, ?3, ?4, ?5)")?;
    for root in &inventory.detection.roots {
        let stored = StoredPath::of(&root.path);
        roots.execute(params![
            exact_bytes(&stored),
            stored.display,
            to_json(&root.provider),
            root.account,
            to_json(&root.origin),
        ])?;
    }
    drop(roots);

    let mut links =
        transaction.prepare("INSERT INTO cloud_link VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
    for link in &inventory.detection.links {
        let from = StoredPath::of(&link.link);
        let to = StoredPath::of(&link.target);
        links.execute(params![
            exact_bytes(&from),
            from.display,
            exact_bytes(&to),
            to.display,
            to_json(&link.provider),
            to_json(&link.verdict),
        ])?;
    }
    drop(links);

    let mut entries = transaction.prepare(
        "INSERT INTO entry VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )?;
    for entry in &inventory.outcome.entries {
        let stored = StoredPath::of(&entry.path);
        let target = entry.link_target.as_ref().map(|path| StoredPath::of(path));
        entries.execute(params![
            exact_bytes(&stored),
            stored.display,
            to_json(&entry.kind),
            store(entry.logical_size),
            entry.allocated_size.map(store),
            entry.created.map(|when| when.to_string()),
            entry.modified.map(|when| when.to_string()),
            entry.file_id.map(|id| store(id.volume)),
            entry.file_id.map(|id| store(id.index)),
            store(entry.link_count),
            target.as_ref().and_then(exact_bytes),
            target.as_ref().map(|stored| stored.display.clone()),
            to_json(&entry.cloud),
        ])?;
    }
    drop(entries);

    let mut unread = transaction.prepare("INSERT INTO unread VALUES (?1, ?2, ?3)")?;
    for place in &inventory.outcome.unread {
        let stored = StoredPath::of(&place.path);
        unread.execute(params![
            exact_bytes(&stored),
            stored.display,
            to_json(&place.reason)
        ])?;
    }
    drop(unread);

    Ok(())
}

/// Reads an entire inventory.
pub fn read_all(connection: &Connection) -> Result<Inventory, StoreError> {
    let raw = connection.query_row("SELECT * FROM header", [], |row| {
        Ok(HeaderRow {
            schema_version: row.get(0)?,
            tool_version: row.get(1)?,
            stage: row.get(2)?,
            kind: row.get(3)?,
            parents: row.get(4)?,
            machine: row.get(5)?,
            created_at: row.get(6)?,
            scope_digest: row.get(7)?,
            content_digest: row.get(8)?,
            path_encoding: row.get(9)?,
        })
    })?;

    let header = ArtifactHeader {
        schema_version: raw.schema_version,
        tool_version: raw.tool_version,
        stage: from_json::<Stage>("stage", &raw.stage)?,
        kind: from_json::<ArtifactKind>("kind", &raw.kind)?,
        parents: from_json::<Vec<Digest>>("parents", &raw.parents)?,
        machine: from_json::<MachineScope>("machine", &raw.machine)?,
        created_at: raw
            .created_at
            .parse()
            .map_err(|error| StoreError::Malformed {
                field: "created_at",
                detail: format!("{error}"),
            })?,
        scope_digest: parse_digest("scope_digest", &raw.scope_digest)?,
        content_digest: parse_digest("content_digest", &raw.content_digest)?,
    };
    let path_encoding = from_json::<PathEncoding>("path_encoding", &raw.path_encoding)?;

    Ok(Inventory {
        header,
        path_encoding,
        detection: Detection {
            roots: read_roots(connection, path_encoding)?,
            links: read_links(connection, path_encoding)?,
        },
        outcome: ScanOutcome {
            entries: read_entries(connection, path_encoding)?,
            unread: read_unread(connection, path_encoding)?,
        },
    })
}

fn read_roots(
    connection: &Connection,
    path_encoding: PathEncoding,
) -> Result<Vec<CloudRoot>, StoreError> {
    let mut statement = connection.prepare("SELECT * FROM cloud_root ORDER BY rowid")?;
    let roots = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let roots = roots
        .into_iter()
        .map(|(bytes, text, provider, account, origin)| {
            Ok(CloudRoot {
                path: revive(bytes.as_deref(), &text, path_encoding),
                provider: from_json::<Provider>("cloud_root.provider", &provider)?,
                account,
                origin: from_json("cloud_root.origin", &origin)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(roots)
}

fn read_links(
    connection: &Connection,
    path_encoding: PathEncoding,
) -> Result<Vec<ProviderLink>, StoreError> {
    let mut statement = connection.prepare("SELECT * FROM cloud_link ORDER BY rowid")?;
    let links = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let links = links
        .into_iter()
        .map(
            |(link_bytes, link_text, target_bytes, target_text, provider, verdict)| {
                Ok(ProviderLink {
                    link: revive(link_bytes.as_deref(), &link_text, path_encoding),
                    target: revive(target_bytes.as_deref(), &target_text, path_encoding),
                    provider: from_json::<Provider>("cloud_link.provider", &provider)?,
                    verdict: from_json::<LinkVerdict>("cloud_link.verdict", &verdict)?,
                })
            },
        )
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(links)
}

fn read_entries(
    connection: &Connection,
    path_encoding: PathEncoding,
) -> Result<Vec<Entry>, StoreError> {
    let mut statement = connection.prepare("SELECT * FROM entry ORDER BY rowid")?;
    let rows = statement
        .query_map([], |row| {
            Ok(EntryRow {
                path: row.get(0)?,
                path_text: row.get(1)?,
                kind: row.get(2)?,
                logical_size: row.get(3)?,
                allocated_size: row.get(4)?,
                created: row.get(5)?,
                modified: row.get(6)?,
                file_volume: row.get(7)?,
                file_index: row.get(8)?,
                link_count: row.get(9)?,
                link_target: row.get(10)?,
                link_target_text: row.get(11)?,
                cloud: row.get(12)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let entries = rows
        .into_iter()
        .map(|row| row.into_entry(path_encoding))
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(entries)
}

fn read_unread(
    connection: &Connection,
    path_encoding: PathEncoding,
) -> Result<Vec<Unread>, StoreError> {
    let mut statement = connection.prepare("SELECT * FROM unread ORDER BY rowid")?;
    let places = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let unread = places
        .into_iter()
        .map(|(bytes, text, reason)| {
            Ok(Unread {
                path: revive(bytes.as_deref(), &text, path_encoding),
                reason: from_json::<UnreadReason>("unread.reason", &reason)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(unread)
}

/// One row of the header table, before it becomes an [`ArtifactHeader`].
struct HeaderRow {
    schema_version: u32,
    tool_version: String,
    stage: String,
    kind: String,
    parents: String,
    machine: String,
    created_at: String,
    scope_digest: String,
    content_digest: String,
    path_encoding: String,
}

fn parse_digest(field: &'static str, text: &str) -> Result<Digest, StoreError> {
    Digest::from_hex(text).map_err(|error| StoreError::Malformed {
        field,
        detail: format!("{error}"),
    })
}

/// One row of the entry table, before it becomes an [`Entry`].
struct EntryRow {
    path: Option<Vec<u8>>,
    path_text: String,
    kind: String,
    logical_size: i64,
    allocated_size: Option<i64>,
    created: Option<String>,
    modified: Option<String>,
    file_volume: Option<i64>,
    file_index: Option<i64>,
    link_count: i64,
    link_target: Option<Vec<u8>>,
    link_target_text: Option<String>,
    cloud: String,
}

impl EntryRow {
    fn into_entry(self, encoding: PathEncoding) -> Result<Entry, StoreError> {
        let link_target = match (&self.link_target, &self.link_target_text) {
            (bytes, Some(text)) => Some(revive(bytes.as_deref(), text, encoding)),
            (_, None) => None,
        };
        Ok(Entry {
            path: revive(self.path.as_deref(), &self.path_text, encoding),
            kind: from_json::<EntryKind>("entry.kind", &self.kind)?,
            logical_size: load(self.logical_size),
            allocated_size: self.allocated_size.map(load),
            created: parse_time("entry.created", self.created.as_deref())?,
            modified: parse_time("entry.modified", self.modified.as_deref())?,
            file_id: match (self.file_volume, self.file_index) {
                (Some(volume), Some(index)) => Some(FileId {
                    volume: load(volume),
                    index: load(index),
                }),
                _ => None,
            },
            link_count: load(self.link_count),
            link_target,
            cloud: from_json::<CloudState>("entry.cloud", &self.cloud)?,
        })
    }
}

/// Rebuilds a path, exactly where possible and legibly otherwise.
///
/// An artifact from a machine that spells paths differently cannot have its
/// paths reconstructed here, and that is deliberate: rebuilding Windows bytes as
/// a macOS path would produce something that looks usable and points nowhere.
/// Such an artifact can still be read, compared and displayed — which is all the
/// merge stage needs, since identity comes from content and never from a path
/// (DR-13).
fn revive(bytes: Option<&[u8]>, text: &str, encoding: PathEncoding) -> std::path::PathBuf {
    let Some(bytes) = bytes else {
        // No bytes were kept, which means the text reproduces the path exactly.
        // Anything else would have kept them.
        return std::path::PathBuf::from(text);
    };
    StoredPath {
        bytes: bytes.to_vec(),
        display: text.to_owned(),
    }
    .to_path(encoding)
    .unwrap_or_else(|| std::path::PathBuf::from(text))
}

fn parse_time(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    value
        .map(|text| {
            text.parse::<jiff::Timestamp>()
                .map_err(|error| StoreError::Malformed {
                    field,
                    detail: format!("{error}"),
                })
        })
        .transpose()
}

/// The bytes to keep beside the text, or nothing when the text is exact.
fn exact_bytes(stored: &StoredPath) -> Option<Vec<u8>> {
    if stored.text_is_exact() {
        None
    } else {
        Some(stored.bytes.clone())
    }
}

/// SQLite stores signed 64-bit integers, and some of what we record — a Windows
/// file index in particular — uses the whole unsigned range. The conversion
/// preserves every bit rather than saturating, so a value that reads back as
/// negative in a database browser is still the same identity we wrote.
fn store(value: u64) -> i64 {
    value.cast_signed()
}

fn load(value: i64) -> u64 {
    value.cast_unsigned()
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

fn from_json<T: DeserializeOwned>(field: &'static str, text: &str) -> Result<T, StoreError> {
    serde_json::from_str(text).map_err(|error| StoreError::Malformed {
        field,
        detail: format!("{error}"),
    })
}
