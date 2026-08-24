//! An artifact written and read back, against the values most likely to be lost.

use std::path::PathBuf;

use scrub_core::artifact::{
    ArtifactHeader, Digest, MachineId, MachineScope, SCHEMA_VERSION, Stage,
};
use scrub_core::cloud::{
    CloudRoot, CloudState, Detection, LinkVerdict, Provider, ProviderLink, Residency, Retention,
    RootOrigin,
};
use scrub_core::inventory::{Entry, EntryKind, FileId, ScanOutcome, Unread, UnreadReason};
use scrub_core::paths;
use scrub_store::Inventory;

fn header(content_digest: Digest) -> ArtifactHeader {
    ArtifactHeader {
        schema_version: SCHEMA_VERSION,
        tool_version: "0.0.0".to_owned(),
        stage: Stage::Scan,
        kind: Stage::Scan.output_kind(),
        parents: Vec::new(),
        machine: MachineScope::Single {
            machine: MachineId::generate(),
        },
        created_at: "2026-08-24T09:30:00Z".parse().expect("a valid timestamp"),
        scope_digest: Digest::of(b"scope"),
        content_digest,
    }
}

/// An inventory containing every shape that has somewhere to go wrong.
fn sample() -> Inventory {
    let detection = Detection {
        roots: vec![CloudRoot {
            path: PathBuf::from("/home/Library/CloudStorage/GoogleDrive-someone@example.com"),
            provider: Provider::GoogleDrive,
            account: Some("someone@example.com".to_owned()),
            origin: RootOrigin::ProviderMount,
        }],
        links: vec![ProviderLink {
            link: PathBuf::from("/home/Library/Mobile Documents/com~apple~CloudDocs/Documents"),
            target: PathBuf::from("/home/Documents"),
            provider: Provider::ICloud,
            verdict: LinkVerdict::ExcludedByProvider,
        }],
    };

    let mut entries = vec![
        Entry {
            path: PathBuf::from("/home/papers/özet çalışma.txt"),
            kind: EntryKind::File,
            logical_size: 4_000,
            allocated_size: Some(4_096),
            created: Some("1965-03-01T00:00:00Z".parse().expect("a pre-epoch date")),
            modified: Some("2026-08-01T12:00:00Z".parse().expect("a valid timestamp")),
            // Deliberately beyond the signed range: a Windows file index uses the
            // whole unsigned one, and storage must not quietly saturate it.
            file_id: Some(FileId {
                volume: u64::MAX,
                index: u64::MAX - 7,
            }),
            link_count: 2,
            link_target: None,
            cloud: CloudState::not_synced(),
        },
        Entry {
            path: PathBuf::from("/home/cloud/film.mov"),
            kind: EntryKind::File,
            logical_size: 8_000_000_000,
            allocated_size: Some(0),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState {
                provider: Some(Provider::ICloud),
                residency: Residency::Remote,
                retention: Retention::Unpinned,
            },
        },
        Entry {
            path: PathBuf::from("/home/shortcut"),
            kind: EntryKind::Symlink,
            logical_size: 12,
            allocated_size: Some(0),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: Some(PathBuf::from("/home/papers")),
            cloud: CloudState::not_synced(),
        },
    ];

    // A filename that is legal but not valid UTF-8. It has no faithful text
    // rendering, which is the whole reason paths are stored as bytes.
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        entries.push(Entry {
            path: PathBuf::from(OsString::from_vec(b"/home/broken\xFF\xFEname.txt".to_vec())),
            kind: EntryKind::File,
            logical_size: 1,
            allocated_size: Some(4_096),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState::not_synced(),
        });
    }

    let outcome = ScanOutcome {
        entries,
        unread: vec![Unread {
            path: PathBuf::from("/home/locked"),
            reason: UnreadReason::WouldRequireDownload,
        }],
    };

    let digest = scrub_store::content_digest(&detection, &outcome);
    Inventory {
        header: header(digest),
        path_encoding: paths::LOCAL,
        detection,
        outcome,
    }
}

#[test]
fn an_artifact_survives_being_written_and_read() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");

    let original = sample();
    original.write(&file).expect("the artifact must write");
    let recovered = Inventory::read(&file).expect("the artifact must read back");

    assert_eq!(original, recovered);
}

#[test]
fn a_path_that_is_not_valid_text_comes_back_byte_for_byte() {
    // The failure this guards: an artifact that renders such a path to
    // replacement characters produces a plan whose every operation targets a
    // file that does not exist, and reports them all as vanished.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");

    let original = sample();
    original.write(&file).expect("write");
    let recovered = Inventory::read(&file).expect("read");

    for (before, after) in original
        .outcome
        .entries
        .iter()
        .zip(&recovered.outcome.entries)
    {
        assert_eq!(before.path, after.path, "every path must return unchanged");
    }
}

#[test]
fn an_identity_beyond_the_signed_range_is_preserved() {
    // A Windows file index uses the full unsigned range while SQLite stores
    // signed integers. Saturating here would merge two unrelated files into one
    // identity, and hard-link detection would then hide a real duplicate.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");

    sample().write(&file).expect("write");
    let recovered = Inventory::read(&file).expect("read");

    let identity = recovered
        .outcome
        .entries
        .iter()
        .find_map(|entry| entry.file_id)
        .expect("the entry carrying an identity must be found");
    assert_eq!(identity.volume, u64::MAX);
    assert_eq!(identity.index, u64::MAX - 7);
}

#[test]
fn the_digest_does_not_depend_on_having_been_stored() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");

    let original = sample();
    let before = original.content_digest();
    original.write(&file).expect("write");
    let after = Inventory::read(&file).expect("read").content_digest();

    assert_eq!(
        before, after,
        "a round trip through storage must not change what the content digests to"
    );
}

#[test]
fn content_edited_after_writing_is_refused() {
    // DR-18 at the level of a single file. An artifact that was altered after it
    // was written is not the artifact its header describes, and nothing
    // downstream may act on it.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");
    sample().write(&file).expect("write");

    let connection = rusqlite::Connection::open(&file).expect("open for editing");
    connection
        .execute("UPDATE entry SET logical_size = logical_size + 1", [])
        .expect("edit the artifact behind the tool's back");
    drop(connection);

    let outcome = Inventory::read(&file);
    assert!(
        matches!(outcome, Err(scrub_store::StoreError::ContentAltered { .. })),
        "an altered artifact must be refused, got {outcome:?}"
    );
}

#[test]
fn an_artifact_from_this_machine_is_usable_here() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");
    sample().write(&file).expect("write");
    assert!(Inventory::read(&file).expect("read").is_native());
}
