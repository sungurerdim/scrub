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
use scrub_store::{Body, Inventory};

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

    let body = Body {
        path_encoding: paths::LOCAL,
        detection,
        outcome,
    };
    Inventory {
        header: header(scrub_store::content_digest(&body, &[])),
        body,
    }
}

#[test]
fn an_artifact_survives_being_written_and_read() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");

    let original = sample();
    original
        .write(&file, scrub_store::Replace::Never)
        .expect("the artifact must write");
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
    original
        .write(&file, scrub_store::Replace::Never)
        .expect("write");
    let recovered = Inventory::read(&file).expect("read");

    for (before, after) in original
        .body
        .outcome
        .entries
        .iter()
        .zip(&recovered.body.outcome.entries)
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

    sample()
        .write(&file, scrub_store::Replace::Never)
        .expect("write");
    let recovered = Inventory::read(&file).expect("read");

    let identity = recovered
        .body
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
    original
        .write(&file, scrub_store::Replace::Never)
        .expect("write");
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
    sample()
        .write(&file, scrub_store::Replace::Never)
        .expect("write");

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
    sample()
        .write(&file, scrub_store::Replace::Never)
        .expect("write");
    assert!(Inventory::read(&file).expect("read").is_native());
}

/// The same body, plus what an analysis concluded about it.
fn analysed() -> scrub_store::Analysis {
    use scrub_core::analysis::{Certainty, Group, StorageObject, Unsettled};

    let inventory = sample();
    let groups = vec![
        Group {
            certainty: Certainty::Exact,
            objects: vec![
                StorageObject {
                    names: vec![0],
                    logical_size: 4_000,
                    allocated_size: Some(4_096),
                },
                StorageObject {
                    names: vec![2, 1],
                    logical_size: 4_000,
                    allocated_size: Some(4_096),
                },
            ],
            digest: Some(Digest::of(b"shared content")),
            logical_size: 4_000,
            unsettled: Vec::new(),
            settled_of_same_size: 0,
        },
        Group {
            certainty: Certainty::Candidate,
            objects: vec![StorageObject {
                names: vec![1],
                logical_size: 8_000_000_000,
                allocated_size: Some(0),
            }],
            digest: None,
            logical_size: 8_000_000_000,
            unsettled: vec![Unsettled::WouldRequireDownload {
                bytes: 8_000_000_000,
            }],
            settled_of_same_size: 3,
        },
    ];

    let body = inventory.body;
    let mut header = header(Digest::of(b"placeholder, replaced below"));
    header.stage = Stage::Analyze;
    header.kind = Stage::Analyze.output_kind();
    header.parents = vec![Digest::of(b"the inventory this came from")];

    let settled = std::collections::BTreeMap::from([
        (
            0,
            scrub_core::analysis::Settled::Content(Digest::of(b"shared content")),
        ),
        (
            2,
            scrub_core::analysis::Settled::DistinctBySample(Digest::of(b"a lonely sample")),
        ),
    ]);

    let mut analysis = scrub_store::Analysis {
        header,
        body,
        groups,
        settled,
    };
    analysis.header.content_digest = analysis.content_digest();
    analysis
}

#[test]
fn a_fingerprint_survives_for_every_file_that_was_read() {
    // What makes comparing two machines possible at all. A file that matched
    // nothing here still carries what was learned about it; dropping that would
    // mean reading the whole disk again to compare it with anywhere else.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.analysis");

    let original = analysed();
    original
        .write(&file, scrub_store::Replace::Never)
        .expect("write");
    let recovered = scrub_store::Analysis::read(&file).expect("read");

    assert_eq!(original.settled, recovered.settled);
    assert!(
        matches!(
            recovered.settled.get(&2),
            Some(scrub_core::analysis::Settled::DistinctBySample(_))
        ),
        "a file the sample ruled out keeps its fingerprint and its status"
    );
}

#[test]
fn an_analysis_survives_being_written_and_read() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.analysis");

    let original = analysed();
    original
        .write(&file, scrub_store::Replace::Never)
        .expect("the analysis must write");
    let recovered = scrub_store::Analysis::read(&file).expect("the analysis must read back");

    assert_eq!(original, recovered);
}

#[test]
fn several_names_for_one_object_survive_as_one_object() {
    // The shape that carries DR-16 through storage. Flattening these into
    // separate rows on the way back would turn one set of bytes into several and
    // reinstate the space claim the analysis was careful not to make.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.analysis");

    analysed()
        .write(&file, scrub_store::Replace::Never)
        .expect("write");
    let recovered = scrub_store::Analysis::read(&file).expect("read");

    let exact = recovered
        .groups
        .iter()
        .find(|group| group.digest.is_some())
        .expect("the proven group");
    assert_eq!(exact.objects.len(), 2);
    assert_eq!(
        exact.objects[1].names,
        vec![2, 1],
        "names keep the order they were recorded in"
    );
}

#[test]
fn an_analysis_digests_differently_from_the_inventory_it_came_from() {
    // If the two agreed, a chain check could not tell one from the other, and a
    // plan built from an analysis could be fed an inventory instead.
    assert_ne!(sample().content_digest(), analysed().content_digest());
}

#[test]
fn an_analysis_edited_after_writing_is_refused() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.analysis");
    analysed()
        .write(&file, scrub_store::Replace::Never)
        .expect("write");

    let connection = rusqlite::Connection::open(&file).expect("open for editing");
    connection
        .execute(
            "UPDATE duplicate_group SET logical_size = logical_size + 1",
            [],
        )
        .expect("edit the findings behind the tool's back");
    drop(connection);

    assert!(
        matches!(
            scrub_store::Analysis::read(&file),
            Err(scrub_store::StoreError::ContentAltered { .. })
        ),
        "an altered analysis must be refused"
    );
}

#[test]
fn an_artifact_from_an_older_format_says_so_rather_than_crying_tamper() {
    // The distinction this guards is about trust, not correctness. An artifact
    // written before the canonical form changed has a digest that no longer
    // matches, and the two possible messages could not be further apart: one
    // says the format moved on, the other says somebody edited your file. Firing
    // the second on an ordinary upgrade would teach people to ignore it.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = directory.path().join("scan.inventory");
    sample()
        .write(&file, scrub_store::Replace::Never)
        .expect("write");

    let connection = rusqlite::Connection::open(&file).expect("open for editing");
    connection
        .execute("UPDATE header SET schema_version = schema_version - 1", [])
        .expect("age the artifact by one schema version");
    drop(connection);

    let outcome = Inventory::read(&file);
    assert!(
        matches!(outcome, Err(scrub_store::StoreError::WrongSchema { .. })),
        "an older format is reported as an older format, got {outcome:?}"
    );
}
