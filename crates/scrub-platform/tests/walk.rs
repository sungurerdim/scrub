//! Traversal against a real filesystem, on a tree built for the occasion.
//!
//! The tree is generated rather than committed, so it can contain things a
//! repository cannot hold: hard links, symbolic links that leave the tree, a
//! cycle, a directory nobody may enter. Every case here is one that would
//! otherwise be discovered on a user's machine.

use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

use scrub_core::cloud::CloudMap;
#[cfg(unix)]
use scrub_core::inventory::UnreadReason;
use scrub_core::inventory::{Entry, EntryKind, ScanOutcome};
use scrub_platform::{enter_read_only_scan_mode, walk::walk};

/// The fixture tree, plus the directory that exists only to be linked to.
///
/// Both are held so that both are removed: a test that leaves directories
/// behind on every run is a test that slowly fills a developer's disk.
struct Fixture {
    tree: tempfile::TempDir,
    _outside: tempfile::TempDir,
}

impl Fixture {
    fn path(&self) -> &Path {
        self.tree.path()
    }
}

/// Builds the fixture tree.
fn fixture() -> Fixture {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let elsewhere = tempfile::tempdir().expect("a second temporary directory");
    let root = temporary.path();

    fs::write(root.join("report.pdf"), vec![b'a'; 4_000]).expect("write report");
    fs::create_dir(root.join("papers")).expect("create papers");
    fs::write(root.join("papers/notes.txt"), b"notes").expect("write notes");

    // The same bytes under two names. Removing both frees one file's worth.
    fs::hard_link(root.join("report.pdf"), root.join("report-copy.pdf")).expect("hard link");

    // A name that is not ASCII, and one that is not even valid Unicode-adjacent
    // in the naive sense: both must survive intact.
    fs::write(root.join("papers/özet çalışma.txt"), b"ozet").expect("write unicode");
    fs::write(root.join("papers/\u{1F4C4} plan.md"), b"plan").expect("write emoji");

    // A directory outside the tree, reachable only through a link.
    let outside = elsewhere.path();
    fs::write(outside.join("secret.txt"), b"outside").expect("write outside");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(root.join("papers"), root.join("papers-link")).expect("link to papers");
        symlink(outside, root.join("outward-link")).expect("link outward");
        // A cycle. Following links would never terminate.
        symlink(root, root.join("papers/loop")).expect("cyclic link");
    }

    Fixture {
        tree: temporary,
        _outside: elsewhere,
    }
}

fn scan(root: &Path) -> ScanOutcome {
    let mode = enter_read_only_scan_mode().expect("read-only scan mode");
    walk(root, &CloudMap::default(), &mode)
}

fn named<'a>(outcome: &'a ScanOutcome, name: &str) -> Option<&'a Entry> {
    outcome
        .entries
        .iter()
        .find(|entry| entry.path.file_name().is_some_and(|found| found == name))
}

#[cfg(unix)]
fn paths(outcome: &ScanOutcome) -> Vec<PathBuf> {
    outcome
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect()
}

#[test]
fn a_tree_with_a_cycle_still_terminates() {
    // Not a formality: following links here loops forever, and a scan that never
    // finishes is indistinguishable from a hung application.
    let tree = fixture();
    let outcome = scan(tree.path());
    assert!(!outcome.entries.is_empty());
}

#[test]
fn ordinary_files_and_directories_are_recorded() {
    let tree = fixture();
    let outcome = scan(tree.path());

    let report = named(&outcome, "report.pdf").expect("report.pdf must be found");
    assert_eq!(report.kind, EntryKind::File);
    assert_eq!(report.logical_size, 4_000);

    let papers = named(&outcome, "papers").expect("papers must be found");
    assert_eq!(papers.kind, EntryKind::Directory);

    assert!(named(&outcome, "notes.txt").is_some());
}

#[test]
fn names_that_are_not_ascii_survive_intact() {
    // Turkish characters and an emoji. A scanner that mangles either produces
    // paths that cannot be acted on later, which turns a plan into a set of
    // operations that all fail at apply time.
    let tree = fixture();
    let outcome = scan(tree.path());

    assert!(
        named(&outcome, "özet çalışma.txt").is_some(),
        "a Turkish filename must round-trip"
    );
    assert!(
        named(&outcome, "\u{1F4C4} plan.md").is_some(),
        "an emoji filename must round-trip"
    );
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_recorded_but_not_followed() {
    // The headline rule (DR-22). `papers-link` points at `papers`; if traversal
    // followed it, every file in `papers` would be counted twice and every
    // duplicate report would be wrong.
    let tree = fixture();
    let outcome = scan(tree.path());

    let link = named(&outcome, "papers-link").expect("the link must be recorded");
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(
        link.link_target.as_deref(),
        Some(tree.path().join("papers").as_path())
    );

    let through_the_link = tree.path().join("papers-link/notes.txt");
    assert!(
        !paths(&outcome).contains(&through_the_link),
        "traversal must not descend through a symbolic link"
    );

    let notes_entries = outcome
        .entries
        .iter()
        .filter(|entry| {
            entry
                .path
                .file_name()
                .is_some_and(|name| name == "notes.txt")
        })
        .count();
    assert_eq!(notes_entries, 1, "notes.txt must be counted exactly once");
}

#[cfg(unix)]
#[test]
fn a_link_leading_out_of_the_tree_does_not_drag_the_target_in() {
    // The failure this guards is the one that loses files: a folder outside the
    // scanned tree appearing inside it, and therefore appearing to be covered by
    // whatever the tree is covered by.
    let tree = fixture();
    let outcome = scan(tree.path());

    let link = named(&outcome, "outward-link").expect("the outward link must be recorded");
    assert_eq!(link.kind, EntryKind::Symlink);
    assert!(
        named(&outcome, "secret.txt").is_none(),
        "content outside the tree must not appear inside it"
    );
}

#[cfg(unix)]
#[test]
fn hard_linked_names_share_an_identity_and_are_counted_once() {
    // Two names, one set of bytes. Reporting 8 KB of recoverable space where
    // deleting both frees 4 KB is the kind of claim that makes a user delete
    // more than they meant to (DR-16).
    let tree = fixture();
    let outcome = scan(tree.path());

    let original = named(&outcome, "report.pdf").expect("report.pdf");
    let copy = named(&outcome, "report-copy.pdf").expect("report-copy.pdf");

    assert_eq!(
        original.file_id, copy.file_id,
        "hard links share an identity"
    );
    assert!(original.file_id.is_some(), "an identity must be available");
    assert_eq!(original.link_count, 2);
    assert_eq!(copy.link_count, 2);

    let one_file = original
        .allocated_size
        .expect("macOS reports allocation size");
    let pair = ScanOutcome {
        entries: vec![original.clone(), copy.clone()],
        unread: Vec::new(),
    };
    assert_eq!(
        pair.reclaimable_bytes(),
        one_file,
        "two names for one set of bytes must be counted once, not twice"
    );
}

#[cfg(unix)]
#[test]
fn a_directory_we_may_not_enter_is_recorded_as_unread_not_empty() {
    // DR-23. Reporting this as empty would report its contents as missing, and a
    // user acting on that would go looking for files that never left.
    use std::os::unix::fs::PermissionsExt as _;

    let tree = fixture();
    let locked = tree.path().join("locked");
    fs::create_dir(&locked).expect("create locked");
    fs::write(locked.join("hidden.txt"), b"hidden").expect("write hidden");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("remove permissions");

    if fs::read_dir(&locked).is_ok() {
        // Elevated privileges defeat the permission bits, so the situation this
        // test is about cannot be produced here. Checking the condition itself
        // rather than guessing from the user id: what matters is whether the
        // directory is actually unreadable, not who we are.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore");
        return;
    }

    let outcome = scan(tree.path());

    // Restore before any assertion, so a failure cannot leave an unreadable
    // directory behind for the temporary directory's own cleanup.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore permissions");

    let recorded = outcome
        .unread
        .iter()
        .find(|unread| unread.path == locked)
        .expect("the unreadable directory must be recorded");
    assert_eq!(recorded.reason, UnreadReason::PermissionDenied);
    assert!(
        !outcome.is_complete(),
        "the scan must report itself incomplete"
    );
    assert!(
        named(&outcome, "hidden.txt").is_none(),
        "nothing inside it can have been read"
    );
}
