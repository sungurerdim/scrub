//! The canonical form an artifact's digest is taken over.
//!
//! Not a serialization format anybody reads: a defined byte stream fed to the
//! hasher, so that the same content always produces the same digest. Every value
//! is length-prefixed and tagged, so no two different contents can produce the
//! same stream by accident — `["ab", "c"]` and `["a", "bc"]` must not collide.
//!
//! Collections are sorted before hashing. Traversal order depends on how the
//! filesystem happens to hand back directory entries, and two scans of an
//! unchanged tree have to agree (DR-12).

use blake3::Hasher;
use scrub_core::analysis::Group;
use scrub_core::artifact::Digest;
use scrub_core::cloud::{CloudRoot, ProviderLink};
use scrub_core::inventory::{Entry, Unread};
use scrub_core::paths::StoredPath;

use crate::Body;

/// The digest of a plan.
///
/// Covers the operations in the order they were recorded, because order is part
/// of what a plan says: creating a directory after moving into it is a different
/// plan from doing it before.
#[must_use]
pub fn plan_digest(
    body: &Body,
    operations: &[scrub_core::plan::Operation],
    edits: &[scrub_core::edit::Edit],
) -> Digest {
    let mut hasher = Hasher::new();
    field(&mut hasher, content_digest(body, &[]).to_hex().as_bytes());
    section(&mut hasher, b"operations", operations.len());
    for operation in operations {
        json(&mut hasher, operation);
    }
    // Covered because they are in the artifact. A digest that only covered the
    // operations would call a plan unaltered after somebody edited the record of
    // what was asked for, which is exactly the kind of quiet difference the
    // chain exists to catch.
    section(&mut hasher, b"edits", edits.len());
    for edit in edits {
        json(&mut hasher, edit);
    }
    Digest::from_bytes(*hasher.finalize().as_bytes())
}

/// The digest of a preflight.
#[must_use]
pub fn preflight_digest(
    body: &Body,
    operations: &[scrub_core::plan::Operation],
    verdicts: &[scrub_core::preflight::Verdict],
) -> Digest {
    let mut hasher = Hasher::new();
    // No edits: a preflight carries the operations, not the intent behind them.
    // A digest has to cover what its own artifact holds and nothing else, or it
    // cannot be recomputed from the artifact — and the intent is still covered,
    // through the parent plan's digest recorded in the header.
    field(
        &mut hasher,
        plan_digest(body, operations, &[]).to_hex().as_bytes(),
    );
    section(&mut hasher, b"verdicts", verdicts.len());
    for verdict in verdicts {
        json(&mut hasher, verdict);
    }
    Digest::from_bytes(*hasher.finalize().as_bytes())
}

/// The digest of a run.
#[must_use]
pub fn journal_digest(
    body: &Body,
    operations: &[scrub_core::plan::Operation],
    steps: &[scrub_core::journal::Step],
) -> Digest {
    let mut hasher = Hasher::new();
    // As above: a record of what happened, not of what was asked for.
    field(
        &mut hasher,
        plan_digest(body, operations, &[]).to_hex().as_bytes(),
    );
    section(&mut hasher, b"steps", steps.len());
    for step in steps {
        json(&mut hasher, step);
    }
    Digest::from_bytes(*hasher.finalize().as_bytes())
}

/// The digest of an artifact's content.
///
/// Covers the scan body and, for an analysis, the groups derived from it. An
/// inventory passes no groups, so an analysis never digests to the same value as
/// the inventory it came from even when it found nothing.
#[must_use]
pub fn analysis_digest(
    body: &Body,
    groups: &[Group],
    settled: &std::collections::BTreeMap<usize, scrub_core::analysis::Settled>,
) -> Digest {
    let mut hasher = Hasher::new();
    field(
        &mut hasher,
        content_digest(body, groups).to_hex().as_bytes(),
    );
    section(&mut hasher, b"settled", settled.len());
    for (index, state) in settled {
        number(&mut hasher, *index as u64);
        json(&mut hasher, state);
    }
    Digest::from_bytes(*hasher.finalize().as_bytes())
}

/// The digest of an artifact's content.
#[must_use]
pub fn content_digest(body: &Body, groups: &[Group]) -> Digest {
    let detection = &body.detection;
    let outcome = &body.outcome;
    let mut hasher = Hasher::new();

    let mut roots: Vec<&CloudRoot> = detection.roots.iter().collect();
    roots.sort_by(|left, right| left.path.cmp(&right.path));
    section(&mut hasher, b"roots", roots.len());
    for root in roots {
        field(&mut hasher, root.path.as_os_str().as_encoded_bytes());
        json(&mut hasher, &root.provider);
        field(
            &mut hasher,
            root.account.as_deref().unwrap_or("").as_bytes(),
        );
        json(&mut hasher, &root.origin);
    }

    let mut links: Vec<&ProviderLink> = detection.links.iter().collect();
    links.sort_by(|left, right| left.link.cmp(&right.link));
    section(&mut hasher, b"links", links.len());
    for link in links {
        field(&mut hasher, link.link.as_os_str().as_encoded_bytes());
        field(&mut hasher, link.target.as_os_str().as_encoded_bytes());
        json(&mut hasher, &link.provider);
        json(&mut hasher, &link.verdict);
    }

    let mut entries: Vec<&Entry> = outcome.entries.iter().collect();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    section(&mut hasher, b"entries", entries.len());
    for entry in entries {
        field(&mut hasher, &StoredPath::of(&entry.path).bytes);
        json(&mut hasher, &entry.kind);
        number(&mut hasher, entry.logical_size);
        optional_number(&mut hasher, entry.allocated_size);
        optional_number(
            &mut hasher,
            entry.created.map(|when| when.as_second().unsigned_abs()),
        );
        optional_number(
            &mut hasher,
            entry.modified.map(|when| when.as_second().unsigned_abs()),
        );
        json(&mut hasher, &entry.file_id);
        number(&mut hasher, entry.link_count);
        match &entry.link_target {
            Some(target) => field(&mut hasher, &StoredPath::of(target).bytes),
            None => field(&mut hasher, b""),
        }
        json(&mut hasher, &entry.cloud);
    }

    let mut unread: Vec<&Unread> = outcome.unread.iter().collect();
    unread.sort_by(|left, right| left.path.cmp(&right.path));
    section(&mut hasher, b"unread", unread.len());
    for place in unread {
        field(&mut hasher, &StoredPath::of(&place.path).bytes);
        json(&mut hasher, &place.reason);
    }

    // Groups are already ordered by size and then by digest, but ordering is
    // asserted here rather than assumed: a change upstream that reshuffled them
    // would otherwise change the digest of identical findings.
    let mut ordered: Vec<&Group> = groups.iter().collect();
    ordered.sort_by(|left, right| {
        left.logical_size
            .cmp(&right.logical_size)
            .then_with(|| left.digest.cmp(&right.digest))
            .then_with(|| {
                left.objects
                    .first()
                    .map(|o| o.names.clone())
                    .cmp(&right.objects.first().map(|o| o.names.clone()))
            })
    });
    section(&mut hasher, b"groups", ordered.len());
    for group in ordered {
        json(&mut hasher, group);
    }

    Digest::from_bytes(*hasher.finalize().as_bytes())
}

/// The digest of what a scan was asked to cover.
///
/// Recorded in the header so a later stage can tell that an artifact describes a
/// different part of the disk than the one it expected, rather than silently
/// treating a partial scan as a complete one.
#[must_use]
pub fn scope_digest(roots: &[std::path::PathBuf]) -> Digest {
    let mut sorted: Vec<&std::path::PathBuf> = roots.iter().collect();
    sorted.sort();

    let mut hasher = Hasher::new();
    section(&mut hasher, b"scope", sorted.len());
    for root in sorted {
        field(&mut hasher, &StoredPath::of(root).bytes);
    }
    Digest::from_bytes(*hasher.finalize().as_bytes())
}

/// Marks the start of a collection and how many items follow.
fn section(hasher: &mut Hasher, name: &[u8], count: usize) {
    field(hasher, name);
    number(hasher, count as u64);
}

/// Feeds one value, prefixed by its length so it cannot run into the next.
fn field(hasher: &mut Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn number(hasher: &mut Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

/// Distinguishes "absent" from "zero", which are different facts.
fn optional_number(hasher: &mut Hasher, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            number(hasher, value);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

/// Feeds a value through its serialized form.
///
/// Serde emits a struct's fields in declaration order, so this is stable for a
/// given schema version; a schema change that reorders fields changes the
/// digest, which is correct — it is a different artifact shape.
fn json(hasher: &mut Hasher, value: &impl serde::Serialize) {
    let encoded = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    field(hasher, &encoded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrub_core::cloud::Detection;
    use scrub_core::cloud::{CloudState, Provider, RootOrigin};
    use scrub_core::inventory::{EntryKind, ScanOutcome};
    use std::path::PathBuf;

    fn entry(path: &str, size: u64) -> Entry {
        Entry {
            path: PathBuf::from(path),
            kind: EntryKind::File,
            logical_size: size,
            allocated_size: Some(4_096),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState::not_synced(),
        }
    }

    fn outcome(entries: Vec<Entry>) -> Body {
        body(Detection::default(), entries)
    }

    fn body(detection: Detection, entries: Vec<Entry>) -> Body {
        Body {
            path_encoding: scrub_core::paths::LOCAL,
            detection,
            outcome: ScanOutcome {
                entries,
                unread: Vec::new(),
            },
        }
    }

    #[test]
    fn the_same_content_digests_the_same() {
        let one = outcome(vec![entry("/a.txt", 10), entry("/b.txt", 20)]);
        let two = outcome(vec![entry("/a.txt", 10), entry("/b.txt", 20)]);
        assert_eq!(content_digest(&one, &[]), content_digest(&two, &[]));
    }

    #[test]
    fn traversal_order_does_not_change_the_digest() {
        // Directory enumeration order is the filesystem's business and varies
        // between runs. If it changed the digest, "nothing has changed since
        // last time" could never be stated.
        let forwards = outcome(vec![entry("/a.txt", 10), entry("/b.txt", 20)]);
        let backwards = outcome(vec![entry("/b.txt", 20), entry("/a.txt", 10)]);
        assert_eq!(
            content_digest(&forwards, &[]),
            content_digest(&backwards, &[])
        );
    }

    #[test]
    fn a_changed_size_changes_the_digest() {
        let before = outcome(vec![entry("/a.txt", 10)]);
        let after = outcome(vec![entry("/a.txt", 11)]);
        assert_ne!(content_digest(&before, &[]), content_digest(&after, &[]));
    }

    #[test]
    fn a_removed_file_changes_the_digest() {
        let before = outcome(vec![entry("/a.txt", 10), entry("/b.txt", 20)]);
        let after = outcome(vec![entry("/a.txt", 10)]);
        assert_ne!(content_digest(&before, &[]), content_digest(&after, &[]));
    }

    #[test]
    fn adjacent_fields_cannot_be_confused_for_one_another() {
        // Without length prefixes, "ab" followed by "c" and "a" followed by "bc"
        // feed the hasher identical bytes — two different trees with one digest.
        let one = outcome(vec![entry("/ab", 1), entry("/c", 1)]);
        let two = outcome(vec![entry("/a", 1), entry("/bc", 1)]);
        assert_ne!(content_digest(&one, &[]), content_digest(&two, &[]));
    }

    #[test]
    fn an_absent_value_differs_from_a_zero_one() {
        // "the platform could not tell us" and "it occupies nothing" are
        // different facts, and DR-16 turns on the difference.
        let mut unknown = entry("/a.txt", 10);
        unknown.allocated_size = None;
        let mut empty = entry("/a.txt", 10);
        empty.allocated_size = Some(0);
        assert_ne!(
            content_digest(&outcome(vec![unknown]), &[]),
            content_digest(&outcome(vec![empty]), &[])
        );
    }

    #[test]
    fn the_providers_found_are_part_of_the_digest() {
        let detection = Detection {
            roots: vec![CloudRoot {
                path: PathBuf::from("/cloud"),
                provider: Provider::ICloud,
                account: None,
                origin: RootOrigin::ProviderMount,
            }],
            links: Vec::new(),
        };
        assert_ne!(
            content_digest(&body(detection, vec![]), &[]),
            content_digest(&outcome(vec![]), &[])
        );
    }
}
