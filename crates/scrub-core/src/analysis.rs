//! Deciding what is the same file as what.
//!
//! Everything here is pure. It takes an inventory and answers two questions —
//! which files would have to be read to settle identity, and given what was
//! read, which files are the same — without touching a filesystem. The reading
//! itself belongs to the platform layer, which is the only place that knows
//! whether opening something would cost a download.
//!
//! Three rules do most of the work.
//!
//! **Identity comes only from content** (DR-13). Names and dates are shown to
//! help a person choose which copy to keep; they never decide whether two files
//! are the same file.
//!
//! **Certainty tiers are never mixed** (DR-14, DR-15). A pair proven identical
//! and a pair that merely could not be checked are different findings, and only
//! the first is ever offered as something to act on.
//!
//! **Shared bytes are not duplicates** (DR-16). Two names for one set of bytes
//! already cost what they cost; removing one frees nothing, and a tool that says
//! otherwise is making a promise the filesystem will not keep.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::artifact::Digest;
use crate::inventory::{Entry, EntryKind, FileId, UnreadReason};

/// How sure we are that a group's members hold the same content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    /// Every member's content was read and digested, and the digests match.
    ///
    /// The only tier anything is ever offered for.
    Exact,
    /// Members share a size but at least one could not be read.
    ///
    /// Never acted on automatically and never counted as recoverable space.
    /// Carries what would settle it.
    Candidate,
}

/// What reading established about one entry.
///
/// The distinction that keeps the two passes honest. A file the quick pass
/// separated from everything its size was shared with **was** read; treating it
/// as unread in the second pass would file a settled fact under "could not
/// check", and bury the real candidates among thousands of false ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Settled {
    /// Its whole content was read, and digests to this.
    ///
    /// Identity, and the only thing that ever is (DR-13).
    Content(Digest),
    /// The sample separated it from everything of its size on this machine.
    ///
    /// Carries the sample digest — the two ends and the length — which is not
    /// identity and is never used as such. It is kept because comparing two
    /// machines starts by matching samples, and a file with no recorded
    /// fingerprint at all could not be compared to anything without being read
    /// again from scratch.
    DistinctBySample(Digest),
}

impl Settled {
    /// The content digest, where one was established.
    #[must_use]
    pub fn content(self) -> Option<Digest> {
        match self {
            Self::Content(digest) => Some(digest),
            Self::DistinctBySample(_) => None,
        }
    }

    /// The fingerprint recorded, whichever kind it is.
    #[must_use]
    pub fn fingerprint(self) -> Digest {
        match self {
            Self::Content(digest) | Self::DistinctBySample(digest) => digest,
        }
    }
}

/// Why an entry's content could not be digested.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unsettled {
    /// Its content lives with a provider; reading it would download it.
    WouldRequireDownload {
        /// How many bytes reading it would pull down.
        bytes: u64,
    },
    /// The system refused to read it.
    Refused(UnreadReason),
}

/// One set of bytes on disk, and every name that refers to it.
///
/// Hard links and copy-on-write clones produce several names for one object.
/// Collapsing them here is what keeps the recoverable figure honest: an object
/// occupies its space once however many names it has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageObject {
    /// Indices into the inventory's entries, in the order they were recorded.
    pub names: Vec<usize>,
    /// The size every name reports.
    pub logical_size: u64,
    /// What it occupies here, where the platform could say.
    pub allocated_size: Option<u64>,
}

impl StorageObject {
    /// How many names refer to these bytes.
    #[must_use]
    pub fn name_count(&self) -> usize {
        self.names.len()
    }
}

/// A set of files found to hold, or possibly hold, the same content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// How sure we are.
    pub certainty: Certainty,
    /// The distinct sets of bytes in this group.
    pub objects: Vec<StorageObject>,
    /// The shared content digest, where every member was read.
    pub digest: Option<Digest>,
    /// The size every member reports.
    pub logical_size: u64,
    /// Why members could not be settled, for a candidate group.
    pub unsettled: Vec<Unsettled>,
    /// How many objects of this size were settled, for a candidate group.
    ///
    /// Context rather than an accusation: "three other files this size were
    /// checked" tells a person how likely the unchecked one is to matter.
    pub settled_of_same_size: usize,
}

impl Group {
    /// Bytes that removing every copy but one would actually return.
    ///
    /// Zero for a candidate group, always: space that might be recoverable is
    /// not space anyone should plan around (DR-15). Zero, too, where the
    /// platform could not report what is allocated — better to under-promise
    /// than to invent a figure from a logical size that a placeholder inflates.
    #[must_use]
    pub fn reclaimable_bytes(&self) -> u64 {
        if self.certainty != Certainty::Exact || self.objects.len() < 2 {
            return 0;
        }
        self.objects
            .iter()
            .skip(1)
            .filter_map(|object| object.allocated_size)
            .sum()
    }

    /// How many bytes reading the unsettled members would download.
    #[must_use]
    pub fn bytes_to_settle(&self) -> u64 {
        self.unsettled
            .iter()
            .map(|reason| match reason {
                Unsettled::WouldRequireDownload { bytes } => *bytes,
                Unsettled::Refused(_) => 0,
            })
            .sum()
    }
}

/// Which entries would have to be read to settle identity.
///
/// Only files whose size is shared with a different set of bytes: a size nothing
/// else shares cannot have a duplicate, and reading it would be work done to
/// learn nothing. On a real tree this is the difference between digesting
/// everything and digesting a small fraction of it.
///
/// Entries whose content is not on this machine are left out. Deciding to
/// download them is the user's, and this returns what can be read for free.
#[must_use]
pub fn readable_candidates(entries: &[Entry]) -> Vec<usize> {
    let mut wanted = Vec::new();
    for (_, objects) in group_by_size(entries) {
        if objects.len() < 2 {
            continue;
        }
        for object in objects {
            let first = object.names[0];
            if !entries[first].cloud.residency.read_may_download() {
                wanted.push(first);
            }
        }
    }
    wanted.sort_unstable();
    wanted
}

/// Every file whose content can be read here, whatever its size.
///
/// The mode for comparing machines. [`readable_candidates`] skips files whose
/// size nothing else on *this* machine shares, which is right for finding local
/// duplicates and wrong for comparison: a file unique here may well sit on the
/// other machine, and without a fingerprint it can never be recognised there.
///
/// The cost is real — every file is read rather than a fraction — which is why
/// it is a separate choice rather than the default.
#[must_use]
pub fn all_readable(entries: &[Entry]) -> Vec<usize> {
    let mut wanted = Vec::new();
    for (_, objects) in group_by_size(entries) {
        for object in objects {
            let first = object.names[0];
            if !entries[first].cloud.residency.read_may_download() {
                wanted.push(first);
            }
        }
    }
    wanted.sort_unstable();
    wanted
}

/// Forms duplicate groups from an inventory and whatever content was digested.
///
/// `digests` maps an entry index to the digest of its content. An index that is
/// absent was not read, and the objects it belongs to become candidates rather
/// than disappearing.
#[must_use]
pub fn group_duplicates<S: std::hash::BuildHasher>(
    entries: &[Entry],
    settled: &HashMap<usize, Settled, S>,
) -> Vec<Group> {
    let mut groups = Vec::new();

    for (logical_size, objects) in group_by_size(entries) {
        if objects.len() < 2 {
            continue;
        }

        let (known, unknown): (Vec<_>, Vec<_>) = objects
            .into_iter()
            .partition(|object| settled.contains_key(&object.names[0]));

        // Objects whose content was read group by what they actually contain.
        // Ones the sample separated are settled but match nothing, so they are
        // counted as checked and grouped with no one.
        let mut by_digest: BTreeMap<Digest, Vec<StorageObject>> = BTreeMap::new();
        let mut settled_count = 0;
        for object in known {
            settled_count += 1;
            if let Some(digest) = settled[&object.names[0]].content() {
                by_digest.entry(digest).or_default().push(object);
            }
        }

        for (digest, members) in by_digest {
            if members.len() < 2 {
                continue;
            }
            groups.push(Group {
                certainty: Certainty::Exact,
                objects: members,
                digest: Some(digest),
                logical_size,
                unsettled: Vec::new(),
                settled_of_same_size: 0,
            });
        }

        // Anything that could not be read is reported on its own, never folded
        // into a group that would then look actionable.
        if !unknown.is_empty() {
            let reasons = unknown
                .iter()
                .map(|object| unsettled_reason(&entries[object.names[0]]))
                .collect();
            groups.push(Group {
                certainty: Certainty::Candidate,
                objects: unknown,
                digest: None,
                logical_size,
                unsettled: reasons,
                settled_of_same_size: settled_count,
            });
        }
    }

    groups
}

/// Which entries still have to be read in full to settle identity.
///
/// Given groups formed from quick digests — a digest of each file's two ends and
/// its length — this returns the members whose ends agreed. Those are the only
/// files worth reading whole. Everything else has already been separated by a few
/// kilobytes rather than by its entire length.
///
/// A quick digest is never identity on its own (DR-13): two files can agree at
/// both ends and differ in the middle, which is exactly what the second pass is
/// for.
#[must_use]
pub fn needing_full_read(groups: &[Group]) -> Vec<usize> {
    let mut wanted: Vec<usize> = groups
        .iter()
        .filter(|group| group.certainty == Certainty::Exact)
        .flat_map(|group| group.objects.iter())
        .filter_map(|object| object.names.first().copied())
        .collect();
    wanted.sort_unstable();
    wanted.dedup();
    wanted
}

/// Why one entry's content could not be digested.
fn unsettled_reason(entry: &Entry) -> Unsettled {
    if entry.cloud.residency.read_may_download() {
        Unsettled::WouldRequireDownload {
            bytes: entry.logical_size,
        }
    } else {
        Unsettled::Refused(UnreadReason::Other(
            "content was not digested during this analysis".to_owned(),
        ))
    }
}

/// Files bucketed by size, with names of the same bytes collapsed together.
fn group_by_size(entries: &[Entry]) -> BTreeMap<u64, Vec<StorageObject>> {
    let mut buckets: BTreeMap<u64, Vec<StorageObject>> = BTreeMap::new();
    let mut by_identity: HashMap<FileId, (u64, usize)> = HashMap::new();

    for (index, entry) in entries.iter().enumerate() {
        // Directories and links have sizes, and none of them mean what a file's
        // size means. An empty file cannot be a duplicate of anything worth
        // reporting either — every empty file matches every other one, which
        // buries the findings that matter under thousands that do not.
        if entry.kind != EntryKind::File || entry.logical_size == 0 {
            continue;
        }

        if let Some(identity) = entry.file_id
            && let Some(&(size, position)) = by_identity.get(&identity)
        {
            // Another name for bytes already recorded. It joins that object
            // rather than becoming a second one (DR-16).
            if let Some(object) = buckets
                .get_mut(&size)
                .and_then(|objects| objects.get_mut(position))
            {
                object.names.push(index);
            }
            continue;
        }

        let objects = buckets.entry(entry.logical_size).or_default();
        objects.push(StorageObject {
            names: vec![index],
            logical_size: entry.logical_size,
            allocated_size: entry.allocated_size,
        });
        if let Some(identity) = entry.file_id {
            by_identity.insert(identity, (entry.logical_size, objects.len() - 1));
        }
    }

    buckets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::{CloudState, Provider, Residency, Retention};
    use std::path::PathBuf;

    fn file(path: &str, size: u64) -> Entry {
        Entry {
            path: PathBuf::from(path),
            kind: EntryKind::File,
            logical_size: size,
            allocated_size: Some(size.div_ceil(4_096) * 4_096),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState::not_synced(),
        }
    }

    fn linked(path: &str, size: u64, identity: u64) -> Entry {
        let mut entry = file(path, size);
        entry.file_id = Some(FileId {
            volume: 1,
            index: identity,
        });
        entry.link_count = 2;
        entry
    }

    fn in_the_cloud(path: &str, size: u64) -> Entry {
        let mut entry = file(path, size);
        entry.allocated_size = Some(0);
        entry.cloud = CloudState {
            provider: Some(Provider::ICloud),
            residency: Residency::Remote,
            retention: Retention::Unspecified,
        };
        entry
    }

    fn digest_of(text: &str) -> Settled {
        Settled::Content(Digest::of(text.as_bytes()))
    }

    #[test]
    fn a_size_nothing_shares_is_never_read() {
        // The optimisation the whole stage rests on. Digesting every file would
        // read a terabyte to learn what sizes already ruled out.
        let entries = vec![file("/a.txt", 10), file("/b.txt", 20), file("/c.txt", 30)];
        assert!(readable_candidates(&entries).is_empty());
    }

    #[test]
    fn files_sharing_a_size_are_read() {
        let entries = vec![file("/a.txt", 10), file("/b.txt", 10), file("/c.txt", 30)];
        assert_eq!(readable_candidates(&entries), vec![0, 1]);
    }

    #[test]
    fn a_file_in_the_cloud_is_not_read() {
        // DR-11. Reading it would download it, and that is the user's decision
        // to make, not a side effect of asking what is duplicated.
        let entries = vec![file("/a.txt", 10), in_the_cloud("/cloud/b.txt", 10)];
        assert_eq!(readable_candidates(&entries), vec![0]);
    }

    #[test]
    fn identical_content_forms_an_exact_group() {
        let entries = vec![file("/a.txt", 10), file("/b.txt", 10)];
        let digests = HashMap::from([(0, digest_of("same")), (1, digest_of("same"))]);

        let groups = group_duplicates(&entries, &digests);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].certainty, Certainty::Exact);
        assert_eq!(groups[0].objects.len(), 2);
        assert_eq!(groups[0].reclaimable_bytes(), 4_096);
    }

    #[test]
    fn the_same_size_with_different_content_is_not_a_group() {
        // Size collisions are ordinary. A tool that reported them as duplicates
        // would be wrong most of the time, on exactly the files people care
        // about least noticing an error in.
        let entries = vec![file("/a.txt", 10), file("/b.txt", 10)];
        let digests = HashMap::from([(0, digest_of("one")), (1, digest_of("other"))]);
        assert!(group_duplicates(&entries, &digests).is_empty());
    }

    #[test]
    fn dates_and_names_never_make_two_files_the_same() {
        // DR-13. These two share a name and a size and differ in content; a
        // tool matching on names would offer to delete one.
        let mut first = file("/backup/report.pdf", 10);
        let mut second = file("/archive/report.pdf", 10);
        first.modified = Some(crate::inventory::timestamp_of(std::time::UNIX_EPOCH));
        second.modified = first.modified;

        let digests = HashMap::from([(0, digest_of("v1")), (1, digest_of("v2"))]);
        assert!(group_duplicates(&[first, second], &digests).is_empty());
    }

    #[test]
    fn two_names_for_one_set_of_bytes_are_not_a_duplicate() {
        // DR-16, and the failure it prevents: offering to reclaim space that
        // deleting cannot return, because the bytes were never stored twice.
        let entries = vec![
            linked("/a/report.pdf", 10, 42),
            linked("/b/report.pdf", 10, 42),
        ];
        let digests = HashMap::from([(0, digest_of("same"))]);

        let groups = group_duplicates(&entries, &digests);
        assert!(
            groups.is_empty(),
            "one object with two names is not two objects: {groups:?}"
        );
    }

    #[test]
    fn a_hard_linked_pair_still_duplicates_a_separate_copy() {
        // Three names, two objects. Removing the separate copy frees its space;
        // removing either linked name frees nothing.
        let entries = vec![
            linked("/a/report.pdf", 10, 42),
            linked("/b/report.pdf", 10, 42),
            file("/c/report.pdf", 10),
        ];
        let digests = HashMap::from([(0, digest_of("same")), (2, digest_of("same"))]);

        let groups = group_duplicates(&entries, &digests);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].objects.len(), 2, "two objects, not three names");
        assert_eq!(groups[0].objects[0].name_count(), 2);
        assert_eq!(groups[0].reclaimable_bytes(), 4_096, "one object's worth");
    }

    #[test]
    fn a_file_that_could_not_be_read_becomes_a_candidate() {
        // DR-15. It is not dropped, and it is not claimed either.
        let entries = vec![file("/a.txt", 5_000), in_the_cloud("/cloud/b.txt", 5_000)];
        let digests = HashMap::from([(0, digest_of("content"))]);

        let groups = group_duplicates(&entries, &digests);
        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.certainty, Certainty::Candidate);
        assert_eq!(group.settled_of_same_size, 1);
        assert_eq!(group.bytes_to_settle(), 5_000);
        assert_eq!(
            group.reclaimable_bytes(),
            0,
            "a candidate never promises space"
        );
    }

    #[test]
    fn proven_and_merely_possible_are_reported_separately() {
        // DR-14. Two real copies plus one that could not be checked: the pair is
        // actionable, the third is a question, and merging them would make the
        // question look like an answer.
        let entries = vec![
            file("/a.txt", 5_000),
            file("/b.txt", 5_000),
            in_the_cloud("/cloud/c.txt", 5_000),
        ];
        let digests = HashMap::from([(0, digest_of("same")), (1, digest_of("same"))]);

        let groups = group_duplicates(&entries, &digests);
        assert_eq!(groups.len(), 2);
        let exact = groups
            .iter()
            .find(|group| group.certainty == Certainty::Exact)
            .expect("the proven pair");
        let candidate = groups
            .iter()
            .find(|group| group.certainty == Certainty::Candidate)
            .expect("the unchecked one");

        assert_eq!(exact.objects.len(), 2);
        assert_eq!(candidate.objects.len(), 1);
        assert_eq!(candidate.settled_of_same_size, 2);
    }

    #[test]
    fn empty_files_are_left_out_of_duplicate_reporting() {
        // Every empty file matches every other one. Reporting them would bury
        // the findings that matter under thousands that do not.
        let entries = vec![file("/a.txt", 0), file("/b.txt", 0), file("/c.txt", 0)];
        assert!(readable_candidates(&entries).is_empty());
        assert!(group_duplicates(&entries, &HashMap::new()).is_empty());
    }

    #[test]
    fn directories_and_links_are_not_duplicate_candidates() {
        let mut directory = file("/a", 10);
        directory.kind = EntryKind::Directory;
        let mut link = file("/b", 10);
        link.kind = EntryKind::Symlink;
        assert!(readable_candidates(&[directory, link]).is_empty());
    }

    #[test]
    fn only_files_the_quick_pass_could_not_separate_are_read_in_full() {
        // The saving that makes analysis affordable. Two large files sharing a
        // size but differing at either end never get read past their first and
        // last blocks.
        let entries = vec![
            file("/a.bin", 9_000),
            file("/b.bin", 9_000),
            file("/c.bin", 9_000),
        ];
        let quick = HashMap::from([
            (0, digest_of("ends-match")),
            (1, digest_of("ends-match")),
            (2, digest_of("ends-differ")),
        ]);

        let groups = group_duplicates(&entries, &quick);
        assert_eq!(needing_full_read(&groups), vec![0, 1]);
    }

    #[test]
    fn a_candidate_group_does_not_send_anything_off_to_be_read() {
        // Its members could not be read in the first place; listing them for a
        // second attempt would produce the download the first pass declined.
        let entries = vec![file("/a.txt", 5_000), in_the_cloud("/cloud/b.txt", 5_000)];
        let digests = HashMap::from([(0, digest_of("content"))]);
        let groups = group_duplicates(&entries, &digests);
        assert!(needing_full_read(&groups).is_empty());
    }

    #[test]
    fn comparing_machines_reads_files_a_local_search_would_skip() {
        // The gap this closes. Locally, a size nothing else shares cannot be a
        // duplicate and is never read — but the other machine may hold it, and a
        // file with no fingerprint cannot be recognised anywhere.
        let entries = vec![file("/a.txt", 10), file("/b.txt", 20), file("/c.txt", 30)];
        assert!(readable_candidates(&entries).is_empty());
        assert_eq!(all_readable(&entries), vec![0, 1, 2]);
    }

    #[test]
    fn comparing_machines_still_refuses_to_download() {
        // Reading everything means everything that is here, and nothing that is
        // not (DR-11).
        let entries = vec![file("/a.txt", 10), in_the_cloud("/cloud/b.txt", 20)];
        assert_eq!(all_readable(&entries), vec![0]);
    }

    #[test]
    fn a_file_the_sample_ruled_out_is_settled_not_a_candidate() {
        // The trap this guards, and it is a quiet one: after the second pass
        // only the files read in full carry a content digest. Treating the rest
        // as unread would file every file that merely shared a size under
        // "could not check", turning a handful of real questions into thousands
        // of false ones and making the tier meaningless.
        let entries = vec![file("/a.bin", 9_000), file("/b.bin", 9_000)];
        let settled = HashMap::from([
            (0, digest_of("same")),
            (1, Settled::DistinctBySample(Digest::of(b"a lonely sample"))),
        ]);

        let groups = group_duplicates(&entries, &settled);
        assert!(
            groups.is_empty(),
            "one matched nothing and the other was read: no group, no question: {groups:?}"
        );
    }

    #[test]
    fn a_platform_that_cannot_report_allocation_promises_nothing() {
        let mut one = file("/a.txt", 10);
        let mut two = file("/b.txt", 10);
        one.allocated_size = None;
        two.allocated_size = None;
        let digests = HashMap::from([(0, digest_of("same")), (1, digest_of("same"))]);

        let groups = group_duplicates(&[one, two], &digests);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].reclaimable_bytes(), 0);
    }
}
