//! What someone intends to do, recorded without doing any of it.
//!
//! A plan is a list of operations and nothing more. Building one touches no
//! file, creates no directory, and moves nothing; it can be built on a machine
//! that does not hold the files at all, kept for a week, read by somebody else,
//! and thrown away with no trace (DR-9).
//!
//! Two things are settled here rather than during execution, because settling
//! them later means settling them halfway through.
//!
//! **Nothing is ever deleted** (DR-5). The strongest thing a plan can say about
//! a file is that it should go to quarantine, which is a move like any other and
//! is reversed the same way.
//!
//! **Nothing is ever overwritten** (DR-6). Two operations wanting the same
//! destination, or one destination already occupied, is a conflict — reported
//! while the plan is still a document, not discovered at operation four hundred
//! with three hundred and ninety-nine already done.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::analysis::{Certainty, Group};
use crate::artifact::Digest;
use crate::inventory::Entry;

/// The file an operation acts on, recorded well enough to prove it later.
///
/// Carries content as well as path. When the plan is eventually applied, the
/// file at that path has to still be this file; a path alone would let a plan
/// act on whatever happened to take the name in the meantime (DR-8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Which entry of the analysis this is.
    pub entry: usize,
    /// Where it was when the plan was made.
    pub path: PathBuf,
    /// What it contained, where that was established.
    pub content: Option<Digest>,
    /// How large it was.
    pub logical_size: u64,
    /// When it last changed.
    pub modified: Option<Timestamp>,
}

impl Subject {
    /// Records an entry as the subject of an operation.
    #[must_use]
    pub fn of(entry: usize, source: &Entry, content: Option<Digest>) -> Self {
        Self {
            entry,
            path: source.path.clone(),
            content,
            logical_size: source.logical_size,
            modified: source.modified,
        }
    }
}

/// Why a file is being set aside.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Because {
    /// Its content is held elsewhere too, and that copy is being kept.
    RedundantCopy {
        /// The copy that stays.
        kept: PathBuf,
        /// The content both hold.
        content: Digest,
    },
    /// Somebody asked for it directly.
    Requested,
}

/// One thing a plan says should happen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Make a directory that does not exist yet.
    CreateDirectory {
        /// Where.
        path: PathBuf,
    },
    /// Put a file somewhere else.
    Move {
        /// What to move.
        subject: Subject,
        /// Where to.
        destination: PathBuf,
    },
    /// Set a file aside, recoverably.
    ///
    /// The closest this tool comes to deleting, and it is not close: quarantine
    /// is a directory like any other, and its contents leave it only when
    /// somebody empties it deliberately (DR-5).
    Quarantine {
        /// What to set aside.
        subject: Subject,
        /// Why.
        because: Because,
    },
}

impl Operation {
    /// The file this acts on, where there is one.
    #[must_use]
    pub fn subject(&self) -> Option<&Subject> {
        match self {
            Self::CreateDirectory { .. } => None,
            Self::Move { subject, .. } | Self::Quarantine { subject, .. } => Some(subject),
        }
    }

    /// The path this operation would occupy, where it takes one.
    ///
    /// Quarantine has no fixed destination here: where in quarantine a file
    /// lands is settled at execution, against a directory whose contents this
    /// plan cannot see.
    #[must_use]
    pub fn destination(&self) -> Option<&Path> {
        match self {
            Self::Move { destination, .. } => Some(destination),
            Self::CreateDirectory { path } => Some(path),
            Self::Quarantine { .. } => None,
        }
    }

    /// Bytes this would free, if it frees any.
    #[must_use]
    pub fn frees(&self, entries: &[Entry]) -> u64 {
        match self {
            Self::Quarantine { subject, .. } => entries
                .get(subject.entry)
                .and_then(|entry| entry.allocated_size)
                .unwrap_or(0),
            Self::CreateDirectory { .. } | Self::Move { .. } => 0,
        }
    }
}

/// Which copy of a duplicated file to keep.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Keep {
    /// The one whose recorded modification time is earliest.
    ///
    /// Usually the original, and usually what people mean when they say they
    /// want the original.
    Oldest,
    /// The one whose recorded modification time is latest.
    Newest,
    /// The one with the fewest directories above it.
    ///
    /// A file at `Documents/tax.pdf` is more likely to be where it belongs than
    /// the same file at `Desktop/old/backup 2/copy of Documents/tax.pdf`.
    Shallowest,
    /// Whichever lies under this path, falling back to the shallowest.
    Under(PathBuf),
}

impl Keep {
    /// Picks the copy to keep out of a group's members.
    ///
    /// Returns an index into `candidates`. Ties are broken by path so that the
    /// same group always yields the same plan (DR-12): two runs that disagreed
    /// about which copy to keep would make the plan artifact undiffable and the
    /// decision unreviewable.
    fn choose(&self, candidates: &[&Entry]) -> usize {
        let ranked = |entry: &Entry| -> (u8, i64, usize) {
            let preference = match self {
                Self::Under(root) => u8::from(!entry.path.starts_with(root)),
                Self::Oldest | Self::Newest | Self::Shallowest => 0,
            };
            let ordering = match self {
                Self::Oldest => entry.modified.map_or(i64::MAX, Timestamp::as_second),
                Self::Newest => entry.modified.map_or(i64::MIN, |when| -when.as_second()),
                Self::Shallowest | Self::Under(_) => {
                    i64::try_from(entry.path.components().count()).unwrap_or(i64::MAX)
                }
            };
            (preference, ordering, 0)
        };

        let mut best = 0;
        for (index, entry) in candidates.iter().enumerate().skip(1) {
            let (left, right) = (ranked(entry), ranked(candidates[best]));
            let better = (left.0, left.1, &entry.path) < (right.0, right.1, &candidates[best].path);
            if better {
                best = index;
            }
        }
        best
    }
}

/// Turns proven duplicate groups into operations that set the extra copies aside.
///
/// Only proven groups. A group that could not be checked is left entirely alone,
/// however likely it looks: acting on a maybe is how a tool loses the only copy
/// of something (DR-14, DR-15).
///
/// An object with several names contributes one operation per name, because
/// setting aside one name of a hard-linked pair frees nothing — the bytes stay
/// behind the other name. The plan says so rather than quietly freeing less than
/// it promised (DR-16).
#[must_use]
pub fn resolve_duplicates(entries: &[Entry], groups: &[Group], keep: &Keep) -> Vec<Operation> {
    let mut operations = Vec::new();

    for group in groups {
        if group.certainty != Certainty::Exact || group.objects.len() < 2 {
            continue;
        }

        let representatives: Vec<&Entry> = group
            .objects
            .iter()
            .filter_map(|object| object.names.first().and_then(|name| entries.get(*name)))
            .collect();
        if representatives.len() != group.objects.len() {
            // An index that does not resolve means the plan and the analysis
            // disagree about what exists. Skipping the group is the only honest
            // response; guessing which object was meant is not.
            continue;
        }

        let keeper = keep.choose(&representatives);
        let kept = representatives[keeper].path.clone();

        for (position, object) in group.objects.iter().enumerate() {
            if position == keeper {
                continue;
            }
            for name in &object.names {
                let Some(entry) = entries.get(*name) else {
                    continue;
                };
                operations.push(Operation::Quarantine {
                    subject: Subject::of(*name, entry, group.digest),
                    because: Because::RedundantCopy {
                        kept: kept.clone(),
                        content: group.digest.unwrap_or_else(|| Digest::of(b"")),
                    },
                });
            }
        }
    }

    operations
}

/// Puts a rule's operations together with the ones somebody asked for.
///
/// What was asked for wins. A file somebody moved by hand is not also a
/// redundant copy to be set aside: two operations on one file would have the
/// second look for it at a path it had already left, and of the two, the one a
/// person chose is the one they meant.
///
/// No file ends up with two operations either way. That is not tidiness — the
/// executor checks each subject is still where the plan says before touching
/// it, so a second operation on the same file is a step that skips itself and a
/// line in the report that means nothing.
#[must_use]
pub fn combine(by_rule: Vec<Operation>, requested: Vec<Operation>) -> Vec<Operation> {
    let asked_about: HashSet<usize> = requested
        .iter()
        .filter_map(|operation| operation.subject().map(|subject| subject.entry))
        .collect();

    let mut combined = requested;
    let mut folders: HashSet<PathBuf> = combined
        .iter()
        .filter_map(|operation| match operation {
            Operation::CreateDirectory { path } => Some(path.clone()),
            Operation::Move { .. } | Operation::Quarantine { .. } => None,
        })
        .collect();

    for operation in by_rule {
        match &operation {
            Operation::CreateDirectory { path } => {
                if !folders.insert(path.clone()) {
                    continue;
                }
            }
            Operation::Move { subject, .. } | Operation::Quarantine { subject, .. } => {
                if asked_about.contains(&subject.entry) {
                    continue;
                }
            }
        }
        combined.push(operation);
    }

    combined
}

/// Two things wanting the same place, or one place already taken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// The place in question.
    pub destination: PathBuf,
    /// Operations that want it, by index into the plan.
    pub claimants: Vec<usize>,
    /// An entry already there, if the scan saw one.
    pub occupied_by: Option<usize>,
}

/// Finds every place two operations would collide, or that is already taken.
///
/// The whole point of doing this now: a conflict found while the plan is a
/// document costs a question, and the same conflict found during execution costs
/// a half-finished reorganization (DR-6, DR-8).
///
/// A destination that an operation is itself vacating does not count as
/// occupied — moving `a` to `b` and `b` to `c` is an ordinary rotation, not a
/// collision.
#[must_use]
pub fn conflicts(entries: &[Entry], operations: &[Operation]) -> Vec<Conflict> {
    let vacating: HashSet<&Path> = operations
        .iter()
        .filter_map(|operation| operation.subject())
        .map(|subject| subject.path.as_path())
        .collect();

    let occupants: BTreeMap<&Path, usize> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.as_path(), index))
        .collect();

    let mut wanted: BTreeMap<&Path, Vec<usize>> = BTreeMap::new();
    for (index, operation) in operations.iter().enumerate() {
        if let Some(destination) = operation.destination() {
            wanted.entry(destination).or_default().push(index);
        }
    }

    let mut found = Vec::new();
    for (destination, claimants) in wanted {
        let occupied = occupants
            .get(destination)
            .copied()
            .filter(|_| !vacating.contains(destination));

        if claimants.len() > 1 || occupied.is_some() {
            found.push(Conflict {
                destination: destination.to_path_buf(),
                claimants,
                occupied_by: occupied,
            });
        }
    }
    found
}

/// Puts operations in an order that can actually be carried out.
///
/// Directories are created before anything moves into them, and moves run before
/// anything is set aside, so a file is never looked for somewhere it has already
/// left. Within each kind the order is by path, so the same intent always
/// produces the same plan (DR-12).
#[must_use]
pub fn ordered(mut operations: Vec<Operation>) -> Vec<Operation> {
    operations.sort_by_key(|operation| {
        let stage = match operation {
            Operation::CreateDirectory { .. } => 0,
            Operation::Move { .. } => 1,
            Operation::Quarantine { .. } => 2,
        };
        let path = match operation {
            Operation::CreateDirectory { path } => path.clone(),
            Operation::Move { destination, .. } => destination.clone(),
            Operation::Quarantine { subject, .. } => subject.path.clone(),
        };
        (stage, path)
    });
    operations
}

/// What a plan would achieve, in the terms a person decides on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effect {
    /// How many files would be set aside.
    pub quarantined: usize,
    /// How many files would move.
    pub moved: usize,
    /// How many directories would be created.
    pub directories: usize,
    /// Bytes that setting those files aside would actually free.
    pub frees: u64,
}

/// Sums up what a plan would do.
#[must_use]
pub fn effect(entries: &[Entry], operations: &[Operation]) -> Effect {
    let mut effect = Effect::default();
    for operation in operations {
        match operation {
            Operation::CreateDirectory { .. } => effect.directories += 1,
            Operation::Move { .. } => effect.moved += 1,
            Operation::Quarantine { .. } => effect.quarantined += 1,
        }
        effect.frees += operation.frees(entries);
    }
    effect
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::StorageObject;
    use crate::cloud::CloudState;
    use crate::inventory::{EntryKind, timestamp_of};
    use std::time::{Duration, UNIX_EPOCH};

    fn file(path: &str, seconds: u64) -> Entry {
        Entry {
            path: PathBuf::from(path),
            kind: EntryKind::File,
            logical_size: 5_000,
            allocated_size: Some(8_192),
            created: None,
            modified: Some(timestamp_of(UNIX_EPOCH + Duration::from_secs(seconds))),
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState::not_synced(),
        }
    }

    fn group(names: Vec<Vec<usize>>, certainty: Certainty) -> Group {
        Group {
            certainty,
            objects: names
                .into_iter()
                .map(|names| StorageObject {
                    names,
                    logical_size: 5_000,
                    allocated_size: Some(8_192),
                })
                .collect(),
            digest: Some(Digest::of(b"shared")),
            logical_size: 5_000,
            unsettled: Vec::new(),
            settled_of_same_size: 0,
        }
    }

    fn quarantined_paths(operations: &[Operation]) -> Vec<PathBuf> {
        operations
            .iter()
            .filter_map(|operation| match operation {
                Operation::Quarantine { subject, .. } => Some(subject.path.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn keeping_the_oldest_sets_the_others_aside() {
        let entries = vec![file("/new.pdf", 2_000), file("/old.pdf", 1_000)];
        let operations = resolve_duplicates(
            &entries,
            &[group(vec![vec![0], vec![1]], Certainty::Exact)],
            &Keep::Oldest,
        );

        assert_eq!(
            quarantined_paths(&operations),
            vec![PathBuf::from("/new.pdf")]
        );
    }

    #[test]
    fn keeping_the_newest_is_the_other_way_round() {
        let entries = vec![file("/new.pdf", 2_000), file("/old.pdf", 1_000)];
        let operations = resolve_duplicates(
            &entries,
            &[group(vec![vec![0], vec![1]], Certainty::Exact)],
            &Keep::Newest,
        );

        assert_eq!(
            quarantined_paths(&operations),
            vec![PathBuf::from("/old.pdf")]
        );
    }

    #[test]
    fn keeping_the_shallowest_prefers_where_a_file_belongs() {
        let entries = vec![
            file("/Desktop/old/backup 2/copy of tax.pdf", 1_000),
            file("/Documents/tax.pdf", 2_000),
        ];
        let operations = resolve_duplicates(
            &entries,
            &[group(vec![vec![0], vec![1]], Certainty::Exact)],
            &Keep::Shallowest,
        );

        assert_eq!(
            quarantined_paths(&operations),
            vec![PathBuf::from("/Desktop/old/backup 2/copy of tax.pdf")]
        );
    }

    #[test]
    fn keeping_what_is_under_a_path_beats_everything_else() {
        let entries = vec![
            file("/a.pdf", 1_000),
            file("/iCloud/deep/down/a.pdf", 2_000),
        ];
        let operations = resolve_duplicates(
            &entries,
            &[group(vec![vec![0], vec![1]], Certainty::Exact)],
            &Keep::Under(PathBuf::from("/iCloud")),
        );

        assert_eq!(
            quarantined_paths(&operations),
            vec![PathBuf::from("/a.pdf")],
            "the copy in the chosen place stays even though it is deeper"
        );
    }

    #[test]
    fn a_group_that_could_not_be_checked_yields_nothing() {
        // DR-15, at the moment it matters most. A plan is the last place a maybe
        // should turn into an action.
        let entries = vec![file("/a.pdf", 1_000), file("/b.pdf", 2_000)];
        let operations = resolve_duplicates(
            &entries,
            &[group(vec![vec![0], vec![1]], Certainty::Candidate)],
            &Keep::Oldest,
        );
        assert!(operations.is_empty());
    }

    #[test]
    fn every_name_of_a_redundant_object_is_set_aside() {
        // Setting aside one name of a hard-linked pair frees nothing: the bytes
        // stay behind the other name. Emitting one operation would promise space
        // the filesystem would not return (DR-16).
        let entries = vec![
            file("/keep.pdf", 1_000),
            file("/copy-a.pdf", 2_000),
            file("/copy-b.pdf", 2_000),
        ];
        let operations = resolve_duplicates(
            &entries,
            &[group(vec![vec![0], vec![1, 2]], Certainty::Exact)],
            &Keep::Oldest,
        );

        assert_eq!(
            quarantined_paths(&operations),
            vec![PathBuf::from("/copy-a.pdf"), PathBuf::from("/copy-b.pdf")]
        );
    }

    #[test]
    fn the_same_group_always_produces_the_same_plan() {
        // DR-12. A plan that reshuffled between runs could not be diffed, and a
        // decision nobody can re-read is a decision nobody can review.
        let entries = vec![file("/a.pdf", 1_000), file("/b.pdf", 1_000)];
        let groups = [group(vec![vec![0], vec![1]], Certainty::Exact)];

        let first = resolve_duplicates(&entries, &groups, &Keep::Oldest);
        let second = resolve_duplicates(&entries, &groups, &Keep::Oldest);
        assert_eq!(
            first, second,
            "identical timestamps must still break the same way"
        );
    }

    #[test]
    fn two_operations_wanting_one_place_is_a_conflict() {
        // Found while the plan is still a document, which is the entire reason
        // the stage exists (DR-6).
        let entries = vec![file("/a.pdf", 1_000), file("/b.pdf", 2_000)];
        let operations = vec![
            Operation::Move {
                subject: Subject::of(0, &entries[0], None),
                destination: PathBuf::from("/archive/tax.pdf"),
            },
            Operation::Move {
                subject: Subject::of(1, &entries[1], None),
                destination: PathBuf::from("/archive/tax.pdf"),
            },
        ];

        let found = conflicts(&entries, &operations);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].claimants, vec![0, 1]);
        assert!(found[0].occupied_by.is_none());
    }

    #[test]
    fn moving_onto_an_existing_file_is_a_conflict() {
        // The failure the user described from doing this by hand: a copy landing
        // on a file that was already there, with nothing asked and nothing said.
        let entries = vec![file("/new/tax.pdf", 2_000), file("/archive/tax.pdf", 1_000)];
        let operations = vec![Operation::Move {
            subject: Subject::of(0, &entries[0], None),
            destination: PathBuf::from("/archive/tax.pdf"),
        }];

        let found = conflicts(&entries, &operations);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].occupied_by, Some(1));
    }

    #[test]
    fn a_place_being_vacated_is_not_occupied() {
        // Rotating two files past each other is ordinary. Calling it a collision
        // would make the tool refuse the most common rearrangement there is.
        let entries = vec![file("/a.pdf", 1_000), file("/b.pdf", 2_000)];
        let operations = vec![
            Operation::Move {
                subject: Subject::of(0, &entries[0], None),
                destination: PathBuf::from("/b.pdf"),
            },
            Operation::Move {
                subject: Subject::of(1, &entries[1], None),
                destination: PathBuf::from("/c.pdf"),
            },
        ];

        assert!(conflicts(&entries, &operations).is_empty());
    }

    #[test]
    fn directories_are_made_before_anything_moves_into_them() {
        let entries = [file("/a.pdf", 1_000)];
        let operations = ordered(vec![
            Operation::Quarantine {
                subject: Subject::of(0, &entries[0], None),
                because: Because::Requested,
            },
            Operation::Move {
                subject: Subject::of(0, &entries[0], None),
                destination: PathBuf::from("/archive/a.pdf"),
            },
            Operation::CreateDirectory {
                path: PathBuf::from("/archive"),
            },
        ]);

        assert!(matches!(operations[0], Operation::CreateDirectory { .. }));
        assert!(matches!(operations[1], Operation::Move { .. }));
        assert!(matches!(operations[2], Operation::Quarantine { .. }));
    }

    #[test]
    fn the_effect_counts_only_space_that_would_actually_be_freed() {
        let entries = vec![file("/a.pdf", 1_000), file("/b.pdf", 2_000)];
        let operations = vec![
            Operation::Quarantine {
                subject: Subject::of(0, &entries[0], None),
                because: Because::Requested,
            },
            Operation::Move {
                subject: Subject::of(1, &entries[1], None),
                destination: PathBuf::from("/elsewhere/b.pdf"),
            },
        ];

        let summary = effect(&entries, &operations);
        assert_eq!(summary.quarantined, 1);
        assert_eq!(summary.moved, 1);
        assert_eq!(summary.frees, 8_192, "moving a file frees nothing");
    }

    #[test]
    fn a_subject_records_what_it_acted_on_not_just_where() {
        // What lets execution prove it is touching the file the plan meant, and
        // stop if it is not (DR-8).
        let entries = [file("/a.pdf", 1_000)];
        let subject = Subject::of(0, &entries[0], Some(Digest::of(b"content")));

        assert_eq!(subject.path, PathBuf::from("/a.pdf"));
        assert_eq!(subject.content, Some(Digest::of(b"content")));
        assert_eq!(subject.logical_size, 5_000);
        assert!(subject.modified.is_some());
    }
}
