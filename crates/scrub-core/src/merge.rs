//! Putting two machines' analyses side by side.
//!
//! This is the stage that answers the question the whole tool was built for: is
//! this file in both places, or only one? A laptop and a desktop each scan
//! themselves, and their artifacts are brought together anywhere — including on
//! a third machine that holds neither set of files, since comparison needs
//! fingerprints and never needs the files themselves.
//!
//! Identity across machines is what it is everywhere else: content, and nothing
//! but content (DR-13). Paths cannot be compared — the same document lives at
//! different paths on two machines, and different documents share a path all the
//! time — and a merged artifact is never executed against anything, because half
//! of what it describes is somewhere else (DR-18).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::analysis::Settled;
use crate::artifact::MachineId;
use crate::cloud::{CloudRoot, ProviderLink};
use crate::inventory::{FileId, ScanOutcome, Unread};

/// One machine's analysis, ready to be combined with others.
#[derive(Clone, Debug)]
pub struct Input {
    /// What to call this machine when reporting.
    pub label: String,
    /// Which machine it was.
    pub machine: MachineId,
    /// The providers found there.
    pub roots: Vec<CloudRoot>,
    /// The links found there.
    pub links: Vec<ProviderLink>,
    /// What the scan found there.
    pub outcome: ScanOutcome,
    /// What reading established about each entry there.
    pub settled: BTreeMap<usize, Settled>,
}

/// Where one machine's entries sit in the combined list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// What to call it.
    pub label: String,
    /// Which machine it was.
    pub machine: MachineId,
    /// The index its first entry took in the combined list.
    pub first_entry: usize,
    /// How many entries it contributed.
    pub entry_count: usize,
}

impl Source {
    /// Whether a combined-list index came from this machine.
    #[must_use]
    pub fn contains(&self, entry: usize) -> bool {
        entry >= self.first_entry && entry < self.first_entry + self.entry_count
    }
}

/// Several machines' findings, combined into one.
#[derive(Clone, Debug, Default)]
pub struct Merged {
    /// Which machine contributed which stretch of the combined list.
    pub sources: Vec<Source>,
    /// The providers found across all of them.
    pub roots: Vec<CloudRoot>,
    /// The links found across all of them.
    pub links: Vec<ProviderLink>,
    /// Every entry from every machine, in source order.
    pub outcome: ScanOutcome,
    /// Every fingerprint from every machine, re-indexed.
    pub settled: BTreeMap<usize, Settled>,
}

impl Merged {
    /// Which machine an entry came from.
    #[must_use]
    pub fn source_of(&self, entry: usize) -> Option<&Source> {
        self.sources.iter().find(|source| source.contains(entry))
    }

    /// Which machines are represented in a set of entries.
    ///
    /// The question a duplicate group is really being asked: a group whose
    /// members all come from one machine is a local duplicate, and one spanning
    /// two is a file that exists in both places.
    #[must_use]
    pub fn sources_among(&self, entries: &[usize]) -> Vec<usize> {
        let mut found: Vec<usize> = entries
            .iter()
            .filter_map(|entry| {
                self.sources
                    .iter()
                    .position(|source| source.contains(*entry))
            })
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }
}

/// Combines several machines' analyses into one.
///
/// Entries are concatenated in the order given, and every index that refers to
/// them — fingerprints, and later the duplicate groups — is shifted to match.
#[must_use]
pub fn merge(inputs: Vec<Input>) -> Merged {
    let mut merged = Merged::default();

    for (position, input) in inputs.into_iter().enumerate() {
        let offset = merged.outcome.entries.len();

        merged.sources.push(Source {
            label: input.label,
            machine: input.machine,
            first_entry: offset,
            entry_count: input.outcome.entries.len(),
        });

        for mut entry in input.outcome.entries {
            entry.file_id = entry.file_id.map(|identity| scope(identity, position));
            merged.outcome.entries.push(entry);
        }

        merged
            .outcome
            .unread
            .extend(input.outcome.unread.into_iter().map(|place| Unread {
                path: place.path,
                reason: place.reason,
            }));
        merged.roots.extend(input.roots);
        merged.links.extend(input.links);

        for (index, state) in input.settled {
            merged.settled.insert(index + offset, state);
        }
    }

    merged
}

/// Makes a file identity unique to the machine it came from.
///
/// The trap this exists for is quiet and would be very hard to notice: a device
/// number and an inode are only unique *within one filesystem*, and two machines
/// routinely hand out the same pair to entirely unrelated files. Combined
/// without this, two strangers would be treated as one set of bytes with two
/// names — collapsing a genuine duplicate out of existence and understating the
/// space it occupies (DR-16).
///
/// Scoping preserves what the identity is for: names that shared bytes on one
/// machine still share them here, and nothing else does.
fn scope(identity: FileId, source: usize) -> FileId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(source as u64).to_le_bytes());
    hasher.update(&identity.volume.to_le_bytes());
    let mixed = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&mixed.as_bytes()[..8]);

    FileId {
        volume: u64::from_le_bytes(bytes),
        index: identity.index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{Certainty, group_duplicates};
    use crate::artifact::Digest;
    use crate::cloud::CloudState;
    use crate::inventory::{Entry, EntryKind};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn file(path: &str, size: u64) -> Entry {
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

    fn input(label: &str, entries: Vec<Entry>, settled: Vec<(usize, &str)>) -> Input {
        Input {
            label: label.to_owned(),
            machine: MachineId::generate(),
            roots: Vec::new(),
            links: Vec::new(),
            outcome: ScanOutcome {
                entries,
                unread: Vec::new(),
            },
            settled: settled
                .into_iter()
                .map(|(index, content)| (index, Settled::Content(Digest::of(content.as_bytes()))))
                .collect(),
        }
    }

    #[test]
    fn entries_are_concatenated_and_attributed() {
        let merged = merge(vec![
            input("mac", vec![file("/a", 10), file("/b", 20)], vec![]),
            input("windows", vec![file("C:/c", 30)], vec![]),
        ]);

        assert_eq!(merged.outcome.entries.len(), 3);
        assert_eq!(merged.source_of(0).expect("a source").label, "mac");
        assert_eq!(merged.source_of(1).expect("a source").label, "mac");
        assert_eq!(merged.source_of(2).expect("a source").label, "windows");
        assert!(merged.source_of(3).is_none());
    }

    #[test]
    fn fingerprints_follow_their_entries() {
        // If these drifted, every fingerprint after the first machine would be
        // attached to the wrong file, and the comparison would be nonsense that
        // looked plausible.
        let merged = merge(vec![
            input("mac", vec![file("/a", 10)], vec![(0, "one")]),
            input("windows", vec![file("C:/b", 10)], vec![(0, "two")]),
        ]);

        assert_eq!(
            merged.settled[&0].content(),
            Some(Digest::of(b"one")),
            "the first machine's fingerprint stays at index 0"
        );
        assert_eq!(
            merged.settled[&1].content(),
            Some(Digest::of(b"two")),
            "the second machine's is shifted to follow it"
        );
    }

    #[test]
    fn the_same_content_on_two_machines_forms_one_group() {
        // The finding the stage exists for.
        let merged = merge(vec![
            input(
                "mac",
                vec![file("/Documents/tax.pdf", 5_000)],
                vec![(0, "the same")],
            ),
            input(
                "windows",
                vec![file("C:/Users/me/tax.pdf", 5_000)],
                vec![(0, "the same")],
            ),
        ]);

        let settled: HashMap<usize, Settled> = merged.settled.clone().into_iter().collect();
        let groups = group_duplicates(&merged.outcome.entries, &settled);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].certainty, Certainty::Exact);

        let names: Vec<usize> = groups[0]
            .objects
            .iter()
            .flat_map(|object| object.names.clone())
            .collect();
        assert_eq!(
            merged.sources_among(&names),
            vec![0, 1],
            "the group spans both machines, which is what makes it interesting"
        );
    }

    #[test]
    fn different_content_at_the_same_path_is_not_a_match() {
        // Paths mean nothing across machines. Two people's `Documents/notes.txt`
        // are unrelated, and matching them would be the most obvious way to get
        // this stage catastrophically wrong (DR-13).
        let merged = merge(vec![
            input(
                "mac",
                vec![file("/Documents/notes.txt", 5_000)],
                vec![(0, "mine")],
            ),
            input(
                "windows",
                vec![file("/Documents/notes.txt", 5_000)],
                vec![(0, "theirs")],
            ),
        ]);

        let settled: HashMap<usize, Settled> = merged.settled.clone().into_iter().collect();
        assert!(group_duplicates(&merged.outcome.entries, &settled).is_empty());
    }

    #[test]
    fn two_machines_reusing_a_file_identity_are_kept_apart() {
        // The quiet trap. A device number and an inode are unique within one
        // filesystem and nowhere else, so two machines hand out the same pair to
        // unrelated files as a matter of course. Combined without scoping, these
        // two strangers would become one set of bytes with two names — and a
        // real duplicate would vanish from the findings.
        let mut mac = file("/a/report.pdf", 5_000);
        let mut windows = file("C:/b/report.pdf", 5_000);
        let shared = Some(FileId {
            volume: 16_777_230,
            index: 1_234_567,
        });
        mac.file_id = shared;
        windows.file_id = shared;

        let merged = merge(vec![
            input("mac", vec![mac], vec![(0, "the same")]),
            input("windows", vec![windows], vec![(0, "the same")]),
        ]);

        assert_ne!(
            merged.outcome.entries[0].file_id, merged.outcome.entries[1].file_id,
            "identities from different machines must not collide"
        );

        let settled: HashMap<usize, Settled> = merged.settled.clone().into_iter().collect();
        let groups = group_duplicates(&merged.outcome.entries, &settled);
        assert_eq!(
            groups.len(),
            1,
            "the duplicate survives rather than collapsing"
        );
        assert_eq!(
            groups[0].objects.len(),
            2,
            "two machines, two sets of bytes"
        );
    }

    #[test]
    fn names_that_shared_bytes_on_one_machine_still_share_them() {
        // Scoping must separate machines without destroying what the identity is
        // for: two hard links on one machine are still one object afterwards.
        let mut first = file("/a/report.pdf", 5_000);
        let mut second = file("/b/report.pdf", 5_000);
        let shared = Some(FileId {
            volume: 1,
            index: 42,
        });
        first.file_id = shared;
        second.file_id = shared;

        let merged = merge(vec![input("mac", vec![first, second], vec![(0, "same")])]);
        assert_eq!(
            merged.outcome.entries[0].file_id, merged.outcome.entries[1].file_id,
            "within one machine the identity is preserved"
        );
    }

    #[test]
    fn a_local_duplicate_is_distinguishable_from_a_shared_one() {
        // Two copies on one machine and one on another: the interface has to be
        // able to say which finding is which, because the answer changes what a
        // person does about it.
        let merged = merge(vec![
            input(
                "mac",
                vec![file("/one.pdf", 5_000), file("/two.pdf", 5_000)],
                vec![(0, "same"), (1, "same")],
            ),
            input(
                "windows",
                vec![file("C:/three.pdf", 9_000)],
                vec![(0, "other")],
            ),
        ]);

        let settled: HashMap<usize, Settled> = merged.settled.clone().into_iter().collect();
        let groups = group_duplicates(&merged.outcome.entries, &settled);
        assert_eq!(groups.len(), 1);

        let names: Vec<usize> = groups[0]
            .objects
            .iter()
            .flat_map(|object| object.names.clone())
            .collect();
        assert_eq!(merged.sources_among(&names), vec![0], "one machine only");
    }
}
