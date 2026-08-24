//! Rearranging everything, with nothing happening.
//!
//! This is where somebody makes folders, renames things and moves them about,
//! and none of it touches a disk (DR-9). Each change is applied to a picture of
//! the filesystem held here, so the next change sees the world as the last one
//! left it: rename a folder, then move a file into it by its new name, and both
//! work — because the second change is asked about a folder that, as far as this
//! module is concerned, is already called that.
//!
//! What comes out is a list of operations and an account of what changed. The
//! operations are what a plan carries; the account is what lets an interface
//! show the old arrangement beside the new one before anybody commits to it.
//!
//! Two things are deliberately not possible here.
//!
//! **Nothing is deleted, and no folder is set aside.** Files go to quarantine
//! and come back the same way (DR-5). A folder does not, because moving a folder
//! is one atomic rename within a disk and nothing at all between two disks, and
//! a half-moved folder is the state this project exists to prevent. Setting
//! aside the files inside it does the same job and can be undone one file at a
//! time.
//!
//! **Nothing lands on top of anything.** A destination that is occupied — by a
//! file that is staying, by a folder about to be created, by another change
//! wanting the same name — is refused while it is still a question (DR-6).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::analysis::Settled;
use crate::inventory::{Entry, EntryKind};
use crate::plan::{Because, Operation, Subject};

/// One change somebody asked for.
///
/// Recorded as intent rather than as a finished path, so the account of what was
/// asked survives alongside what it came to mean. "Rename entry 41 to `Tax`"
/// stays readable after the folder above it has also moved; a bare pair of paths
/// would not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edit {
    /// Make a folder that does not exist yet.
    NewDirectory {
        /// Where it goes, in full.
        path: PathBuf,
    },
    /// Give something a different name, where it already is.
    Rename {
        /// Which entry of the inventory.
        entry: usize,
        /// The new name — a name, never a path.
        to: String,
    },
    /// Put something inside a different folder, under the name it has.
    Relocate {
        /// Which entry of the inventory.
        entry: usize,
        /// The folder it goes into.
        into: PathBuf,
    },
    /// Set a file aside, recoverably.
    SetAside {
        /// Which entry of the inventory.
        entry: usize,
    },
}

/// Why a change could not be made.
///
/// Every one of these is a sentence an interface can show as it stands. A
/// refusal somebody cannot act on is a refusal that becomes a shrug.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trouble {
    /// The inventory has no such entry.
    NoSuchEntry,
    /// A name was given where a name was expected, and it was not one.
    ///
    /// Carries what was wrong with it: empty, or containing a separator, or one
    /// of the two names every directory already has.
    NotAName(String),
    /// Something is already at the destination.
    Occupied,
    /// A folder cannot be moved inside itself.
    IntoItself,
    /// The destination is not a folder, or is not going to be one.
    NotADirectory,
    /// The thing being acted on has already been set aside.
    AlreadyAside,
    /// A folder was asked to be set aside, which this tool does not do.
    FoldersAreNotSetAside,
    /// A path was given that is not absolute, so it names nowhere in particular.
    NotAbsolute,
}

impl Trouble {
    /// The refusal in words, for an interface to show unchanged.
    #[must_use]
    pub fn say(&self) -> String {
        match self {
            Self::NoSuchEntry => {
                "that is not in this scan any more — scan again and try it".to_owned()
            }
            Self::NotAName(why) => why.clone(),
            Self::Occupied => {
                "something is already there, and nothing is ever written over".to_owned()
            }
            Self::IntoItself => "a folder cannot be put inside itself".to_owned(),
            Self::NotADirectory => "that destination is not a folder".to_owned(),
            Self::AlreadyAside => "that has already been set aside".to_owned(),
            Self::FoldersAreNotSetAside => {
                "folders are not set aside — set aside the files inside it, \
                 which can be undone one at a time"
                    .to_owned()
            }
            Self::NotAbsolute => "that path does not say where it starts from".to_owned(),
        }
    }
}

/// A change that was asked for and not made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// Which change, by position in the list asked for.
    pub edit: usize,
    /// Why.
    pub because: Trouble,
}

/// Where something is, and where it is going.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Which entry of the inventory.
    pub entry: usize,
    /// Where it was when the scan ran.
    pub was: PathBuf,
    /// Where it will be, or `None` if it is being set aside.
    pub becomes: Option<PathBuf>,
    /// Whether it moved because a folder above it moved, rather than by itself.
    ///
    /// Shown differently, because "you renamed a folder and forty things came
    /// with it" is one decision, not forty.
    pub carried: bool,
}

/// What is at a path, as far as the arrangement is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Occupant {
    /// An entry from the scan.
    Entry(usize),
    /// A folder these changes will create.
    NewDirectory,
}

/// A picture of the filesystem that changes are applied to.
///
/// Built once from an inventory and then handed one change at a time. It is
/// deliberately not rebuilt per change: the index over a real machine's two and
/// a half million entries costs a second to build and nothing to consult, and an
/// interface that rebuilt it on every keystroke would feel broken.
pub struct Arrangement<'a> {
    entries: &'a [Entry],
    /// Every entry by the path it had when the scan ran.
    ///
    /// Borrowed rather than owned: copying two and a half million paths to make
    /// a lookup table is a quarter of a gigabyte spent on something the entries
    /// already hold.
    was_at: BTreeMap<&'a Path, usize>,
    /// Where entries have moved to, for those that have.
    moved: BTreeMap<usize, PathBuf>,
    /// Paths that now hold something that was not there before.
    now_at: BTreeMap<PathBuf, Occupant>,
    /// Entries being set aside.
    aside: BTreeSet<usize>,
    /// Changes asked for, in the order they were asked.
    asked: Vec<Edit>,
    /// Changes asked for and refused.
    refused: Vec<Refusal>,
}

impl<'a> Arrangement<'a> {
    /// Starts from what the scan found, with nothing changed.
    #[must_use]
    pub fn of(entries: &'a [Entry]) -> Self {
        Self {
            entries,
            was_at: entries
                .iter()
                .enumerate()
                .map(|(index, entry)| (entry.path.as_path(), index))
                .collect(),
            moved: BTreeMap::new(),
            now_at: BTreeMap::new(),
            aside: BTreeSet::new(),
            asked: Vec::new(),
            refused: Vec::new(),
        }
    }

    /// Replays a list of changes onto a fresh arrangement.
    ///
    /// What an interface does when it opens a plan somebody left yesterday.
    #[must_use]
    pub fn replaying(entries: &'a [Entry], edits: &[Edit]) -> Self {
        let mut arrangement = Self::of(entries);
        for edit in edits {
            let _ = arrangement.apply(edit.clone());
        }
        arrangement
    }

    /// Applies one change.
    ///
    /// # Errors
    ///
    /// Returns why it could not be made. A refused change is still recorded —
    /// an interface showing a list of what was asked should show the one that
    /// did not work, rather than having it vanish.
    pub fn apply(&mut self, edit: Edit) -> Result<(), Trouble> {
        let position = self.asked.len();
        let outcome = self.attempt(&edit);
        self.asked.push(edit);
        if let Err(because) = &outcome {
            self.refused.push(Refusal {
                edit: position,
                because: because.clone(),
            });
        }
        outcome
    }

    /// Takes back the last change asked for, whether or not it worked.
    ///
    /// Implemented by replaying the rest from the beginning rather than by
    /// reversing anything. Reversing a change means knowing what it displaced,
    /// what it carried, and what a later change did on top — three things that
    /// have to be right every time. Replaying has one thing to get right, and it
    /// is the thing already covered by every other test here.
    pub fn take_back_last(&mut self) {
        if self.asked.pop().is_none() {
            return;
        }
        let again = std::mem::take(&mut self.asked);
        *self = Self::replaying(self.entries, &again);
    }

    /// Everything asked for, in order.
    #[must_use]
    pub fn asked(&self) -> &[Edit] {
        &self.asked
    }

    /// Everything asked for and refused.
    #[must_use]
    pub fn refused(&self) -> &[Refusal] {
        &self.refused
    }

    /// Where an entry is now, as far as these changes are concerned.
    #[must_use]
    pub fn path_of(&self, entry: usize) -> Option<&Path> {
        self.moved
            .get(&entry)
            .map(PathBuf::as_path)
            .or_else(|| self.entries.get(entry).map(|found| found.path.as_path()))
    }

    /// Folders these changes would create, in the order they must be made.
    #[must_use]
    pub fn new_directories(&self) -> Vec<PathBuf> {
        // Sorted, so a folder is made before anything nested inside it: a path
        // sorts before every path that extends it.
        self.now_at
            .iter()
            .filter(|(_, occupant)| **occupant == Occupant::NewDirectory)
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Everything that would end up somewhere other than where it was.
    ///
    /// Sorted by where it was, because that is the order somebody reading a
    /// before-and-after wants: the left column in the order they know.
    #[must_use]
    pub fn changes(&self) -> Vec<Change> {
        let asked_for: BTreeSet<usize> = self
            .asked
            .iter()
            .filter_map(|edit| match edit {
                Edit::Rename { entry, .. }
                | Edit::Relocate { entry, .. }
                | Edit::SetAside { entry } => Some(*entry),
                Edit::NewDirectory { .. } => None,
            })
            .collect();

        let mut changes: Vec<Change> = self
            .moved
            .iter()
            .filter_map(|(entry, becomes)| {
                Some(Change {
                    entry: *entry,
                    was: self.entries.get(*entry)?.path.clone(),
                    becomes: Some(becomes.clone()),
                    carried: !asked_for.contains(entry),
                })
            })
            .chain(self.aside.iter().filter_map(|entry| {
                Some(Change {
                    entry: *entry,
                    was: self.entries.get(*entry)?.path.clone(),
                    becomes: None,
                    carried: !asked_for.contains(entry),
                })
            }))
            .collect();

        changes.sort_by(|left, right| left.was.cmp(&right.was));
        changes
    }

    /// The operations these changes come to.
    ///
    /// One operation per change asked for, never one per thing affected: a
    /// folder that moves takes its contents with it, and emitting a move for
    /// every file inside would be both slower and wrong — the files are not
    /// there any more by the time their turn came.
    #[must_use]
    pub fn operations(&self, settled: &BTreeMap<usize, Settled>) -> Vec<Operation> {
        let mut operations: Vec<Operation> = self
            .new_directories()
            .into_iter()
            .map(|path| Operation::CreateDirectory { path })
            .collect();

        let content = |entry: usize| settled.get(&entry).and_then(|found| found.content());

        for edit in &self.asked {
            match edit {
                Edit::NewDirectory { .. } => {}
                Edit::Rename { entry, .. } | Edit::Relocate { entry, .. } => {
                    let (Some(source), Some(destination)) =
                        (self.entries.get(*entry), self.moved.get(entry))
                    else {
                        continue;
                    };
                    operations.push(Operation::Move {
                        subject: Subject::of(*entry, source, content(*entry)),
                        destination: destination.clone(),
                    });
                }
                Edit::SetAside { entry } => {
                    let Some(source) = self
                        .entries
                        .get(*entry)
                        .filter(|_| self.aside.contains(entry))
                    else {
                        continue;
                    };
                    operations.push(Operation::Quarantine {
                        subject: Subject::of(*entry, source, content(*entry)),
                        because: Because::Requested,
                    });
                }
            }
        }

        operations
    }

    // ---- the working parts ----

    fn attempt(&mut self, edit: &Edit) -> Result<(), Trouble> {
        match edit {
            Edit::NewDirectory { path } => self.make_directory(path),
            Edit::Rename { entry, to } => {
                let here = self.living_path(*entry)?;
                let name = check_name(to)?;
                let destination = here
                    .parent()
                    .map_or_else(|| PathBuf::from(&name), |parent| parent.join(&name));
                self.put(*entry, destination)
            }
            Edit::Relocate { entry, into } => {
                let here = self.living_path(*entry)?;
                if !into.is_absolute() {
                    return Err(Trouble::NotAbsolute);
                }
                if !self.is_a_directory(into) {
                    return Err(Trouble::NotADirectory);
                }
                let name = here
                    .file_name()
                    .ok_or_else(|| Trouble::NotAName("that has no name to keep".to_owned()))?;
                let destination = into.join(name);
                self.put(*entry, destination)
            }
            Edit::SetAside { entry } => {
                let _ = self.living_path(*entry)?;
                let kind = self.entries.get(*entry).ok_or(Trouble::NoSuchEntry)?.kind;
                if kind == EntryKind::Directory {
                    return Err(Trouble::FoldersAreNotSetAside);
                }
                self.set_aside(*entry);
                Ok(())
            }
        }
    }

    /// Where an entry currently is, refusing one that is gone.
    fn living_path(&self, entry: usize) -> Result<PathBuf, Trouble> {
        if self.aside.contains(&entry) {
            return Err(Trouble::AlreadyAside);
        }
        self.path_of(entry)
            .map(Path::to_path_buf)
            .ok_or(Trouble::NoSuchEntry)
    }

    fn make_directory(&mut self, path: &Path) -> Result<(), Trouble> {
        if !path.is_absolute() {
            return Err(Trouble::NotAbsolute);
        }
        if path
            .file_name()
            .is_none_or(|name| check_name(&name.to_string_lossy()).is_err())
        {
            return Err(Trouble::NotAName(
                "a folder needs a name of its own".to_owned(),
            ));
        }
        if self.what_is_at(path).is_some() {
            return Err(Trouble::Occupied);
        }
        self.now_at
            .insert(path.to_path_buf(), Occupant::NewDirectory);
        Ok(())
    }

    /// Moves an entry, taking anything inside it along.
    fn put(&mut self, entry: usize, destination: PathBuf) -> Result<(), Trouble> {
        let here = self.living_path(entry)?;
        if here == destination {
            // Asking for the name something already has is not a change and not
            // a mistake. Nothing happens, and nothing is reported.
            return Ok(());
        }
        if destination.starts_with(&here) {
            return Err(Trouble::IntoItself);
        }
        if self.what_is_at(&destination).is_some() {
            return Err(Trouble::Occupied);
        }

        let is_directory = self
            .entries
            .get(entry)
            .is_some_and(|found| found.kind == EntryKind::Directory);

        // Everything under it comes too, and is recorded as having come rather
        // than as having been asked for.
        if is_directory {
            for carried in self.inside(&here) {
                let Some(was) = self.path_of(carried).map(Path::to_path_buf) else {
                    continue;
                };
                let Ok(under) = was.strip_prefix(&here) else {
                    continue;
                };
                let lands = destination.join(under);
                self.moved.insert(carried, lands.clone());
                self.now_at.insert(lands, Occupant::Entry(carried));
            }
        }

        self.now_at.remove(&here);
        self.moved.insert(entry, destination.clone());
        self.now_at.insert(destination, Occupant::Entry(entry));
        Ok(())
    }

    fn set_aside(&mut self, entry: usize) {
        if let Some(here) = self.path_of(entry).map(Path::to_path_buf) {
            self.now_at.remove(&here);
        }
        self.moved.remove(&entry);
        self.aside.insert(entry);
    }

    /// What, if anything, is at a path right now.
    fn what_is_at(&self, path: &Path) -> Option<Occupant> {
        if let Some(occupant) = self.now_at.get(path) {
            return Some(*occupant);
        }

        // Nothing sits inside a folder that has moved away or been emptied: the
        // move rewrote every path underneath it, so a stale one names nowhere.
        if self.has_left(path) {
            return None;
        }

        self.was_at.get(path).map(|entry| Occupant::Entry(*entry))
    }

    /// Whether the thing originally at this path is no longer there.
    fn has_left(&self, path: &Path) -> bool {
        self.was_at
            .get(path)
            .is_some_and(|entry| self.moved.contains_key(entry) || self.aside.contains(entry))
    }

    fn is_a_directory(&self, path: &Path) -> bool {
        match self.what_is_at(path) {
            Some(Occupant::NewDirectory) => true,
            Some(Occupant::Entry(entry)) => self
                .entries
                .get(entry)
                .is_some_and(|found| found.kind == EntryKind::Directory),
            None => false,
        }
    }

    /// Every entry currently under a folder, however it got there.
    fn inside(&self, folder: &Path) -> Vec<usize> {
        let mut found: BTreeSet<usize> = self
            .was_at
            .range(folder..)
            .take_while(|(path, _)| path.starts_with(folder))
            .filter(|(path, _)| path.as_os_str() != folder.as_os_str())
            .map(|(_, entry)| *entry)
            .filter(|entry| !self.moved.contains_key(entry) && !self.aside.contains(entry))
            .collect();

        // Anything that was moved in here since is under it too.
        found.extend(
            self.moved
                .iter()
                .filter(|(entry, path)| {
                    path.starts_with(folder)
                        && path.as_path() != folder
                        && !self.aside.contains(entry)
                })
                .map(|(entry, _)| *entry),
        );

        found.into_iter().collect()
    }
}

/// Checks that a name is a name and not a path, an escape, or nothing at all.
///
/// The one place a person types free text that becomes a filesystem path, which
/// makes it the one place a slash turns "rename this to `Tax`" into "move it
/// three folders up" (DR-20).
fn check_name(name: &str) -> Result<String, Trouble> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Trouble::NotAName("a name cannot be empty".to_owned()));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(Trouble::NotAName(
            "every folder already has those two names".to_owned(),
        ));
    }

    // Asking the platform rather than looking for a slash: what separates one
    // path component from another is the platform's business, and on Windows
    // there are two of them.
    let as_path = Path::new(trimmed);
    let mut components = as_path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(only)), None) if only == trimmed => Ok(trimmed.to_owned()),
        _ => Err(Trouble::NotAName(
            "a name cannot contain a path separator — to move something, move it".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::CloudState;

    fn thing(path: &str, kind: EntryKind) -> Entry {
        Entry {
            path: PathBuf::from(path),
            kind,
            logical_size: 10,
            allocated_size: Some(10),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState::not_synced(),
        }
    }

    fn a_small_machine() -> Vec<Entry> {
        vec![
            thing("/home/Documents", EntryKind::Directory),
            thing("/home/Documents/tax.pdf", EntryKind::File),
            thing("/home/Documents/old", EntryKind::Directory),
            thing("/home/Documents/old/tax.pdf", EntryKind::File),
            thing("/home/Desktop", EntryKind::Directory),
            thing("/home/Desktop/notes.txt", EntryKind::File),
        ]
    }

    #[test]
    fn a_change_sees_the_world_the_last_one_left() {
        // The whole reason this module holds a picture rather than a list: a
        // person renames a folder and then works with the new name, because
        // that is what they are looking at.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        arrangement
            .apply(Edit::Rename {
                entry: 0,
                to: "Papers".to_owned(),
            })
            .expect("renaming a folder");

        arrangement
            .apply(Edit::Relocate {
                entry: 5,
                into: PathBuf::from("/home/Papers"),
            })
            .expect("moving a file into the folder by its new name");

        assert_eq!(
            arrangement.path_of(5),
            Some(Path::new("/home/Papers/notes.txt"))
        );
    }

    #[test]
    fn renaming_a_folder_carries_everything_inside_it() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        arrangement
            .apply(Edit::Rename {
                entry: 0,
                to: "Papers".to_owned(),
            })
            .expect("renaming a folder");

        assert_eq!(
            arrangement.path_of(1),
            Some(Path::new("/home/Papers/tax.pdf")),
            "a file one level down"
        );
        assert_eq!(
            arrangement.path_of(3),
            Some(Path::new("/home/Papers/old/tax.pdf")),
            "and one two levels down"
        );

        let carried = arrangement
            .changes()
            .into_iter()
            .filter(|change| change.carried)
            .count();
        assert_eq!(carried, 3, "the file, the folder, and the file in it");
    }

    #[test]
    fn a_folder_that_moves_produces_one_operation_not_one_per_file() {
        // The filesystem moves the contents; emitting a move per file would ask
        // for each of them at a path it had already left.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        arrangement
            .apply(Edit::Rename {
                entry: 0,
                to: "Papers".to_owned(),
            })
            .expect("renaming a folder");

        let operations = arrangement.operations(&BTreeMap::new());
        assert_eq!(operations.len(), 1, "one rename, one operation");
        assert!(matches!(operations[0], Operation::Move { .. }));
    }

    #[test]
    fn nothing_may_land_on_anything() {
        // DR-6, while it is still a question rather than a half-done job.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        let refusal = arrangement
            .apply(Edit::Relocate {
                entry: 3,
                into: PathBuf::from("/home/Documents"),
            })
            .expect_err("there is already a tax.pdf there");
        assert_eq!(refusal, Trouble::Occupied);
        assert!(
            refusal.say().contains("already there"),
            "the refusal reads as a sentence: {}",
            refusal.say()
        );
    }

    #[test]
    fn a_place_something_is_leaving_is_not_occupied() {
        // Moving `a` out and `b` in is an ordinary swap, not a collision.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        arrangement
            .apply(Edit::Relocate {
                entry: 1,
                into: PathBuf::from("/home/Desktop"),
            })
            .expect("moving the outer tax.pdf away");
        arrangement
            .apply(Edit::Relocate {
                entry: 3,
                into: PathBuf::from("/home/Documents"),
            })
            .expect("the name it left is now free");

        assert_eq!(
            arrangement.path_of(3),
            Some(Path::new("/home/Documents/tax.pdf"))
        );
    }

    #[test]
    fn a_name_with_a_separator_in_it_is_not_a_name() {
        // The one place free text becomes a path. A slash here would turn a
        // rename into a move somebody did not ask for.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        let refusal = arrangement
            .apply(Edit::Rename {
                entry: 1,
                to: "../../tax.pdf".to_owned(),
            })
            .expect_err("that is a path, not a name");
        assert!(matches!(refusal, Trouble::NotAName(_)));

        for attempt in ["", "   ", ".", "..", "a/b"] {
            assert!(
                check_name(attempt).is_err(),
                "{attempt:?} should not pass as a name"
            );
        }
        assert_eq!(check_name(" Tax ").expect("a name"), "Tax", "trimmed");
    }

    #[test]
    fn a_folder_cannot_be_put_inside_itself() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        let refusal = arrangement
            .apply(Edit::Relocate {
                entry: 0,
                into: PathBuf::from("/home/Documents/old"),
            })
            .expect_err("that is inside the thing being moved");
        assert_eq!(refusal, Trouble::IntoItself);
    }

    #[test]
    fn folders_are_not_set_aside() {
        // Quarantining a folder is one atomic rename within a disk and nothing
        // at all between two, and a half-moved folder is the state this project
        // exists to prevent.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        let refusal = arrangement
            .apply(Edit::SetAside { entry: 0 })
            .expect_err("folders are not set aside");
        assert_eq!(refusal, Trouble::FoldersAreNotSetAside);
        assert!(refusal.say().contains("files inside"));
    }

    #[test]
    fn a_new_folder_can_be_made_and_moved_into() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);

        arrangement
            .apply(Edit::NewDirectory {
                path: PathBuf::from("/home/Papers"),
            })
            .expect("a folder that is not there yet");
        arrangement
            .apply(Edit::Relocate {
                entry: 1,
                into: PathBuf::from("/home/Papers"),
            })
            .expect("moving into a folder that does not exist yet either");

        let operations = arrangement.operations(&BTreeMap::new());
        assert!(
            matches!(&operations[0], Operation::CreateDirectory { path } if path == Path::new("/home/Papers")),
            "the folder is made first"
        );
        assert_eq!(operations.len(), 2);
    }

    #[test]
    fn a_folder_cannot_be_made_where_something_already_is() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        assert_eq!(
            arrangement.apply(Edit::NewDirectory {
                path: PathBuf::from("/home/Desktop")
            }),
            Err(Trouble::Occupied)
        );
    }

    #[test]
    fn taking_back_a_change_leaves_exactly_what_was_there_before() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        arrangement
            .apply(Edit::Rename {
                entry: 0,
                to: "Papers".to_owned(),
            })
            .expect("renaming");

        let before: Vec<Change> = arrangement.changes();
        arrangement
            .apply(Edit::SetAside { entry: 5 })
            .expect("setting a file aside");
        arrangement.take_back_last();

        assert_eq!(
            arrangement.changes(),
            before,
            "taking back the last change restores the arrangement exactly"
        );
        assert_eq!(arrangement.asked().len(), 1);
    }

    #[test]
    fn a_refused_change_is_kept_in_the_account() {
        // A change that vanishes when it fails is a change somebody thinks they
        // made.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        let _ = arrangement.apply(Edit::SetAside { entry: 0 });

        assert_eq!(arrangement.asked().len(), 1);
        assert_eq!(arrangement.refused().len(), 1);
        assert_eq!(arrangement.refused()[0].edit, 0);
    }

    #[test]
    fn the_account_says_what_moved_by_itself_and_what_came_along() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        arrangement
            .apply(Edit::Rename {
                entry: 2,
                to: "archive".to_owned(),
            })
            .expect("renaming the inner folder");

        let changes = arrangement.changes();
        let asked: Vec<&Change> = changes.iter().filter(|change| !change.carried).collect();
        let carried: Vec<&Change> = changes.iter().filter(|change| change.carried).collect();

        assert_eq!(asked.len(), 1, "one decision was made");
        assert_eq!(carried.len(), 1, "one file came with it");
        assert_eq!(asked[0].was, Path::new("/home/Documents/old"));
        assert_eq!(
            asked[0].becomes.as_deref(),
            Some(Path::new("/home/Documents/archive"))
        );
    }

    #[test]
    fn setting_something_aside_leaves_it_nowhere_rather_than_somewhere() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        arrangement
            .apply(Edit::SetAside { entry: 1 })
            .expect("setting a file aside");

        let changes = arrangement.changes();
        let gone = changes
            .iter()
            .find(|change| change.entry == 1)
            .expect("it is in the account");
        assert_eq!(
            gone.becomes, None,
            "where in quarantine it lands is settled when it lands, not now"
        );

        assert_eq!(
            arrangement.apply(Edit::SetAside { entry: 1 }),
            Err(Trouble::AlreadyAside)
        );
    }

    #[test]
    fn replaying_a_list_gives_the_same_arrangement_as_applying_it() {
        // What lets a plan somebody left yesterday be opened and carried on
        // with (DR-12).
        let entries = a_small_machine();
        let edits = vec![
            Edit::NewDirectory {
                path: PathBuf::from("/home/Papers"),
            },
            Edit::Rename {
                entry: 2,
                to: "archive".to_owned(),
            },
            Edit::Relocate {
                entry: 5,
                into: PathBuf::from("/home/Papers"),
            },
            Edit::SetAside { entry: 1 },
        ];

        let mut applied = Arrangement::of(&entries);
        for edit in &edits {
            let _ = applied.apply(edit.clone());
        }
        let replayed = Arrangement::replaying(&entries, &edits);

        assert_eq!(applied.changes(), replayed.changes());
        assert_eq!(applied.new_directories(), replayed.new_directories());
        assert_eq!(
            applied.operations(&BTreeMap::new()),
            replayed.operations(&BTreeMap::new())
        );
    }

    #[test]
    fn a_folder_is_moved_before_anything_is_moved_into_it() {
        // Load-bearing, and easy to break by accident. Ordering puts moves in
        // order of destination, and a folder's path sorts before every path
        // inside it — so the folder arrives before its new contents do. If that
        // ever stopped holding, the second move would name a folder that does
        // not exist yet.
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        arrangement
            .apply(Edit::Rename {
                entry: 0,
                to: "Papers".to_owned(),
            })
            .expect("renaming the folder");
        arrangement
            .apply(Edit::Relocate {
                entry: 5,
                into: PathBuf::from("/home/Papers"),
            })
            .expect("moving a file into it");

        let ordered = crate::plan::ordered(arrangement.operations(&BTreeMap::new()));
        let destinations: Vec<&Path> = ordered
            .iter()
            .filter_map(crate::plan::Operation::destination)
            .collect();
        assert_eq!(
            destinations,
            vec![
                Path::new("/home/Papers"),
                Path::new("/home/Papers/notes.txt")
            ],
            "the folder first, then what goes in it"
        );
    }

    #[test]
    fn moving_something_onto_the_name_it_already_has_changes_nothing() {
        let entries = a_small_machine();
        let mut arrangement = Arrangement::of(&entries);
        arrangement
            .apply(Edit::Rename {
                entry: 1,
                to: "tax.pdf".to_owned(),
            })
            .expect("the name it already has is not a mistake");

        assert!(
            arrangement.changes().is_empty(),
            "and it is not a change either"
        );
        assert!(arrangement.operations(&BTreeMap::new()).is_empty());
    }
}
