//! Where the window keeps its place between one step and the next.
//!
//! The pipeline's stages are independent by design (DR-17): each reads the file
//! the one before it wrote, and nothing is passed in memory. The window does not
//! change that. What it keeps is only the paths — which artifact is the current
//! inventory, which the current analysis — so the person clicking through does
//! not have to name a file at every step.
//!
//! Everything is written under one directory, and that directory is the whole
//! of the tool's state. Deleting it loses nothing except the need to scan
//! again, and it contains no copy of anybody's files: only sizes, dates, paths
//! and digests (DR-3).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use scrub_core::artifact::MachineId;
use scrub_core::edit::Edit;
use scrub_core::inventory::Entry;
use scrub_run::RunError;

/// The current state of one person's way through the pipeline.
#[derive(Debug, Default)]
pub struct Session {
    /// Where artifacts are written.
    workspace: PathBuf,
    /// This machine's identity, read once.
    machine: Option<MachineId>,
    /// What the scan found, held while somebody is rearranging it.
    ///
    /// Kept in memory rather than read per change, and that is a deliberate
    /// trade. A real machine's inventory is about a gigabyte; reading it again
    /// for every folder somebody renames would make rearranging unusable, and
    /// rearranging is the part of this tool a person spends time in. It is
    /// dropped when a new scan replaces it.
    entries: Vec<Entry>,
    /// The changes somebody has made, in the order they made them.
    edits: Vec<Edit>,
}

/// The session, shared with every command.
#[derive(Debug, Default)]
pub struct Shared(pub Mutex<Session>);

/// The names each stage's artifact is given.
///
/// Fixed rather than timestamped: a person who has scanned twice wants the
/// second scan, and a directory filling with `scan-2026-08-24T11-04-22` is a
/// directory nobody can read. Replacing one is always an explicit act, and the
/// artifact before it is what the undo record points at, not this name.
pub const INVENTORY: &str = "current.inventory";
/// The current analysis.
pub const ANALYSIS: &str = "current.analysis";
/// The current plan.
pub const PLAN: &str = "current.plan";
/// The current preflight.
pub const PREFLIGHT: &str = "current.preflight";
/// The record of the last run.
pub const JOURNAL: &str = "current.journal";
/// The record of the last reversal.
pub const REVERSAL: &str = "reversal.journal";

impl Session {
    /// Settles where artifacts go, and reads this machine's identity.
    ///
    /// # Errors
    ///
    /// Returns a message if the directory could not be made or the identity
    /// could not be read.
    pub fn open(workspace: PathBuf) -> Result<Self, RunError> {
        // DR-11-EXEMPT: the tool's own workspace directory, chosen by the
        // platform for this application. It is never a path a scan discovered,
        // and nothing of the user's is ever inside it.
        std::fs::create_dir_all(&workspace).map_err(|error| {
            RunError::new(format!("could not create {}: {error}", workspace.display()))
        })?;

        Ok(Self {
            workspace,
            machine: Some(scrub_run::machine::identity()?),
            entries: Vec::new(),
            edits: Vec::new(),
        })
    }

    /// Holds entries describing the same scan, keeping any arrangement.
    ///
    /// An analysis carries the scan's entries forward unchanged, so a change
    /// that named entry 41 still names the same thing. Clearing the arrangement
    /// here would throw away somebody's work for looking at duplicates.
    pub fn hold(&mut self, entries: Vec<Entry>) {
        self.entries = entries;
    }

    /// Holds what a fresh scan found, and forgets what was arranged.
    ///
    /// A new scan describes a different machine-moment, and a change that named
    /// entry 41 in the old one names something else in the new one. Keeping
    /// them would be worse than losing them (DR-18).
    pub fn restart_with(&mut self, entries: Vec<Entry>) {
        self.entries = entries;
        self.edits.clear();
    }

    /// What the scan found, if it is still held.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The changes somebody has made.
    #[must_use]
    pub fn edits(&self) -> &[Edit] {
        &self.edits
    }

    /// Replaces the list of changes, after one has been added or taken back.
    pub fn remember(&mut self, edits: Vec<Edit>) {
        self.edits = edits;
    }

    /// Where artifacts are written.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// The path one stage's artifact has.
    #[must_use]
    pub fn artifact(&self, name: &str) -> PathBuf {
        self.workspace.join(name)
    }

    /// This machine's identity.
    ///
    /// # Errors
    ///
    /// Returns a message if the session was never opened, which would mean a
    /// command ran before the window was ready.
    pub fn machine(&self) -> Result<MachineId, RunError> {
        self.machine.ok_or_else(|| {
            RunError::new("this session has not been opened yet, so nothing can run in it")
        })
    }

    /// Whether a stage has produced its artifact.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.artifact(name).exists()
    }

    /// Refuses a stage whose input has not been produced.
    ///
    /// The message names the step to take rather than the file that is missing,
    /// because "run a scan first" is actionable and "current.inventory does not
    /// exist" is not.
    ///
    /// # Errors
    ///
    /// Returns that message when the input is absent.
    pub fn require(&self, name: &str, take_this_step: &str) -> Result<PathBuf, RunError> {
        let path = self.artifact(name);
        if path.exists() {
            return Ok(path);
        }
        Err(RunError::new(format!(
            "there is nothing to work from yet — {take_this_step} first"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_input_names_the_step_to_take_rather_than_the_file() {
        let place = tempfile::tempdir().expect("a temporary directory");
        let session = Session::open(place.path().join("workspace")).expect("a workspace");

        let refusal = session
            .require(INVENTORY, "scan this machine")
            .expect_err("nothing has been scanned");
        assert!(
            refusal.message().contains("scan this machine"),
            "the message has to say what to do: {refusal}"
        );
        assert!(
            !refusal.message().contains(INVENTORY),
            "and not name an internal file: {refusal}"
        );
    }

    #[test]
    fn opening_a_session_creates_the_place_its_artifacts_go() {
        let place = tempfile::tempdir().expect("a temporary directory");
        let workspace = place.path().join("nested/workspace");
        let session = Session::open(workspace.clone()).expect("a workspace");

        assert!(workspace.is_dir(), "the directory has to exist afterwards");
        assert_eq!(session.artifact(ANALYSIS), workspace.join(ANALYSIS));
        assert!(!session.has(ANALYSIS), "nothing has been analysed yet");
    }
}
