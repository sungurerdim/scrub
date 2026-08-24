//! Every stage of the pipeline, driven once and used by every interface.
//!
//! The command line and the desktop application are two ways of asking for the
//! same work. If each drove the stages itself they would drift — one would gain
//! a check the other lacked, and two artifacts claiming the same stage would
//! stop meaning the same thing. So the driving lives here, and both callers get
//! the identical result.
//!
//! Nothing in this crate prints, draws, or decides what a person should be
//! shown. Progress is handed to a [`Watch`], which the caller implements; a
//! caller that wants none uses [`Silent`]. What comes back is the finished
//! artifact, unwritten — where it goes is the caller's business.

#![forbid(unsafe_code)]

mod arrange;
mod carry;
mod look;
pub mod machine;

use std::fmt;
use std::path::{Path, PathBuf};

use scrub_core::artifact::{
    ArtifactHeader, Digest, MachineId, MachineScope, SCHEMA_VERSION, Stage,
};

pub use arrange::{merge, plan, preflight};
pub use carry::{Run, apply, undo};
pub use look::{Depth, analyze, candidates, scan};

/// Anything that stopped a stage from finishing.
///
/// One variant, because every caller does the same thing with it: says so. The
/// message is written for the person reading it, not for a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunError(String);

impl RunError {
    /// Wraps a message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The message, for a caller that wants to present it itself.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RunError {}

impl From<String> for RunError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<scrub_store::StoreError> for RunError {
    fn from(error: scrub_store::StoreError) -> Self {
        Self(error.to_string())
    }
}

impl From<scrub_platform::PlatformError> for RunError {
    fn from(error: scrub_platform::PlatformError) -> Self {
        Self(error.to_string())
    }
}

/// Which reading pass is running.
///
/// Analysis reads twice: once at both ends of every candidate, then in full for
/// the few that the first pass could not separate. They are reported apart
/// because they take wildly different amounts of time and a single bar covering
/// both would appear to stall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    /// Reading a little of each candidate.
    Sampling,
    /// Reading through the ones a sample could not separate.
    Reading,
}

/// Receives progress while a stage runs.
///
/// Every method does nothing by default, so a caller implements only the ones
/// it means to show. A stage never asks whether anybody is watching.
pub trait Watch {
    /// A root is being walked; `state` is where the walk has got to.
    fn walking(&mut self, root: &Path, state: &scrub_platform::walk::Progress<'_>) {
        let _ = (root, state);
    }

    /// A root has been walked.
    fn walked(&mut self, root: &Path, outcome: &scrub_core::inventory::ScanOutcome) {
        let _ = (root, outcome);
    }

    /// A reading pass is starting, over `total` files.
    fn pass_begins(&mut self, pass: Pass, total: usize) {
        let _ = (pass, total);
    }

    /// A reading pass has got through `done` files and `bytes` bytes.
    fn reading(&mut self, pass: Pass, done: usize, bytes: u64) {
        let _ = (pass, done, bytes);
    }

    /// A reading pass has finished.
    fn pass_ends(&mut self, pass: Pass) {
        let _ = pass;
    }

    /// A run has carried out `done` of `total` operations.
    fn operating(&mut self, done: usize, total: usize) {
        let _ = (done, total);
    }
}

/// A watcher that shows nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Silent;

impl Watch for Silent {}

/// Builds the header for an artifact this run produces.
///
/// The content digest is filled in by the caller once the body exists, because
/// several stages can only compute it from the finished artifact.
fn header_for(
    stage: Stage,
    parents: Vec<Digest>,
    machine: MachineId,
    scope_digest: Digest,
    content_digest: Digest,
) -> ArtifactHeader {
    ArtifactHeader {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        stage,
        kind: stage.output_kind(),
        parents,
        machine: MachineScope::Single { machine },
        created_at: jiff::Timestamp::now(),
        scope_digest,
        content_digest,
    }
}

/// A placeholder digest, replaced before the artifact is written.
fn pending() -> Digest {
    Digest::of(b"placeholder")
}

/// This account's home directory.
///
/// # Errors
///
/// Returns a message if the platform's home variable is not set.
pub fn home_directory() -> Result<PathBuf, RunError> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key).map(PathBuf::from).ok_or_else(|| {
        RunError::new(format!(
            "{key} is not set, so there is no home directory to scan"
        ))
    })
}

/// Refuses to start work whose output name is already taken.
///
/// The same refusal happens at the moment of writing, which is where the
/// invariant belongs. This one exists so that a scan of two million files does
/// not run to completion before announcing that its output name was taken.
///
/// # Errors
///
/// Returns a message naming the occupied path, and what to do about it.
pub fn check_output_is_free(out: &Path, replace: bool) -> Result<(), RunError> {
    if replace || !out.exists() {
        return Ok(());
    }
    Err(RunError::new(format!(
        "{} already exists, and nothing is overwritten without being asked. \
         Choose another name, or pass --replace to write over it.",
        out.display()
    )))
}

/// Turns the caller's intent into the store's answer about overwriting.
#[must_use]
pub fn replacement(replace: bool) -> scrub_store::Replace {
    if replace {
        scrub_store::Replace::Yes
    } else {
        scrub_store::Replace::Never
    }
}

/// Reads an artifact's header check, phrased for the person who has to act.
fn executable_here(header: &ArtifactHeader, machine: MachineId) -> Result<(), RunError> {
    scrub_core::artifact::verify_executable_here(header, machine)
        .map_err(|error| RunError::new(error.to_string()))
}

/// Names the file that could not be read, so the message says which one.
fn could_not_read(path: &Path, error: impl fmt::Display) -> RunError {
    RunError::new(format!("could not read {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_occupied_output_is_refused_before_any_work() {
        let place = tempfile::tempdir().expect("a temporary directory");
        let taken = place.path().join("scan.inventory");
        std::fs::write(&taken, b"an artifact from yesterday").expect("write");

        let refusal = check_output_is_free(&taken, false).expect_err("must refuse");
        assert!(
            refusal.message().contains("already exists"),
            "the message has to say why: {refusal}"
        );
        assert!(
            refusal.message().contains("--replace"),
            "and what to do about it: {refusal}"
        );

        check_output_is_free(&taken, true).expect("asked to replace, so it proceeds");
        check_output_is_free(&place.path().join("free.inventory"), false).expect("a free name");
    }

    #[test]
    fn a_watcher_need_only_implement_what_it_shows() {
        // The default methods are what let a caller ignore progress entirely.
        // If they stopped being defaults, every caller would have to grow
        // stubs, and stubs are where a forgotten update hides.
        struct CountsPasses(usize);
        impl Watch for CountsPasses {
            fn pass_begins(&mut self, _pass: Pass, _total: usize) {
                self.0 += 1;
            }
        }

        let mut watcher = CountsPasses(0);
        watcher.pass_begins(Pass::Sampling, 10);
        watcher.reading(Pass::Sampling, 1, 4_096);
        watcher.operating(1, 2);
        assert_eq!(watcher.0, 1);
    }
}
