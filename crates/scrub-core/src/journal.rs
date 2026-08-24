//! The record of what was actually done, written as it is done.
//!
//! Every change is written down before it is made and again after it succeeds.
//! That ordering is the whole design: a crash between the two leaves a step
//! recorded as intended but not finished, which is exactly the state that can be
//! reconciled by looking at the filesystem. The opposite ordering — act first,
//! record after — leaves changes nobody has any record of, and those cannot be
//! undone because nothing knows they happened.
//!
//! The journal is also the undo (DR-10). Reversing a run is reading this back
//! and moving each file to where it came from; there is no separate recovery
//! mode, no special case, and nothing to remember.

use std::path::PathBuf;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::artifact::Digest;
use crate::preflight::Impediment;

/// How far a step got.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Progress {
    /// Written down, not yet attempted.
    ///
    /// Finding one of these on start-up means the run stopped here. Whether the
    /// change happened is settled by looking, not by assuming.
    Intended,
    /// Done, and reversible from what is recorded here.
    Done,
    /// Not attempted, because something had changed since preflight.
    ///
    /// Not a failure: the world moved between checking and acting, which is
    /// ordinary on a machine somebody is using.
    Skipped(Impediment),
    /// Attempted and did not succeed. Nothing was changed by it.
    Failed(String),
}

/// One change, recorded before and after it happened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// Which operation of the plan this is.
    pub operation: usize,
    /// How far it got.
    pub progress: Progress,
    /// Where the file was.
    pub from: PathBuf,
    /// Where it went, once it went anywhere.
    pub to: Option<PathBuf>,
    /// What it contained, so a reversal can confirm it is moving the same file.
    pub content: Option<Digest>,
    /// When this was recorded.
    pub at: Timestamp,
}

impl Step {
    /// Whether this step changed the filesystem and can be reversed.
    #[must_use]
    pub fn is_reversible(&self) -> bool {
        self.progress == Progress::Done && self.to.is_some()
    }
}

/// What a run came to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Changes made.
    pub done: usize,
    /// Steps left alone because something had changed.
    pub skipped: usize,
    /// Steps that were attempted and did not succeed.
    pub failed: usize,
    /// Steps written down but never resolved — a run that stopped part-way.
    pub unresolved: usize,
    /// Bytes freed by what was done.
    pub freed: u64,
}

impl Tally {
    /// Whether the run finished with nothing left hanging.
    #[must_use]
    pub fn is_settled(self) -> bool {
        self.unresolved == 0
    }
}

/// Counts up a run.
#[must_use]
pub fn tally(steps: &[Step], freed_by: impl Fn(&Step) -> u64) -> Tally {
    let mut tally = Tally::default();
    for step in steps {
        match &step.progress {
            Progress::Done => {
                tally.done += 1;
                tally.freed += freed_by(step);
            }
            Progress::Skipped(_) => tally.skipped += 1,
            Progress::Failed(_) => tally.failed += 1,
            Progress::Intended => tally.unresolved += 1,
        }
    }
    tally
}

/// The steps a reversal would undo, newest first.
///
/// Order matters: a run that moved `a` to `b` and then `b` to `c` has to be
/// undone the other way round, or the second reversal finds nothing where it
/// expects it and the first puts a file back on top of one that is still there.
#[must_use]
pub fn reversal_order(steps: &[Step]) -> Vec<usize> {
    let mut reversible: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| step.is_reversible())
        .map(|(index, _)| index)
        .collect();
    reversible.reverse();
    reversible
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn step(operation: usize, progress: Progress, from: &str, to: Option<&str>) -> Step {
        Step {
            operation,
            progress,
            from: PathBuf::from(from),
            to: to.map(PathBuf::from),
            content: None,
            at: Timestamp::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_tally_counts_every_kind_of_ending() {
        let steps = vec![
            step(0, Progress::Done, "/a", Some("/q/a")),
            step(1, Progress::Skipped(Impediment::SourceMissing), "/b", None),
            step(2, Progress::Failed("no room".to_owned()), "/c", None),
            step(3, Progress::Intended, "/d", None),
        ];

        let counted = tally(&steps, |_| 4_096);
        assert_eq!(counted.done, 1);
        assert_eq!(counted.skipped, 1);
        assert_eq!(counted.failed, 1);
        assert_eq!(counted.unresolved, 1);
        assert_eq!(counted.freed, 4_096, "only what was done freed anything");
        assert!(!counted.is_settled());
    }

    #[test]
    fn a_step_that_was_only_intended_is_not_reversible() {
        // It may or may not have happened; that is settled by looking at the
        // filesystem, never by guessing. Reversing it blind could move a file
        // that was never moved.
        assert!(!step(0, Progress::Intended, "/a", None).is_reversible());
        assert!(!step(0, Progress::Skipped(Impediment::SourceMissing), "/a", None).is_reversible());
        assert!(step(0, Progress::Done, "/a", Some("/q/a")).is_reversible());
    }

    #[test]
    fn a_step_recorded_as_done_with_nowhere_to_return_to_is_not_reversible() {
        // Belt and braces: without a destination there is nothing to move back,
        // and pretending otherwise would report an undo that did nothing.
        assert!(!step(0, Progress::Done, "/a", None).is_reversible());
    }

    #[test]
    fn reversal_runs_backwards() {
        // The rotation case. Undoing a-to-b before b-to-c would put a file back
        // on top of one that has not left yet.
        let steps = vec![
            step(0, Progress::Done, "/a", Some("/b")),
            step(1, Progress::Skipped(Impediment::SourceMissing), "/x", None),
            step(2, Progress::Done, "/b", Some("/c")),
        ];

        assert_eq!(
            reversal_order(&steps),
            vec![2, 0],
            "newest first, and nothing that did not happen"
        );
    }

    #[test]
    fn a_settled_run_has_nothing_left_hanging() {
        let steps = vec![step(0, Progress::Done, "/a", Some("/q/a"))];
        assert!(tally(&steps, |_| 0).is_settled());
        assert!(tally(&[], |_| 0).is_settled());
    }

    #[test]
    fn the_record_carries_enough_to_move_a_file_back() {
        // What makes undo a matter of reading rather than of remembering.
        let recorded = step(0, Progress::Done, "/Documents/tax.pdf", Some("/q/tax.pdf"));
        assert_eq!(recorded.from, Path::new("/Documents/tax.pdf"));
        assert_eq!(recorded.to.as_deref(), Some(Path::new("/q/tax.pdf")));
    }
}
