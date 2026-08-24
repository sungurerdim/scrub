//! Grading a plan before any of it runs.
//!
//! Verification and execution are separate stages on purpose (DR-19). This one
//! writes nothing at all: it looks at every operation, decides whether it can
//! proceed, and says so. The result is a complete account of what will happen
//! and what will not, produced while the filesystem is still untouched.
//!
//! The alternative — checking each operation as it is about to run — sounds
//! equivalent and is not. It finds the fortieth problem after thirty-nine
//! changes have already been made, which leaves someone with a half-rearranged
//! disk and a decision to make about it. Everything worth knowing is worth
//! knowing first.

use serde::{Deserialize, Serialize};

use crate::artifact::Digest;

/// How thoroughly an operation's subject was checked.
///
/// Recorded so that execution knows how much the verdict is worth, and so a
/// person reading the report knows what was actually established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rigour {
    /// The file's content was read again and matched what the plan recorded.
    ///
    /// The default, and what the tool is for. It costs a second full read of
    /// everything the plan touches, which is the price of being sure.
    Content,
    /// Only the file's size and modification time were compared.
    ///
    /// Fast, and enough to catch anything an ordinary edit would do. It cannot
    /// catch a file replaced by another of exactly the same size whose timestamp
    /// was preserved, which is rare and not impossible.
    Metadata,
}

/// Why an operation cannot proceed as written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impediment {
    /// The file the plan names is not there any more.
    SourceMissing,
    /// The file is there, but it is not the file the plan recorded.
    SourceChanged {
        /// What the plan expected.
        expected: Expectation,
        /// What is actually there.
        found: Expectation,
    },
    /// Something is already at the destination.
    DestinationOccupied,
    /// The destination's parent directory does not exist and is not being made.
    DestinationUnreachable,
    /// The system refused access to the file or its destination.
    PermissionDenied,
    /// The content is not on this machine, so it cannot be verified or moved.
    ///
    /// A placeholder can be moved by the sync client but not by us: doing it
    /// behind the client's back is how a provider ends up deleting the remote
    /// copy (DR-20).
    ContentNotPresent,
    /// Something else, reported verbatim.
    Other(String),
}

/// The facts an operation's subject was matched against.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expectation {
    /// Its size.
    pub logical_size: Option<u64>,
    /// Its modification time, in whole seconds.
    pub modified_second: Option<i64>,
    /// Its content, where that was read.
    pub content: Option<Digest>,
}

/// What preflight concluded about one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// Everything checked out. This one will run.
    Pass,
    /// Something changed or is unresolved. It will not run, and it can be.
    ///
    /// A hold is a question, not a failure: the file moved, the destination
    /// filled up, the content is in the cloud. Replanning settles it.
    Hold,
    /// It cannot proceed as written and replanning is the only way forward.
    Fail,
}

/// One operation's verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// Which operation of the plan this is.
    pub operation: usize,
    /// Whether it will run.
    pub grade: Grade,
    /// How thoroughly its subject was checked.
    pub rigour: Rigour,
    /// What stands in the way, for anything that is not a pass.
    pub impediment: Option<Impediment>,
}

impl Verdict {
    /// A verdict for an operation that checked out.
    #[must_use]
    pub fn passing(operation: usize, rigour: Rigour) -> Self {
        Self {
            operation,
            grade: Grade::Pass,
            rigour,
            impediment: None,
        }
    }

    /// A verdict for an operation held back, with what would settle it.
    #[must_use]
    pub fn held(operation: usize, rigour: Rigour, impediment: Impediment) -> Self {
        Self {
            operation,
            grade: Grade::Hold,
            rigour,
            impediment: Some(impediment),
        }
    }

    /// A verdict for an operation that cannot proceed at all.
    #[must_use]
    pub fn failed(operation: usize, rigour: Rigour, impediment: Impediment) -> Self {
        Self {
            operation,
            grade: Grade::Fail,
            rigour,
            impediment: Some(impediment),
        }
    }
}

/// What a preflight found, counted up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Standing {
    /// How many operations will run.
    pub passing: usize,
    /// How many are held back.
    pub held: usize,
    /// How many cannot proceed.
    pub failed: usize,
}

impl Standing {
    /// Whether every operation checked out.
    #[must_use]
    pub fn is_clear(self) -> bool {
        self.held == 0 && self.failed == 0
    }

    /// How many operations were graded at all.
    #[must_use]
    pub fn total(self) -> usize {
        self.passing + self.held + self.failed
    }
}

/// Counts up a set of verdicts.
#[must_use]
pub fn standing(verdicts: &[Verdict]) -> Standing {
    let mut standing = Standing::default();
    for verdict in verdicts {
        match verdict.grade {
            Grade::Pass => standing.passing += 1,
            Grade::Hold => standing.held += 1,
            Grade::Fail => standing.failed += 1,
        }
    }
    standing
}

/// The operations that will actually run, in plan order.
///
/// The only list execution is ever given. An operation that was not graded at
/// all does not appear here — the absence of a verdict is not a pass.
#[must_use]
pub fn passing(verdicts: &[Verdict]) -> Vec<usize> {
    let mut running: Vec<usize> = verdicts
        .iter()
        .filter(|verdict| verdict.grade == Grade::Pass)
        .map(|verdict| verdict.operation)
        .collect();
    running.sort_unstable();
    running
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdicts() -> Vec<Verdict> {
        vec![
            Verdict::passing(0, Rigour::Content),
            Verdict::held(1, Rigour::Content, Impediment::DestinationOccupied),
            Verdict::passing(2, Rigour::Content),
            Verdict::failed(3, Rigour::Metadata, Impediment::SourceMissing),
        ]
    }

    #[test]
    fn a_standing_counts_each_grade() {
        let counted = standing(&verdicts());
        assert_eq!(counted.passing, 2);
        assert_eq!(counted.held, 1);
        assert_eq!(counted.failed, 1);
        assert_eq!(counted.total(), 4);
        assert!(!counted.is_clear());
    }

    #[test]
    fn a_clear_standing_is_one_with_nothing_outstanding() {
        let clear = standing(&[
            Verdict::passing(0, Rigour::Content),
            Verdict::passing(1, Rigour::Content),
        ]);
        assert!(clear.is_clear());
        assert!(standing(&[]).is_clear());
    }

    #[test]
    fn only_passing_operations_are_handed_to_execution() {
        assert_eq!(passing(&verdicts()), vec![0, 2]);
    }

    #[test]
    fn an_operation_with_no_verdict_is_not_treated_as_passing() {
        // The absence of a verdict has to mean "not checked", never "fine". A
        // list built by removing failures rather than by collecting passes would
        // run everything nobody looked at.
        let partial = vec![Verdict::passing(5, Rigour::Content)];
        assert_eq!(
            passing(&partial),
            vec![5],
            "operations 0 to 4 were never graded and must not appear"
        );
    }

    #[test]
    fn a_hold_carries_what_stands_in_the_way() {
        // A hold the user cannot act on is a hold that becomes a shrug. Every
        // one of them names its impediment.
        for verdict in verdicts() {
            match verdict.grade {
                Grade::Pass => assert!(verdict.impediment.is_none()),
                Grade::Hold | Grade::Fail => assert!(
                    verdict.impediment.is_some(),
                    "a verdict that stops something must say what stopped it"
                ),
            }
        }
    }
}
