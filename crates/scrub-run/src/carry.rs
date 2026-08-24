//! The two stages that change things, and the only ones that do.
//!
//! Both write their record as they go: the intent first, the outcome after
//! (DR-7). A run killed between those two lines leaves a step marked as intended
//! rather than no record at all, which is the difference between a state that
//! can be reconciled by looking and one that can only be guessed at.
//!
//! Because the record is opened before the first change and appended to
//! throughout, these are the only stages that need to know where their artifact
//! goes. Every other stage hands its result back unwritten.

use std::path::{Path, PathBuf};

use scrub_core::artifact::{MachineId, Stage};
use scrub_core::journal::{Progress, Step};
use scrub_store::{Journal, Preflight};

use crate::{RunError, Watch, could_not_read, executable_here, header_for, pending, replacement};

/// What a run came to, and where the files it moved are waiting.
#[derive(Debug)]
pub struct Run {
    /// The record of the run, read back from what was written.
    pub journal: Journal,
    /// Where files were put, for a run that quarantined any.
    ///
    /// Nothing is ever deleted, so anything a run removed from its place is in
    /// here, under the path it had before (DR-5).
    pub quarantine: Option<PathBuf>,
    /// Whether the run being reversed had itself stopped part-way.
    pub source_was_unfinished: bool,
}

/// Carries out the operations a preflight passed.
///
/// # Errors
///
/// Returns a message if the read-only mode could not be entered, if the
/// preflight could not be read, if it was checked on another machine, if nothing
/// passed it, or if the quarantine directory could not be prepared.
pub fn apply(
    preflight_path: &Path,
    out: &Path,
    replace: bool,
    machine: MachineId,
    watch: &mut dyn Watch,
) -> Result<Run, RunError> {
    // Reading content is part of the last check before each move, so the guard
    // every other stage starts under applies here too (DR-11).
    let mode = scrub_platform::enter_read_only_scan_mode()
        .map_err(|error| RunError::new(error.to_string()))?;

    let checked =
        Preflight::read(preflight_path).map_err(|error| could_not_read(preflight_path, error))?;
    executable_here(&checked.header, machine)?;

    let running = checked.passing();
    if running.is_empty() {
        return Err(RunError::new(
            "nothing passed preflight, so there is nothing to carry out. \
             Re-plan to settle what was held back.",
        ));
    }

    let quarantine =
        scrub_platform::execute::Quarantine::at(scrub_platform::verify::quarantine_beside(out))
            .map_err(|error| {
                RunError::new(format!(
                    "could not prepare the quarantine directory: {error}"
                ))
            })?;

    let home = crate::home_directory()?;
    let map = scrub_platform::detect_cloud_map(&home)
        .map_err(|error| RunError::new(error.to_string()))?;

    let header = header_for(
        Stage::Apply,
        vec![checked.header.content_digest],
        machine,
        checked.header.scope_digest,
        pending(),
    );

    // Opened before anything is done, so a run that is killed halfway through
    // leaves a record of where it got to (DR-7).
    let connection = Journal::begin(
        out,
        &header,
        &checked.body,
        &checked.operations,
        replacement(replace),
    )
    .map_err(|error| RunError::new(error.to_string()))?;

    let total = running.len();
    let mut steps = Vec::with_capacity(total);
    for (sequence, index) in running.iter().enumerate() {
        let Some(operation) = checked.operations.get(*index) else {
            continue;
        };

        // Written down before it is attempted. A crash between these two lines
        // leaves a step marked as intended, which a later run can settle by
        // looking rather than by guessing.
        let intended = Step {
            operation: *index,
            progress: Progress::Intended,
            from: operation
                .subject()
                .map_or_else(PathBuf::new, |subject| subject.path.clone()),
            to: None,
            content: operation.subject().and_then(|subject| subject.content),
            at: jiff::Timestamp::now(),
        };
        Journal::record(&connection, sequence, &intended)
            .map_err(|error| RunError::new(error.to_string()))?;

        let step = scrub_platform::execute::perform(*index, operation, &quarantine, &map, &mode);
        Journal::record(&connection, sequence, &step)
            .map_err(|error| RunError::new(error.to_string()))?;
        steps.push(step);
        watch.operating(sequence + 1, total);
    }

    let digest = scrub_store::journal_digest(&checked.body, &checked.operations, &steps);
    Journal::finish(&connection, digest).map_err(|error| RunError::new(error.to_string()))?;
    drop(connection);

    Ok(Run {
        journal: Journal::read(out).map_err(|error| RunError::new(error.to_string()))?,
        quarantine: Some(quarantine.root().to_path_buf()),
        source_was_unfinished: false,
    })
}

/// Puts everything a run moved back where it was.
///
/// # Errors
///
/// Returns a message if the read-only mode could not be entered, if the record
/// could not be read, if it was made on another machine, or if the run it
/// describes changed nothing.
pub fn undo(
    journal_path: &Path,
    out: &Path,
    replace: bool,
    machine: MachineId,
    watch: &mut dyn Watch,
) -> Result<Run, RunError> {
    let mode = scrub_platform::enter_read_only_scan_mode()
        .map_err(|error| RunError::new(error.to_string()))?;

    let done = Journal::read(journal_path).map_err(|error| could_not_read(journal_path, error))?;
    executable_here(&done.header, machine)?;

    let order = scrub_core::journal::reversal_order(&done.steps);
    if order.is_empty() {
        return Err(RunError::new(
            "this run changed nothing, so there is nothing to put back",
        ));
    }

    let home = crate::home_directory()?;
    let map = scrub_platform::detect_cloud_map(&home)
        .map_err(|error| RunError::new(error.to_string()))?;

    let header = header_for(
        Stage::Undo,
        vec![done.header.content_digest],
        machine,
        done.header.scope_digest,
        pending(),
    );
    let connection = Journal::begin(
        out,
        &header,
        &done.body,
        &done.operations,
        replacement(replace),
    )
    .map_err(|error| RunError::new(error.to_string()))?;

    let total = order.len();
    let mut steps = Vec::with_capacity(total);
    for (sequence, index) in order.iter().enumerate() {
        let step = scrub_platform::execute::reverse(*index, &done.steps[*index], &map, &mode);
        Journal::record(&connection, sequence, &step)
            .map_err(|error| RunError::new(error.to_string()))?;
        steps.push(step);
        watch.operating(sequence + 1, total);
    }

    let digest = scrub_store::journal_digest(&done.body, &done.operations, &steps);
    Journal::finish(&connection, digest).map_err(|error| RunError::new(error.to_string()))?;
    drop(connection);

    Ok(Run {
        journal: Journal::read(out).map_err(|error| RunError::new(error.to_string()))?,
        quarantine: None,
        source_was_unfinished: !done.finished,
    })
}
