//! Everything the window can ask for.
//!
//! Each command is one stage of the pipeline, or one question about an artifact
//! a stage produced. None of them decides anything the pipeline does not: the
//! rules about what is a duplicate, what may be moved and what must be checked
//! first live in the crates, and this file only asks.
//!
//! The three that take time — scanning, analysing, carrying out — run off the
//! window's thread and report through events, so the interface stays answerable
//! while two million files are being walked.

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri resolves a command's arguments by type, and takes AppHandle \
              and State by value; a reference does not compile as a command"
)]

use std::path::{Path, PathBuf};

use scrub_core::plan::{Because, Keep, Operation};
use scrub_core::preflight::{Grade, Impediment, Rigour};
use scrub_run::{Depth, RunError};
use scrub_store::Analysis;
use serde::Serialize;
use tauri::{AppHandle, Runtime, State};

use crate::session::{self, Shared};
use crate::view;
use crate::watch::Reporting;

/// What a command hands back when it fails.
///
/// A string, because every one of them is written to be read by the person who
/// asked, and the window does nothing with it but show it.
type Answer<T> = Result<T, String>;

fn plainly<T>(outcome: Result<T, RunError>) -> Answer<T> {
    outcome.map_err(|error| error.message().to_owned())
}

/// Opens the session and says what this machine synchronises.
///
/// The first thing the window asks, and the only one that runs before anybody
/// clicks anything. It reads no file content and walks nothing: detection is a
/// handful of directory lookups, so the first screen is immediate.
///
/// # Errors
///
/// Returns a message if the workspace could not be prepared or the providers
/// could not be detected.
#[tauri::command]
pub fn begin<R: Runtime>(app: AppHandle<R>, state: State<'_, Shared>) -> Answer<Beginning> {
    let workspace = workspace_for(&app)?;
    let opened = plainly(session::Session::open(workspace))?;
    let home = plainly(scrub_run::home_directory())?;

    let map = scrub_platform::detect_cloud_map(&home)
        .map_err(|error| format!("could not detect what this machine synchronises: {error}"))?;

    let beginning = Beginning {
        home: view::show(&home),
        workspace: view::show(opened.workspace()),
        providers: view::Providers::of(&map),
        ready: [
            (session::INVENTORY, "scan"),
            (session::ANALYSIS, "analyze"),
            (session::PLAN, "plan"),
            (session::PREFLIGHT, "preflight"),
            (session::JOURNAL, "apply"),
        ]
        .into_iter()
        .filter(|(artifact, _)| opened.has(artifact))
        .map(|(_, stage)| stage)
        .collect(),
    };

    *state.0.lock().map_err(|_| poisoned())? = opened;
    Ok(beginning)
}

/// Where the window starts from.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Beginning {
    /// This account's home directory, offered as the thing to scan.
    pub home: String,
    /// Where artifacts are kept, so a person can go and look at them.
    pub workspace: String,
    /// What this machine synchronises, and what it does not.
    pub providers: view::Providers,
    /// Which stages already have an artifact here, in pipeline order.
    ///
    /// A list rather than a flag each, because the window's question is "how far
    /// did I get", and a list answers it directly. The names are the stages:
    /// `scan`, `analyze`, `plan`, `preflight`, `apply`.
    pub ready: Vec<&'static str>,
}

/// Records what is on this machine, opening and downloading nothing.
///
/// # Errors
///
/// Returns a message if the scan could not start or its result could not be
/// written. Places that could not be read are part of the answer, not an error.
#[tauri::command(async)]
pub fn scan<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, Shared>,
    roots: Vec<String>,
) -> Answer<view::Inventory> {
    let (out, machine) = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        (
            session.artifact(session::INVENTORY),
            plainly(session.machine())?,
        )
    };

    let roots: Vec<PathBuf> = roots.into_iter().map(PathBuf::from).collect();
    let mut watcher = Reporting::new(app);
    let inventory = plainly(scrub_run::scan(&roots, machine, &mut watcher))?;

    // Replacing is right here and nowhere else: the window has one current
    // inventory, and scanning again is a person asking for a fresh one. Every
    // artifact that records a change to somebody's files is refused instead.
    plainly(
        inventory
            .write(&out, scrub_store::Replace::Yes)
            .map_err(RunError::from),
    )?;

    // A new scan makes everything downstream of it stale. Removing them is what
    // stops the window offering a plan built from an inventory that no longer
    // describes this machine (DR-18).
    invalidate_after(
        &out.with_file_name(session::ANALYSIS),
        &[session::ANALYSIS, session::PLAN, session::PREFLIGHT],
    );

    Ok(view::Inventory::of(&inventory.body.outcome))
}

/// Works out what is the same file as what.
///
/// # Errors
///
/// Returns a message if there is nothing to analyse, or if the analysis could
/// not be written.
#[tauri::command(async)]
pub fn analyze<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, Shared>,
    thorough: bool,
) -> Answer<view::Findings> {
    let (inventory, out, machine) = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        (
            plainly(session.require(session::INVENTORY, "scan this machine"))?,
            session.artifact(session::ANALYSIS),
            plainly(session.machine())?,
        )
    };

    let depth = if thorough {
        Depth::Thorough
    } else {
        Depth::Duplicates
    };
    let mut watcher = Reporting::new(app);
    let analysis = plainly(scrub_run::analyze(&inventory, machine, depth, &mut watcher))?;
    plainly(
        analysis
            .write(&out, scrub_store::Replace::Yes)
            .map_err(RunError::from),
    )?;

    invalidate_after(&out, &[session::PLAN, session::PREFLIGHT]);
    Ok(findings_of(&analysis))
}

/// The duplicate groups, largest saving first, as one row each (DR-21).
///
/// # Errors
///
/// Returns a message if there is nothing analysed yet.
#[tauri::command]
pub fn groups(
    state: State<'_, Shared>,
    offset: usize,
    limit: usize,
) -> Answer<Vec<view::GroupRow>> {
    let path = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        plainly(session.require(session::ANALYSIS, "look for duplicates"))?
    };
    let analysis = read_analysis(&path)?;

    let mut rows: Vec<view::GroupRow> = analysis
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| view::GroupRow {
            index,
            name: group
                .objects
                .first()
                .and_then(|object| object.names.first())
                .and_then(|entry| analysis.body.outcome.entries.get(*entry))
                .and_then(|entry| entry.path.file_name())
                .map_or_else(
                    || "(unnamed)".to_owned(),
                    |name| name.to_string_lossy().into_owned(),
                ),
            copies: group.objects.len(),
            size: group.logical_size,
            reclaimable: group.reclaimable_bytes(),
            proven: view::is_proven(group.certainty),
        })
        .collect();

    // Largest saving first, because that is the order somebody would work in,
    // and a stable tie-break so paging through does not shuffle rows about.
    rows.sort_by(|left, right| {
        right
            .reclaimable
            .cmp(&left.reclaimable)
            .then(left.index.cmp(&right.index))
    });

    Ok(rows.into_iter().skip(offset).take(limit).collect())
}

/// The copies inside one group, fetched only when somebody opens it.
///
/// # Errors
///
/// Returns a message if there is nothing analysed yet, or if that group is not
/// in the analysis.
#[tauri::command]
pub fn copies(state: State<'_, Shared>, group: usize) -> Answer<Vec<view::Copy>> {
    let path = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        plainly(session.require(session::ANALYSIS, "look for duplicates"))?
    };
    let analysis = read_analysis(&path)?;

    let found = analysis
        .groups
        .get(group)
        .ok_or_else(|| format!("there is no group {group} in this analysis"))?;

    let mut copies = Vec::new();
    for object in &found.objects {
        // The first name is the copy; any further name is the same bytes
        // reached by another path, which frees nothing if removed. Saying so
        // is the difference between a true saving and a wrong one.
        for (position, index) in object.names.iter().enumerate() {
            let Some(entry) = analysis.body.outcome.entries.get(*index) else {
                continue;
            };
            copies.push(view::Copy {
                path: view::show(&entry.path),
                modified: entry.modified.map(jiff::Timestamp::as_second),
                created: entry.created.map(jiff::Timestamp::as_second),
                local: !entry.cloud.residency.read_may_download(),
                same_file: position > 0,
            });
        }
    }
    Ok(copies)
}

/// Decides what should happen, without anything happening.
///
/// # Errors
///
/// Returns a message if there is nothing analysed yet, or if the plan could not
/// be written.
#[tauri::command]
pub fn plan(
    state: State<'_, Shared>,
    keep: String,
    prefer: Option<String>,
) -> Answer<Vec<view::Step>> {
    // Settled before anything is looked up: a rule nobody offers is a fault in
    // the caller, and answering with "nothing has been analysed" would hide it.
    let rule = match prefer {
        Some(path) => Keep::Under(PathBuf::from(path)),
        None => match keep.as_str() {
            "newest" => Keep::Newest,
            "shallowest" => Keep::Shallowest,
            "oldest" => Keep::Oldest,
            other => {
                return Err(format!(
                    "'{other}' is not a rule for choosing which copy to keep; \
                     the rules are oldest, newest and shallowest"
                ));
            }
        },
    };

    let (analysis, out, machine) = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        (
            plainly(session.require(session::ANALYSIS, "look for duplicates"))?,
            session.artifact(session::PLAN),
            plainly(session.machine())?,
        )
    };

    let drafted = plainly(scrub_run::plan(&analysis, &rule, machine))?;
    plainly(
        drafted
            .write(&out, scrub_store::Replace::Yes)
            .map_err(RunError::from),
    )?;

    invalidate_after(&out, &[session::PREFLIGHT]);
    Ok(steps_of(
        &drafted.operations,
        &drafted.body.outcome.entries,
        &[],
    ))
}

/// Checks the plan against the disk, changing nothing.
///
/// # Errors
///
/// Returns a message if there is no plan yet, or if the check could not be
/// written.
#[tauri::command(async)]
pub fn preflight(state: State<'_, Shared>, fast: bool) -> Answer<Vec<view::Step>> {
    let (plan, out, machine) = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        (
            plainly(session.require(session::PLAN, "decide what should happen"))?,
            session.artifact(session::PREFLIGHT),
            plainly(session.machine())?,
        )
    };

    let rigour = if fast {
        Rigour::Metadata
    } else {
        Rigour::Content
    };
    let checked = plainly(scrub_run::preflight(&plan, rigour, machine))?;
    plainly(
        checked
            .write(&out, scrub_store::Replace::Yes)
            .map_err(RunError::from),
    )?;

    Ok(steps_of(
        &checked.operations,
        &checked.body.outcome.entries,
        &checked.verdicts,
    ))
}

/// Carries out what preflight passed.
///
/// The only command in this file that changes anything, and it is reachable
/// only from a screen that has already shown, item by item, what it will do.
/// Nothing is deleted: what it moves goes to a quarantine directory it names in
/// its answer, and the record it writes is what puts everything back (DR-5).
///
/// # Errors
///
/// Returns a message if there is no checked plan, if nothing in it passed, or if
/// the run could not be recorded.
#[tauri::command(async)]
pub fn apply<R: Runtime>(app: AppHandle<R>, state: State<'_, Shared>) -> Answer<Outcome> {
    let (preflight, out, machine) = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        (
            plainly(session.require(session::PREFLIGHT, "check the plan"))?,
            session.artifact(session::JOURNAL),
            plainly(session.machine())?,
        )
    };

    let mut watcher = Reporting::new(app);
    let run = plainly(scrub_run::apply(
        &preflight,
        &out,
        true,
        machine,
        &mut watcher,
    ))?;
    Ok(outcome_of(&run))
}

/// Puts everything the last run moved back where it was.
///
/// # Errors
///
/// Returns a message if there is no run to reverse, or if it changed nothing.
#[tauri::command(async)]
pub fn undo<R: Runtime>(app: AppHandle<R>, state: State<'_, Shared>) -> Answer<Outcome> {
    let (journal, out, machine) = {
        let session = state.0.lock().map_err(|_| poisoned())?;
        (
            plainly(session.require(session::JOURNAL, "carry out a plan"))?,
            session.artifact(session::REVERSAL),
            plainly(session.machine())?,
        )
    };

    let mut watcher = Reporting::new(app);
    let run = plainly(scrub_run::undo(&journal, &out, true, machine, &mut watcher))?;
    Ok(outcome_of(&run))
}

/// What a run came to.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    /// How many changes were made.
    pub done: usize,
    /// How many were left alone because something had changed since the check.
    pub skipped: usize,
    /// How many were attempted and did not succeed.
    pub failed: usize,
    /// How many were written down but never resolved — a run that stopped.
    pub unresolved: usize,
    /// How much space was freed.
    pub freed: u64,
    /// Where the files it moved are waiting, for a run that moved any.
    pub quarantine: Option<String>,
    /// Whether the run being reversed had itself stopped part-way.
    pub source_was_unfinished: bool,
}

fn outcome_of(run: &scrub_run::Run) -> Outcome {
    let entries = &run.journal.body.outcome.entries;
    let tally = scrub_core::journal::tally(&run.journal.steps, |step| {
        run.journal
            .operations
            .get(step.operation)
            .map_or(0, |operation| operation.frees(entries))
    });

    Outcome {
        done: tally.done,
        skipped: tally.skipped,
        failed: tally.failed,
        unresolved: tally.unresolved,
        freed: tally.freed,
        quarantine: run.quarantine.as_deref().map(view::show),
        source_was_unfinished: run.source_was_unfinished,
    }
}

fn findings_of(analysis: &Analysis) -> view::Findings {
    let mut findings = view::Findings::default();
    for group in &analysis.groups {
        if view::is_proven(group.certainty) {
            findings.proven += 1;
            findings.redundant += group.objects.len().saturating_sub(1);
            findings.reclaimable += group.reclaimable_bytes();
        } else {
            findings.unchecked += 1;
            findings.to_settle += group.bytes_to_settle();
        }
    }
    findings
}

fn steps_of(
    operations: &[Operation],
    entries: &[scrub_core::inventory::Entry],
    verdicts: &[scrub_core::preflight::Verdict],
) -> Vec<view::Step> {
    operations
        .iter()
        .enumerate()
        .map(|(index, operation)| view::Step {
            index,
            kind: match operation {
                Operation::CreateDirectory { .. } => "createDirectory",
                Operation::Move { .. } => "move",
                Operation::Quarantine { .. } => "quarantine",
            }
            .to_owned(),
            subject: operation
                .subject()
                .map_or_else(String::new, |subject| view::show(&subject.path)),
            destination: operation.destination().map(view::show),
            frees: operation.frees(entries),
            because: match operation {
                Operation::CreateDirectory { .. } => "somewhere has to exist first".to_owned(),
                Operation::Move { .. } => "you asked for it to go there".to_owned(),
                Operation::Quarantine { because, .. } => match because {
                    Because::RedundantCopy { kept, .. } => format!(
                        "exactly these bytes are also at {}, and that copy is being kept",
                        kept.display()
                    ),
                    Because::Requested => "you asked for it".to_owned(),
                },
            },
            verdict: verdicts
                .iter()
                .find(|verdict| verdict.operation == index)
                .map(|verdict| view::StepVerdict {
                    grade: match verdict.grade {
                        Grade::Pass => "pass",
                        Grade::Hold => "hold",
                        Grade::Fail => "fail",
                    }
                    .to_owned(),
                    impediment: verdict.impediment.as_ref().map(explain),
                }),
        })
        .collect()
}

/// Says what stands in the way in words somebody can act on.
fn explain(impediment: &Impediment) -> String {
    match impediment {
        Impediment::SourceMissing => "it is not there any more".to_owned(),
        Impediment::SourceChanged { .. } => {
            "it is not the same file it was when the plan was made".to_owned()
        }
        Impediment::DestinationOccupied => "something is already where it would go".to_owned(),
        Impediment::DestinationUnreachable => {
            "the folder it would go into does not exist".to_owned()
        }
        Impediment::PermissionDenied => "this account is not allowed to move it".to_owned(),
        Impediment::ContentNotPresent => {
            "its content is in the cloud, so the sync client has to move it, not us".to_owned()
        }
        Impediment::Other(reason) => reason.clone(),
    }
}

/// Removes artifacts that the stage just written has made stale.
///
/// Best effort on purpose: a file that could not be removed is not a reason to
/// fail a scan somebody waited two minutes for. What matters is that the chain
/// is verified when it is read, so a stale artifact is refused rather than
/// silently used (DR-18).
fn invalidate_after(beside: &Path, names: &[&str]) {
    for name in names {
        // DR-11-EXEMPT: the tool's own artifacts in its own workspace, never a
        // path a scan discovered.
        let _ = std::fs::remove_file(beside.with_file_name(name));
    }
}

fn read_analysis(path: &Path) -> Answer<Analysis> {
    Analysis::read(path).map_err(|error| format!("could not read the analysis: {error}"))
}

fn poisoned() -> String {
    "something went wrong earlier in this session; close the window and open it again".to_owned()
}

/// The environment variable that moves the workspace somewhere else.
///
/// Offered because artifacts of a large machine run to a gigabyte, and the
/// place a platform picks for application data is not always the disk somebody
/// wants that on. It is also what lets the tests run against a directory of
/// their own instead of the one a real installation uses.
pub const WORKSPACE_VARIABLE: &str = "SCRUB_WORKSPACE";

/// Where this platform says an application of this name may keep its data.
fn workspace_for<R: Runtime>(app: &AppHandle<R>) -> Answer<PathBuf> {
    use tauri::Manager as _;

    if let Some(chosen) = std::env::var_os(WORKSPACE_VARIABLE) {
        return Ok(PathBuf::from(chosen));
    }

    app.path()
        .app_data_dir()
        .map(|base| base.join("workspace"))
        .map_err(|error| format!("this platform did not say where to keep data: {error}"))
}
