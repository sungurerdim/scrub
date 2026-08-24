//! The stages that decide, and the one that compares.
//!
//! None of them touches a file. Planning reads an analysis and writes down what
//! should happen; preflight reads the plan and grades it against the disk
//! without changing anything (DR-19); merging puts several machines' analyses
//! side by side and produces something that can be read anywhere and executed
//! nowhere.

use std::path::{Path, PathBuf};

use scrub_core::artifact::{Digest, MachineId, MachineScope, Stage};
use scrub_core::edit::{Arrangement, Edit};
use scrub_core::merge::Merged;
use scrub_core::plan::Keep;
use scrub_core::preflight::Rigour;
use scrub_store::{Analysis, Body, Plan, Preflight};

use crate::{RunError, could_not_read, executable_here, header_for, pending};

/// Decides what should happen, without anything happening.
///
/// Two things become operations: the rule for which copy of a duplicate to
/// keep, and whatever somebody rearranged by hand. They are kept apart until
/// here on purpose — a person who changes the rule should not lose the folder
/// they made, and a person who takes back a move should not have every
/// duplicate re-decided.
///
/// # Errors
///
/// Returns a message if the analysis could not be read, or if it is a
/// comparison of several machines — which describes no single machine, and so
/// cannot be carried out on one (DR-18).
pub fn plan(
    analysis_path: &Path,
    keep: &Keep,
    edits: &[Edit],
    machine: MachineId,
) -> Result<Plan, RunError> {
    let analysis =
        Analysis::read(analysis_path).map_err(|error| could_not_read(analysis_path, error))?;

    if matches!(analysis.header.machine, MachineScope::Merged { .. }) {
        return Err(RunError::new(
            "this is a comparison of several machines, and a plan has to be about one. \
             Plan from each machine's own analysis instead.",
        ));
    }

    // Scoped so the arrangement, which borrows the entries, is finished with
    // before the body is handed to the artifact.
    let (requested, asked) = {
        let arrangement = Arrangement::replaying(&analysis.body.outcome.entries, edits);
        (
            arrangement.operations(&analysis.settled),
            arrangement.asked().to_vec(),
        )
    };

    let by_rule = scrub_core::plan::resolve_duplicates(
        &analysis.body.outcome.entries,
        &analysis.groups,
        keep,
    );
    let operations = scrub_core::plan::ordered(scrub_core::plan::combine(by_rule, requested));

    let parent = analysis.header.content_digest;
    let mut drafted = Plan {
        header: header_for(
            Stage::Plan,
            vec![parent],
            machine,
            analysis.header.scope_digest,
            pending(),
        ),
        body: analysis.body,
        operations,
        edits: asked,
    };
    // Carried across rather than rebuilt: the plan is about the machine the
    // analysis described, whichever machine happens to be drafting it.
    drafted.header.machine = analysis.header.machine;
    drafted.header.content_digest = drafted.content_digest();
    Ok(drafted)
}

/// Checks a plan against the disk, changing nothing.
///
/// # Errors
///
/// Returns a message if the read-only mode could not be entered, if the plan
/// could not be read, or if it was made for another machine — where the same
/// paths mean something else.
pub fn preflight(
    plan_path: &Path,
    rigour: Rigour,
    machine: MachineId,
) -> Result<Preflight, RunError> {
    // Checking reads content, so the guard every reading stage starts under
    // applies here too (DR-11).
    let mode = scrub_platform::enter_read_only_scan_mode()
        .map_err(|error| RunError::new(error.to_string()))?;

    let drafted = Plan::read(plan_path).map_err(|error| could_not_read(plan_path, error))?;

    // A plan made for another machine names paths that mean something else here
    // (DR-18).
    executable_here(&drafted.header, machine)?;

    let home = crate::home_directory()?;
    let map = scrub_platform::detect_cloud_map(&home)
        .map_err(|error| RunError::new(error.to_string()))?;

    let verdicts = scrub_platform::verify::verify(
        &drafted.operations,
        &drafted.body.outcome.entries,
        &map,
        rigour,
        &mode,
    );

    let parent = drafted.header.content_digest;
    let mut checked = Preflight {
        header: header_for(
            Stage::Preflight,
            vec![parent],
            machine,
            drafted.header.scope_digest,
            pending(),
        ),
        body: drafted.body,
        operations: drafted.operations,
        verdicts,
    };
    checked.header.machine = drafted.header.machine;
    checked.header.content_digest = checked.content_digest();
    Ok(checked)
}

/// Compares two or more machines' analyses side by side.
///
/// Returns the combined artifact and the reconciliation behind it, because a
/// caller reporting the comparison needs to name the sources.
///
/// # Errors
///
/// Returns a message if fewer than two analyses were given, if one could not be
/// read, or if one of them is itself a comparison — merging those would count a
/// machine twice.
pub fn merge(analyses: &[PathBuf], machine: MachineId) -> Result<(Analysis, Merged), RunError> {
    if analyses.len() < 2 {
        return Err(RunError::new(
            "merging needs at least two analyses; combining one with nothing would \
             produce a second artifact claiming to be a comparison",
        ));
    }

    let mut inputs = Vec::with_capacity(analyses.len());
    let mut parents = Vec::with_capacity(analyses.len());
    let mut encoding = None;

    for path in analyses {
        let analysis = Analysis::read(path).map_err(|error| could_not_read(path, error))?;
        parents.push(analysis.header.content_digest);
        encoding.get_or_insert(analysis.body.path_encoding);

        inputs.push(scrub_core::merge::Input {
            label: label_for(path),
            machine: match analysis.header.machine {
                MachineScope::Single { machine } => machine,
                MachineScope::Merged { .. } => {
                    return Err(RunError::new(format!(
                        "{} is itself a comparison; merge the original analyses instead, \
                         so every machine is counted once",
                        path.display()
                    )));
                }
            },
            roots: analysis.body.detection.roots,
            links: analysis.body.detection.links,
            outcome: analysis.body.outcome,
            settled: analysis.settled,
        });
    }

    let merged = scrub_core::merge::merge(inputs);
    let settled: std::collections::HashMap<_, _> = merged.settled.clone().into_iter().collect();
    let groups = scrub_core::analysis::group_duplicates(&merged.outcome.entries, &settled);

    let body = Body {
        path_encoding: encoding.unwrap_or(scrub_core::paths::LOCAL),
        detection: scrub_core::cloud::Detection {
            roots: merged.roots.clone(),
            links: merged.links.clone(),
        },
        outcome: merged.outcome.clone(),
    };

    let mut header = header_for(
        Stage::Merge,
        parents,
        machine,
        Digest::of(b"combined"),
        pending(),
    );
    // A comparison describes several machines, so it can be read anywhere and
    // executed nowhere (DR-18).
    header.machine = MachineScope::Merged {
        machines: merged.sources.iter().map(|source| source.machine).collect(),
    };

    let mut analysis = Analysis {
        header,
        body,
        groups,
        settled: merged.settled.clone(),
    };
    analysis.header.content_digest = analysis.content_digest();
    Ok((analysis, merged))
}

/// What to call a machine in the comparison.
///
/// Taken from the artifact's file name, because a machine identity is a random
/// value that means nothing to anyone reading a report, and asking for a label
/// every time would be a question with an obvious answer.
fn label_for(path: &Path) -> String {
    path.file_stem().map_or_else(
        || path.display().to_string(),
        |stem| stem.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comparison_is_named_after_the_file_it_came_from() {
        assert_eq!(label_for(Path::new("/tmp/laptop.analysis")), "laptop");
        assert_eq!(label_for(Path::new("desktop.analysis")), "desktop");
    }

    #[test]
    fn merging_fewer_than_two_analyses_is_refused() {
        let refusal = merge(&[PathBuf::from("one.analysis")], MachineId::generate())
            .expect_err("one is not a comparison");
        assert!(refusal.message().contains("at least two"), "{refusal}");
    }
}
