//! The command line: every stage of the pipeline as a command.
//!
//! Not a second product surface. It exists so each stage can be driven and
//! checked by machine, and so the artifacts are usable by anyone who would
//! rather script than click. The graphical interface runs the same crates.

#![forbid(unsafe_code)]

mod report;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use scrub_core::artifact::Stage;
use scrub_run::machine;
use scrub_store::Inventory;

/// See every file you own, across every cloud, and reorganize it without ever
/// losing one.
#[derive(Parser)]
#[command(name = "scrub", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Record what is on this machine, without opening or downloading anything.
    Scan {
        /// What to scan. Defaults to your home directory.
        paths: Vec<PathBuf>,
        /// Where to write the inventory.
        #[arg(short, long, default_value = "scan.inventory")]
        out: PathBuf,
        /// Do not print progress while scanning.
        #[arg(long)]
        quiet: bool,
        /// Write over an artifact already at that path.
        #[arg(long)]
        replace: bool,
    },
    /// Work out what is the same file as what, reading only what is already here.
    Analyze {
        /// The inventory to analyse.
        inventory: PathBuf,
        /// Where to write the analysis.
        #[arg(short, long, default_value = "scan.analysis")]
        out: PathBuf,
        /// Do not print progress while reading.
        #[arg(long)]
        quiet: bool,
        /// Write over an artifact already at that path.
        #[arg(long)]
        replace: bool,
        /// Read every file, not only those that could be local duplicates.
        ///
        /// Needed before comparing this machine with another: a file whose size
        /// nothing here shares is never read otherwise, and without a
        /// fingerprint it cannot be recognised on the other machine.
        #[arg(long)]
        thorough: bool,
    },
    /// Decide what should happen, without anything happening.
    Plan {
        /// The analysis to plan from.
        analysis: PathBuf,
        /// Which copy of a duplicated file to keep.
        #[arg(long, value_enum, default_value_t = KeepRule::Oldest)]
        keep: KeepRule,
        /// Prefer copies under this path, whatever the rule says.
        #[arg(long)]
        prefer: Option<PathBuf>,
        /// Where to write the plan.
        #[arg(short, long, default_value = "scan.plan")]
        out: PathBuf,
        /// Write over an artifact already at that path.
        #[arg(long)]
        replace: bool,
    },
    /// Check a plan against the disk, changing nothing.
    Preflight {
        /// The plan to check.
        plan: PathBuf,
        /// Where to write the result.
        #[arg(short, long, default_value = "scan.preflight")]
        out: PathBuf,
        /// Compare sizes and timestamps instead of reading content again.
        ///
        /// Much faster, and enough to catch anything an ordinary edit would do.
        /// It cannot catch a file swapped for another of the same size with its
        /// timestamp preserved.
        #[arg(long)]
        fast: bool,
        /// Write over an artifact already at that path.
        #[arg(long)]
        replace: bool,
    },
    /// Carry out the operations a preflight passed.
    Apply {
        /// The preflight to carry out.
        preflight: PathBuf,
        /// Where to write the record of the run.
        #[arg(short, long, default_value = "scan.journal")]
        out: PathBuf,
        /// Write over an artifact already at that path.
        #[arg(long)]
        replace: bool,
    },
    /// Put everything a run moved back where it was.
    Undo {
        /// The record of the run to reverse.
        journal: PathBuf,
        /// Where to write the record of the reversal.
        #[arg(short, long, default_value = "undo.journal")]
        out: PathBuf,
        /// Write over an artifact already at that path.
        #[arg(long)]
        replace: bool,
    },
    /// Compare two or more machines' analyses side by side.
    Merge {
        /// The analyses to combine. Each file's name becomes its label.
        analyses: Vec<PathBuf>,
        /// Where to write the combined view.
        #[arg(short, long, default_value = "combined.analysis")]
        out: PathBuf,
        /// Write over an artifact already at that path.
        #[arg(long)]
        replace: bool,
    },
    /// Summarise an artifact.
    Inspect {
        /// The artifact to read.
        artifact: PathBuf,
    },
    /// Write an artifact's content as newline-delimited JSON.
    Export {
        /// The artifact to read.
        artifact: PathBuf,
        /// Where to write. Defaults to standard output.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Scan {
            paths,
            out,
            quiet,
            replace,
        } => scan(&paths, &out, quiet, replace),
        Command::Analyze {
            inventory,
            out,
            quiet,
            replace,
            thorough,
        } => analyze(&inventory, &out, quiet, replace, thorough),
        Command::Plan {
            analysis,
            keep,
            prefer,
            out,
            replace,
        } => plan(&analysis, keep, prefer, &out, replace),
        Command::Preflight {
            plan,
            out,
            fast,
            replace,
        } => preflight(&plan, &out, fast, replace),
        Command::Apply {
            preflight,
            out,
            replace,
        } => apply(&preflight, &out, replace),
        Command::Undo {
            journal,
            out,
            replace,
        } => undo(&journal, &out, replace),
        Command::Merge {
            analyses,
            out,
            replace,
        } => merge(&analyses, &out, replace),
        Command::Inspect { artifact } => inspect(&artifact),
        Command::Export { artifact, out } => export(&artifact, out.as_deref()),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("scrub: {message}");
            ExitCode::FAILURE
        }
    }
}

fn scan(
    paths: &[PathBuf],
    out: &Path,
    quiet: bool,
    replace: bool,
) -> Result<(), scrub_run::RunError> {
    scrub_run::check_output_is_free(out, replace)?;

    // Detected once here purely so the providers can be named before a scan of
    // two million files begins; the scan detects them again for itself.
    let home = scrub_run::home_directory()?;
    if let Ok(map) = scrub_platform::detect_cloud_map(&home) {
        report::describe_providers(&map);
    }

    let mut watcher = report::Terminal::new(quiet);
    let inventory = scrub_run::scan(paths, machine::identity()?, &mut watcher)?;
    inventory.write(out, scrub_run::replacement(replace))?;

    report::describe_body(&inventory.body, Some(out));
    Ok(())
}

fn analyze(
    inventory: &Path,
    out: &Path,
    quiet: bool,
    replace: bool,
    thorough: bool,
) -> Result<(), scrub_run::RunError> {
    scrub_run::check_output_is_free(out, replace)?;

    let depth = if thorough {
        scrub_run::Depth::Thorough
    } else {
        scrub_run::Depth::Duplicates
    };
    let mut watcher = report::Terminal::new(quiet);
    let analysis = scrub_run::analyze(inventory, machine::identity()?, depth, &mut watcher)?;
    analysis.write(out, scrub_run::replacement(replace))?;

    report::describe_groups(&analysis, Some(out));
    Ok(())
}

fn plan(
    analysis: &Path,
    keep: KeepRule,
    prefer: Option<PathBuf>,
    out: &Path,
    replace: bool,
) -> Result<(), scrub_run::RunError> {
    scrub_run::check_output_is_free(out, replace)?;

    let rule = match prefer {
        Some(path) => scrub_core::plan::Keep::Under(path),
        None => match keep {
            KeepRule::Oldest => scrub_core::plan::Keep::Oldest,
            KeepRule::Newest => scrub_core::plan::Keep::Newest,
            KeepRule::Shallowest => scrub_core::plan::Keep::Shallowest,
        },
    };

    // The command line drafts from the rule alone. Rearranging by hand is
    // what the window is for, and a plan it wrote keeps those changes.
    let drafted = scrub_run::plan(analysis, &rule, &[], machine::identity()?)?;
    drafted.write(out, scrub_run::replacement(replace))?;

    report::describe_plan(&drafted, &rule, Some(out));
    Ok(())
}

fn preflight(
    plan: &Path,
    out: &Path,
    fast: bool,
    replace: bool,
) -> Result<(), scrub_run::RunError> {
    scrub_run::check_output_is_free(out, replace)?;

    let rigour = if fast {
        scrub_core::preflight::Rigour::Metadata
    } else {
        scrub_core::preflight::Rigour::Content
    };

    let checked = scrub_run::preflight(plan, rigour, machine::identity()?)?;
    checked.write(out, scrub_run::replacement(replace))?;

    report::describe_preflight(&checked, Some(out));
    Ok(())
}

fn apply(preflight: &Path, out: &Path, replace: bool) -> Result<(), scrub_run::RunError> {
    scrub_run::check_output_is_free(out, replace)?;

    let mut watcher = report::Terminal::new(false);
    let run = scrub_run::apply(preflight, out, replace, machine::identity()?, &mut watcher)?;

    report::describe_run(&run.journal, out, run.quarantine.as_deref());
    Ok(())
}

fn undo(journal: &Path, out: &Path, replace: bool) -> Result<(), scrub_run::RunError> {
    scrub_run::check_output_is_free(out, replace)?;

    let mut watcher = report::Terminal::new(false);
    let run = scrub_run::undo(journal, out, replace, machine::identity()?, &mut watcher)?;
    if run.source_was_unfinished {
        println!("This run did not reach its end. Reversing what it did get to.");
    }

    report::describe_run(&run.journal, out, None);
    Ok(())
}

fn merge(analyses: &[PathBuf], out: &Path, replace: bool) -> Result<(), scrub_run::RunError> {
    scrub_run::check_output_is_free(out, replace)?;

    let (analysis, merged) = scrub_run::merge(analyses, machine::identity()?)?;
    analysis.write(out, scrub_run::replacement(replace))?;

    report::describe_comparison(&merged, &analysis, out);
    Ok(())
}

/// Which copy of a duplicated file to keep.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum KeepRule {
    /// The one modified longest ago, which is usually the original.
    Oldest,
    /// The one modified most recently.
    Newest,
    /// The one with the fewest directories above it.
    Shallowest,
}

fn inspect(artifact: &Path) -> Result<(), scrub_run::RunError> {
    // Each artifact is the one before it with more in it, so trying the richest
    // first tells us which we were handed without asking the caller to say.
    if let Ok(run) = scrub_store::Journal::read(artifact)
        && matches!(run.header.stage, Stage::Apply | Stage::Undo)
    {
        report::describe_header(&run.header, run.is_native());
        report::describe_run(&run, artifact, None);
        return Ok(());
    }

    if let Ok(checked) = scrub_store::Preflight::read(artifact)
        && checked.header.stage == Stage::Preflight
    {
        report::describe_header(&checked.header, checked.is_native());
        report::describe_preflight(&checked, None);
        return Ok(());
    }

    if let Ok(drafted) = scrub_store::Plan::read(artifact)
        && drafted.header.stage == Stage::Plan
    {
        report::describe_header(&drafted.header, drafted.is_native());
        report::describe_plan(&drafted, &scrub_core::plan::Keep::Oldest, None);
        return Ok(());
    }

    if let Ok(analysis) = scrub_store::Analysis::read(artifact)
        && analysis.header.stage == Stage::Analyze
    {
        report::describe_header(&analysis.header, analysis.is_native());
        report::describe_body(&analysis.body, None);
        report::describe_groups(&analysis, None);
        return Ok(());
    }

    let inventory = Inventory::read(artifact)?;
    report::describe_header(&inventory.header, inventory.is_native());
    report::describe_body(&inventory.body, None);
    Ok(())
}

fn export(artifact: &Path, out: Option<&Path>) -> Result<(), scrub_run::RunError> {
    let inventory = Inventory::read(artifact)?;

    if let Some(path) = out {
        // DR-11-EXEMPT: a destination the user named on the command line for the
        // tool's own output, never a path discovered by a scan.
        let file = std::fs::File::create(path).map_err(|error| {
            scrub_run::RunError::new(format!("could not create {}: {error}", path.display()))
        })?;
        let mut writer = std::io::BufWriter::new(file);
        return scrub_store::write_ndjson(&inventory, &mut writer)
            .map_err(|error| scrub_run::RunError::new(error.to_string()));
    }

    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    scrub_store::write_ndjson(&inventory, &mut writer)
        .map_err(|error| scrub_run::RunError::new(error.to_string()))
}
