//! The command line: every stage of the pipeline as a command.
//!
//! Not a second product surface. It exists so each stage can be driven and
//! checked by machine, and so the artifacts are usable by anyone who would
//! rather script than click. The graphical interface runs the same crates.

#![forbid(unsafe_code)]

mod machine;
mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use scrub_core::artifact::{ArtifactHeader, MachineScope, SCHEMA_VERSION, Stage};
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
        } => scan(paths, &out, quiet, replace),
        Command::Analyze {
            inventory,
            out,
            quiet,
            replace,
            thorough,
        } => analyze(&inventory, &out, quiet, replace, thorough),
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
    paths: Vec<PathBuf>,
    out: &std::path::Path,
    quiet: bool,
    replace: bool,
) -> Result<(), String> {
    check_output_is_free(out, replace)?;

    // Before anything else: ask the platform to make an accidental download
    // impossible. If it refuses, the scan does not start — proceeding would risk
    // pulling a user's archive down over a metered connection (DR-11).
    let mode = scrub_platform::enter_read_only_scan_mode().map_err(|error| error.to_string())?;

    let home = home_directory()?;
    let map = scrub_platform::detect_cloud_map(&home).map_err(|error| error.to_string())?;

    let roots = if paths.is_empty() { vec![home] } else { paths };

    report::describe_providers(&map);

    let mut outcome = scrub_core::inventory::ScanOutcome::default();
    for root in &roots {
        let mut progress = report::Progress::new(quiet, root);
        let found = scrub_platform::walk::walk_reporting(root, &map, &mode, &mut |state| {
            progress.update(state);
        });
        progress.finish(&found);
        outcome.entries.extend(found.entries);
        outcome.unread.extend(found.unread);
    }

    let body = scrub_store::Body {
        path_encoding: scrub_core::paths::LOCAL,
        detection: scrub_core::cloud::Detection {
            roots: map.roots().to_vec(),
            links: map.links().to_vec(),
        },
        outcome,
    };

    let inventory = Inventory {
        header: header_for(
            Stage::Scan,
            Vec::new(),
            scrub_store::scope_digest(&roots),
            scrub_store::content_digest(&body, &[]),
        )?,
        body,
    };

    inventory
        .write(out, replacement(replace))
        .map_err(|error| error.to_string())?;

    report::describe_body(&inventory.body, Some(out));
    Ok(())
}

/// Refuses an occupied output before any work is done.
///
/// The same refusal happens at the moment of writing, which is where the
/// invariant belongs. This one exists so that a scan of two million files does
/// not run to completion before announcing that its output name was taken.
fn check_output_is_free(out: &std::path::Path, replace: bool) -> Result<(), String> {
    if replace || !out.exists() {
        return Ok(());
    }
    Err(format!(
        "{} already exists, and nothing is overwritten without being asked. \
         Choose another name, or pass --replace to write over it.",
        out.display()
    ))
}

fn replacement(replace: bool) -> scrub_store::Replace {
    if replace {
        scrub_store::Replace::Yes
    } else {
        scrub_store::Replace::Never
    }
}

/// Builds the header every artifact this run produces.
fn header_for(
    stage: Stage,
    parents: Vec<scrub_core::artifact::Digest>,
    scope_digest: scrub_core::artifact::Digest,
    content_digest: scrub_core::artifact::Digest,
) -> Result<ArtifactHeader, String> {
    Ok(ArtifactHeader {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        stage,
        kind: stage.output_kind(),
        parents,
        machine: MachineScope::Single {
            machine: machine::identity()?,
        },
        created_at: jiff::Timestamp::now(),
        scope_digest,
        content_digest,
    })
}

fn analyze(
    inventory_path: &std::path::Path,
    out: &std::path::Path,
    quiet: bool,
    replace: bool,
    thorough: bool,
) -> Result<(), String> {
    check_output_is_free(out, replace)?;

    // Analysis reads file content, so the same guard the scan starts under
    // applies here with more force (DR-11).
    let mode = scrub_platform::enter_read_only_scan_mode().map_err(|error| error.to_string())?;

    let inventory = Inventory::read(inventory_path)
        .map_err(|error| format!("could not read {}: {error}", inventory_path.display()))?;
    scrub_core::artifact::verify_executable_here(&inventory.header, machine::identity()?)
        .map_err(|error| error.to_string())?;
    if !inventory.is_native() {
        return Err(
            "this inventory was recorded by a machine that spells paths differently,              so its files cannot be read here"
                .to_owned(),
        );
    }

    let entries = &inventory.body.outcome.entries;
    let parent = inventory.header.content_digest;

    let settled = report::run_passes(entries, &mode, quiet, thorough);
    let groups = scrub_core::analysis::group_duplicates(entries, &settled);
    let settled: std::collections::BTreeMap<_, _> = settled.into_iter().collect();

    let analysis = scrub_store::Analysis {
        header: header_for(
            Stage::Analyze,
            vec![parent],
            inventory.header.scope_digest,
            scrub_store::analysis_digest(&inventory.body, &groups, &settled),
        )?,
        body: inventory.body,
        groups,
        settled,
    };

    analysis
        .write(out, replacement(replace))
        .map_err(|error| error.to_string())?;

    report::describe_groups(&analysis, Some(out));
    Ok(())
}

fn merge(analyses: &[PathBuf], out: &std::path::Path, replace: bool) -> Result<(), String> {
    check_output_is_free(out, replace)?;
    if analyses.len() < 2 {
        return Err(
            "merging needs at least two analyses; combining one with nothing would \
             produce a second artifact claiming to be a comparison"
                .to_owned(),
        );
    }

    let mut inputs = Vec::with_capacity(analyses.len());
    let mut parents = Vec::with_capacity(analyses.len());
    let mut encoding = None;

    for path in analyses {
        let analysis = scrub_store::Analysis::read(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        parents.push(analysis.header.content_digest);
        encoding.get_or_insert(analysis.body.path_encoding);

        inputs.push(scrub_core::merge::Input {
            label: label_for(path),
            machine: match analysis.header.machine {
                MachineScope::Single { machine } => machine,
                MachineScope::Merged { .. } => {
                    return Err(format!(
                        "{} is itself a comparison; merge the original analyses instead, \
                         so every machine is counted once",
                        path.display()
                    ));
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

    let body = scrub_store::Body {
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
        scrub_core::artifact::Digest::of(b"combined"),
        scrub_core::artifact::Digest::of(b"placeholder"),
    )?;
    // A comparison describes several machines, so it can be read anywhere and
    // executed nowhere (DR-18).
    header.machine = MachineScope::Merged {
        machines: merged.sources.iter().map(|source| source.machine).collect(),
    };

    let mut analysis = scrub_store::Analysis {
        header,
        body,
        groups,
        settled: merged.settled.clone(),
    };
    analysis.header.content_digest = analysis.content_digest();

    analysis
        .write(out, replacement(replace))
        .map_err(|error| error.to_string())?;

    report::describe_comparison(&merged, &analysis, out);
    Ok(())
}

/// What to call a machine in the comparison.
///
/// Taken from the artifact's file name, because a machine identity is a random
/// value that means nothing to anyone reading a report, and asking for a label
/// every time would be a question with an obvious answer.
fn label_for(path: &std::path::Path) -> String {
    path.file_stem().map_or_else(
        || path.display().to_string(),
        |stem| stem.to_string_lossy().into_owned(),
    )
}

fn inspect(artifact: &std::path::Path) -> Result<(), String> {
    // An analysis is an inventory with more in it, so trying that first tells us
    // which we were handed without asking the caller to say.
    if let Ok(analysis) = scrub_store::Analysis::read(artifact)
        && analysis.header.stage == Stage::Analyze
    {
        report::describe_header(&analysis.header, analysis.is_native());
        report::describe_body(&analysis.body, None);
        report::describe_groups(&analysis, None);
        return Ok(());
    }

    let inventory = Inventory::read(artifact)
        .map_err(|error| format!("could not read {}: {error}", artifact.display()))?;
    report::describe_header(&inventory.header, inventory.is_native());
    report::describe_body(&inventory.body, None);
    Ok(())
}

fn export(artifact: &std::path::Path, out: Option<&std::path::Path>) -> Result<(), String> {
    let inventory = Inventory::read(artifact)
        .map_err(|error| format!("could not read {}: {error}", artifact.display()))?;

    if let Some(path) = out {
        // DR-11-EXEMPT: a destination the user named on the command line for the
        // tool's own output, never a path discovered by a scan.
        let file = std::fs::File::create(path)
            .map_err(|error| format!("could not create {}: {error}", path.display()))?;
        let mut writer = std::io::BufWriter::new(file);
        return scrub_store::write_ndjson(&inventory, &mut writer)
            .map_err(|error| error.to_string());
    }

    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    scrub_store::write_ndjson(&inventory, &mut writer).map_err(|error| error.to_string())
}

fn home_directory() -> Result<PathBuf, String> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{key} is not set, so there is no home directory to scan"))
}
