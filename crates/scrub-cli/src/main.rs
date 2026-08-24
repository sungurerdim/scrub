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
        Command::Scan { paths, out, quiet } => scan(paths, &out, quiet),
        Command::Analyze {
            inventory,
            out,
            quiet,
        } => analyze(&inventory, &out, quiet),
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

fn scan(paths: Vec<PathBuf>, out: &std::path::Path, quiet: bool) -> Result<(), String> {
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
        .write(out)
        .map_err(|error| format!("could not write {}: {error}", out.display()))?;

    report::describe_body(&inventory.body, Some(out));
    Ok(())
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
) -> Result<(), String> {
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

    let settled = report::run_passes(entries, &mode, quiet);
    let groups = scrub_core::analysis::group_duplicates(entries, &settled);

    let analysis = scrub_store::Analysis {
        header: header_for(
            Stage::Analyze,
            vec![parent],
            inventory.header.scope_digest,
            scrub_store::content_digest(&inventory.body, &groups),
        )?,
        body: inventory.body,
        groups,
    };

    analysis
        .write(out)
        .map_err(|error| format!("could not write {}: {error}", out.display()))?;

    report::describe_groups(&analysis, Some(out));
    Ok(())
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
