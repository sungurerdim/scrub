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

    let detection = scrub_core::cloud::Detection {
        roots: map.roots().to_vec(),
        links: map.links().to_vec(),
    };
    let content_digest = scrub_store::content_digest(&detection, &outcome);

    let inventory = Inventory {
        header: ArtifactHeader {
            schema_version: SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            stage: Stage::Scan,
            kind: Stage::Scan.output_kind(),
            parents: Vec::new(),
            machine: MachineScope::Single {
                machine: machine::identity()?,
            },
            created_at: jiff::Timestamp::now(),
            scope_digest: scrub_store::scope_digest(&roots),
            content_digest,
        },
        path_encoding: scrub_core::paths::LOCAL,
        detection,
        outcome,
    };

    inventory
        .write(out)
        .map_err(|error| format!("could not write {}: {error}", out.display()))?;

    report::describe_inventory(&inventory, Some(out));
    Ok(())
}

fn inspect(artifact: &std::path::Path) -> Result<(), String> {
    let inventory = Inventory::read(artifact)
        .map_err(|error| format!("could not read {}: {error}", artifact.display()))?;
    report::describe_header(&inventory);
    report::describe_inventory(&inventory, None);
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
