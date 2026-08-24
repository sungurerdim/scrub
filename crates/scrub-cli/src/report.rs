//! What the command line prints.
//!
//! Two rules shape all of it. Say the incomplete thing plainly rather than
//! rounding it away (DR-23), and lead with the fact the reader is most likely to
//! act on rather than with the largest number.

use std::io::{IsTerminal as _, Write as _};
use std::path::Path;
use std::time::Instant;

use scrub_core::cloud::{CloudMap, LinkVerdict, Residency};
use scrub_core::inventory::{EntryKind, ScanOutcome, UnreadReason};
use scrub_store::Inventory;

/// Prints what the machine is synchronising, before the scan starts.
pub fn describe_providers(map: &CloudMap) {
    if map.roots().is_empty() {
        println!("No sync providers detected on this machine.");
        return;
    }

    println!("{} provider directories detected.", map.roots().len());

    // Surfaced first and by itself: a folder sitting inside a cloud directory
    // that the provider is not backing up is the single most consequential thing
    // this tool can tell someone, and it is invisible in a file browser.
    let excluded: Vec<_> = map.excluded_links().collect();
    if !excluded.is_empty() {
        println!(
            "\n  {} folder(s) inside a cloud directory are NOT being backed up:",
            excluded.len()
        );
        for link in &excluded {
            println!("    {}", link.target.display());
            println!("      linked from {}", link.link.display());
        }
        println!("    The provider marked these links as excluded from sync.");
    }

    let owned = map
        .links()
        .iter()
        .filter(|link| link.verdict == LinkVerdict::ProviderOwned)
        .count();
    if owned > 0 {
        println!("\n  {owned} link(s) lead to a provider's own storage.");
    }

    let unsettled: Vec<_> = map.unsettled_links().collect();
    if !unsettled.is_empty() {
        println!(
            "\n  {} link(s) lead outside every known provider, and nothing on this",
            unsettled.len()
        );
        println!("  machine says whether their contents are backed up:");
        for link in &unsettled {
            println!("    {} -> {}", link.link.display(), link.target.display());
        }
    }
    println!();
}

/// Progress while a scan runs.
pub struct Progress {
    quiet: bool,
    started: Instant,
    last_drawn: Instant,
}

impl Progress {
    pub fn new(quiet: bool, root: &Path) -> Self {
        // Progress redraws in place with a carriage return, which only means
        // anything to a terminal. Piped to a file or another program it produces
        // one unbroken line of noise, so it is simply not drawn there.
        let quiet = quiet || !std::io::stdout().is_terminal();
        let now = Instant::now();
        if !quiet {
            println!("Scanning {}", root.display());
        }
        Self {
            quiet,
            started: now,
            last_drawn: now,
        }
    }

    /// Redraws at most a few times a second.
    ///
    /// A scan reads tens of thousands of directories a second; drawing on each
    /// one would spend more time on the terminal than on the filesystem.
    pub fn update(&mut self, state: &scrub_platform::walk::Progress<'_>) {
        if self.quiet || self.last_drawn.elapsed().as_millis() < 250 {
            return;
        }
        self.last_drawn = Instant::now();
        print!("\r  {} found, {} unreadable…  ", state.found, state.unread);
        let _ = std::io::stdout().flush();
    }

    pub fn finish(&self, outcome: &ScanOutcome) {
        if self.quiet {
            return;
        }
        println!(
            "\r  {} entries in {:.1?}{}",
            outcome.entries.len(),
            self.started.elapsed(),
            " ".repeat(20)
        );
    }
}

/// Prints where an artifact came from.
pub fn describe_header(inventory: &Inventory) {
    let header = &inventory.header;
    println!("Artifact");
    println!("  stage        {:?}", header.stage);
    println!("  produced     {}", header.created_at);
    println!("  by           scrub {}", header.tool_version);
    println!("  content      {}", header.content_digest);
    if !inventory.is_native() {
        println!("  paths        recorded by a machine that spells paths differently;");
        println!("               readable and comparable here, but not executable against.");
    }
    println!();
}

/// Prints what a scan found.
pub fn describe_inventory(inventory: &Inventory, written_to: Option<&Path>) {
    let outcome = &inventory.outcome;
    let files = count(outcome, EntryKind::File);
    let directories = count(outcome, EntryKind::Directory);
    let links = count(outcome, EntryKind::Symlink);

    let not_downloaded = outcome
        .entries
        .iter()
        .filter(|entry| entry.cloud.residency == Residency::Remote)
        .count();
    let synced = outcome
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File && entry.cloud.provider.is_some())
        .count();

    println!("Found");
    println!("  {files} files, {directories} directories, {links} links");
    println!("  {synced} files are in a sync provider's directory");
    println!("  {not_downloaded} of those are not downloaded to this machine");
    println!(
        "  {} would actually be freed by removing every file once",
        human_bytes(outcome.reclaimable_bytes())
    );

    // Never folded into the totals above. "I could not look inside" and "there
    // is nothing inside" lead to opposite decisions (DR-23).
    if outcome.is_complete() {
        println!("  everything asked for was read");
    } else {
        println!("\n  {} place(s) could not be read:", outcome.unread.len());
        for reason in [
            UnreadReason::PermissionDenied,
            UnreadReason::WouldRequireDownload,
            UnreadReason::Vanished,
        ] {
            let matching: Vec<_> = outcome
                .unread
                .iter()
                .filter(|place| place.reason == reason)
                .collect();
            if matching.is_empty() {
                continue;
            }
            println!("    {} — {}", matching.len(), explain(&reason));
            for place in matching.iter().take(3) {
                println!("      {}", place.path.display());
            }
            if matching.len() > 3 {
                println!("      … and {} more", matching.len() - 3);
            }
        }
        println!("  Counts above cover what was read, and nothing more.");
    }

    if let Some(path) = written_to {
        println!("\nWritten to {}", path.display());
        println!("  content digest {}", inventory.header.content_digest);
    }
}

/// Renders a byte count without pretending to precision it does not have.
///
/// Integer arithmetic throughout: a home directory can hold more bytes than a
/// float carries exactly, and a figure the user is about to make a decision on
/// should not drift because of the way it was printed.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TB", 1_000_000_000_000),
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("kB", 1_000),
    ];
    for (unit, scale) in UNITS {
        if bytes >= scale {
            let whole = bytes / scale;
            let tenths = (bytes % scale) * 10 / scale;
            return format!("{whole}.{tenths} {unit}");
        }
    }
    format!("{bytes} bytes")
}

fn count(outcome: &ScanOutcome, kind: EntryKind) -> usize {
    outcome
        .entries
        .iter()
        .filter(|entry| entry.kind == kind)
        .count()
}

fn explain(reason: &UnreadReason) -> &'static str {
    match reason {
        UnreadReason::PermissionDenied => "the system refused access",
        UnreadReason::WouldRequireDownload => "cloud-only; reading would download it",
        UnreadReason::Vanished => "it disappeared while scanning",
        UnreadReason::Other(_) => "reported by the system",
    }
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

    #[test]
    fn byte_counts_are_rendered_without_floating_point_drift() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(999), "999 bytes");
        assert_eq!(human_bytes(1_500), "1.5 kB");
        assert_eq!(human_bytes(332_053_000_000), "332.0 GB");
        // Beyond what an f64 carries exactly, which is the reason for integers.
        assert_eq!(human_bytes(9_007_199_254_740_993), "9007.1 TB");
    }
}
