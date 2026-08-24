//! What the command line prints.
//!
//! Two rules shape all of it. Say the incomplete thing plainly rather than
//! rounding it away (DR-23), and lead with the fact the reader is most likely to
//! act on rather than with the largest number.

use std::io::{IsTerminal as _, Write as _};
use std::path::Path;
use std::time::Instant;

use std::collections::HashMap;

use scrub_core::analysis::{Certainty, Settled};
use scrub_core::artifact::ArtifactHeader;
use scrub_core::cloud::{CloudMap, LinkVerdict, Residency};
use scrub_core::inventory::{Entry, EntryKind, ScanOutcome, UnreadReason};
use scrub_store::{Analysis, Body};

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

/// Runs the two reading passes, reporting as it goes.
///
/// The first reads each candidate's two ends, which separates almost everything
/// that merely shares a size. Only what survives that is read in full — which is
/// the difference between reading a terabyte and reading a few gigabytes of it.
pub fn run_passes(
    entries: &[Entry],
    mode: &scrub_platform::ScanMode,
    quiet: bool,
) -> HashMap<usize, Settled> {
    let candidates = scrub_core::analysis::readable_candidates(entries);
    if !quiet {
        println!(
            "{} files share a size with another and can be read here.",
            candidates.len()
        );
    }

    let sampled = read_pass(entries, &candidates, mode, quiet, "sampling ends", true);
    let coarse = scrub_core::analysis::group_duplicates(entries, &sampled);
    let confirm = scrub_core::analysis::needing_full_read(&coarse);

    if !quiet {
        println!(
            "  {} still matched after sampling and are read in full.",
            confirm.len()
        );
    }
    let confirmed = read_pass(entries, &confirm, mode, quiet, "reading in full", false);

    // Everything sampled counts as settled. A file the sample separated matched
    // nothing, which is a finding rather than a gap; filing it as unread would
    // turn a settled fact into a question (DR-14).
    let mut settled = HashMap::with_capacity(sampled.len());
    for index in sampled.keys() {
        settled.insert(*index, Settled::DistinctBySample);
    }
    settled.extend(confirmed);
    settled
}

fn read_pass(
    entries: &[Entry],
    indices: &[usize],
    mode: &scrub_platform::ScanMode,
    quiet: bool,
    label: &str,
    sample: bool,
) -> HashMap<usize, Settled> {
    let mut digests = HashMap::with_capacity(indices.len());
    let show = !quiet && std::io::stdout().is_terminal();
    let mut last_drawn = Instant::now();

    for (done, index) in indices.iter().enumerate() {
        let entry = &entries[*index];
        let outcome = if sample {
            scrub_platform::digest::quick_digest(
                &entry.path,
                &entry.cloud,
                entry.logical_size,
                mode,
            )
        } else {
            scrub_platform::digest::full_digest(&entry.path, &entry.cloud, entry.logical_size, mode)
        };
        // A refusal is not a failure to report loudly here: the file simply
        // stays unsettled, and the group it belongs to says why.
        if let Ok(digest) = outcome {
            digests.insert(*index, Settled::Content(digest));
        }

        if show && last_drawn.elapsed().as_millis() >= 250 {
            last_drawn = Instant::now();
            print!("\r  {label}: {done}/{}    ", indices.len());
            let _ = std::io::stdout().flush();
        }
    }

    if show {
        print!("\r{}\r", " ".repeat(40));
        let _ = std::io::stdout().flush();
    }
    digests
}

/// Prints what an analysis concluded.
pub fn describe_groups(analysis: &Analysis, written_to: Option<&Path>) {
    let exact: Vec<_> = analysis
        .groups
        .iter()
        .filter(|group| group.certainty == Certainty::Exact)
        .collect();
    let candidates: Vec<_> = analysis
        .groups
        .iter()
        .filter(|group| group.certainty == Certainty::Candidate)
        .collect();

    let reclaimable: u64 = exact.iter().map(|group| group.reclaimable_bytes()).sum();
    let copies: usize = exact
        .iter()
        .map(|group| group.objects.len().saturating_sub(1))
        .sum();

    println!("\nDuplicates");
    println!(
        "  {} group(s) proven identical, holding {copies} redundant cop(ies)",
        exact.len()
    );
    println!(
        "  {} would be freed by keeping one of each",
        human_bytes(reclaimable)
    );

    // Never added to the figure above. What might be recoverable is not
    // something anyone should plan around (DR-15).
    if candidates.is_empty() {
        println!("  nothing was left unchecked");
    } else {
        let to_settle: u64 = candidates.iter().map(|group| group.bytes_to_settle()).sum();
        println!(
            "\n  {} group(s) could not be checked, because their content is not on",
            candidates.len()
        );
        println!("  this machine. They are not counted above.");
        if to_settle > 0 {
            println!("  Settling them would download {}.", human_bytes(to_settle));
        }
    }

    if let Some(largest) = exact.iter().max_by_key(|group| group.reclaimable_bytes())
        && largest.reclaimable_bytes() > 0
    {
        println!(
            "\n  Largest single finding: {}",
            human_bytes(largest.reclaimable_bytes())
        );
        for object in largest.objects.iter().take(3) {
            if let Some(index) = object.names.first() {
                println!(
                    "    {}",
                    analysis.body.outcome.entries[*index].path.display()
                );
            }
        }
        if largest.objects.len() > 3 {
            println!("    … and {} more", largest.objects.len() - 3);
        }
    }

    if let Some(path) = written_to {
        println!("\nWritten to {}", path.display());
        println!("  content digest {}", analysis.header.content_digest);
    }
}

/// Prints where an artifact came from.
pub fn describe_header(header: &ArtifactHeader, native: bool) {
    println!("Artifact");
    println!("  stage        {:?}", header.stage);
    println!("  produced     {}", header.created_at);
    println!("  by           scrub {}", header.tool_version);
    println!("  content      {}", header.content_digest);
    if !native {
        println!("  paths        recorded by a machine that spells paths differently;");
        println!("               readable and comparable here, but not executable against.");
    }
    println!();
}

/// Prints what a scan found.
pub fn describe_body(body: &Body, written_to: Option<&Path>) {
    let outcome = &body.outcome;
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
