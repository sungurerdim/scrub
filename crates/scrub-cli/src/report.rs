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
use scrub_core::plan::Keep;
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
/// The first reads each candidate's two ends — its whole content, for anything
/// small enough that seeking would cost more than reading. That separates almost
/// everything which merely shares a size. Only what survives is read through.
pub fn run_passes(
    entries: &[Entry],
    mode: &scrub_platform::ScanMode,
    quiet: bool,
    thorough: bool,
) -> HashMap<usize, Settled> {
    let candidates = if thorough {
        scrub_core::analysis::all_readable(entries)
    } else {
        scrub_core::analysis::readable_candidates(entries)
    };
    if !quiet {
        if thorough {
            println!(
                "{} files can be read here, and all of them will be — \
                 comparison needs a fingerprint for each.",
                candidates.len()
            );
        } else {
            println!(
                "{} files share a size with another and can be read here.",
                candidates.len()
            );
        }
    }

    let sampled = read_pass(entries, &candidates, mode, quiet, "sampling", true);

    // A file small enough to have been read through already has its content
    // digest; a larger one has only a fingerprint, which is not identity.
    let mut settled: HashMap<usize, Settled> = sampled
        .iter()
        .map(|(index, digest)| {
            let complete = entries[*index].logical_size
                <= scrub_platform::digest::SAMPLE_READS_WHOLE_FILE_UP_TO;
            let settled = if complete {
                Settled::Content(*digest)
            } else {
                Settled::DistinctBySample(*digest)
            };
            (*index, settled)
        })
        .collect();

    // Grouping on samples decides only what is worth reading in full. Treating a
    // sample as identity here is safe because nothing acts on the result; the
    // groups that survive are read through before anything is concluded.
    let provisional: HashMap<usize, Settled> = sampled
        .iter()
        .map(|(index, digest)| (*index, Settled::Content(*digest)))
        .collect();
    let confirm: Vec<usize> = scrub_core::analysis::needing_full_read(
        &scrub_core::analysis::group_duplicates(entries, &provisional),
    )
    .into_iter()
    .filter(|index| {
        entries[*index].logical_size > scrub_platform::digest::SAMPLE_READS_WHOLE_FILE_UP_TO
    })
    .collect();

    if !quiet {
        println!(
            "  {} are large enough to need reading in full.",
            confirm.len()
        );
    }
    for (index, digest) in read_pass(entries, &confirm, mode, quiet, "reading", false) {
        settled.insert(index, Settled::Content(digest));
    }

    settled
}

fn read_pass(
    entries: &[Entry],
    indices: &[usize],
    mode: &scrub_platform::ScanMode,
    quiet: bool,
    label: &str,
    sample: bool,
) -> HashMap<usize, scrub_core::artifact::Digest> {
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
        // A refusal is not reported loudly here: the file stays unsettled, and
        // the group it belongs to says why.
        if let Ok(digest) = outcome {
            digests.insert(*index, digest);
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

/// Prints what comparing several machines showed.
///
/// Leads with the question people actually have — is this in both places, or
/// only one — rather than with a total. A file present on one machine only is
/// the one worth acting on; a file present on both is the one that is safe.
pub fn describe_comparison(
    merged: &scrub_core::merge::Merged,
    analysis: &Analysis,
    written_to: &Path,
) {
    println!("Comparing {} machines", merged.sources.len());

    // Coverage first, because everything below is only true of what was read. An
    // analysis run without --thorough skips files whose size nothing on their
    // own machine shares, and those cannot be recognised anywhere (DR-23).
    let mut partial = false;
    for source in &merged.sources {
        let files = (source.first_entry..source.first_entry + source.entry_count)
            .filter(|index| merged.outcome.entries[*index].kind == EntryKind::File)
            .filter(|index| merged.outcome.entries[*index].logical_size > 0)
            .count();
        let fingerprinted = analysis
            .settled
            .keys()
            .filter(|entry| source.contains(**entry))
            .count();
        partial |= fingerprinted < files;
        println!(
            "  {:<20} {fingerprinted} of {files} files carry a fingerprint",
            source.label
        );
    }

    if partial {
        println!("\n  Files without a fingerprint were never read, so nothing below");
        println!("  says anything about them. Re-run `analyze --thorough` on each");
        println!("  machine to compare everything.");
    }

    let mut shared = 0_usize;
    let mut shared_bytes = 0_u64;
    let mut local_only = 0_usize;

    for group in &analysis.groups {
        if group.certainty != Certainty::Exact {
            continue;
        }
        let names: Vec<usize> = group
            .objects
            .iter()
            .flat_map(|object| object.names.clone())
            .collect();
        if merged.sources_among(&names).len() > 1 {
            shared += 1;
            shared_bytes += group.logical_size;
        } else {
            local_only += 1;
        }
    }

    println!("\nHeld in more than one place");
    println!(
        "  {shared} file(s), {} of content",
        human_bytes(shared_bytes)
    );
    println!("  {local_only} duplicate group(s) live entirely on one machine");

    // What is on one machine and nowhere else. The figure people came for, and
    // the one a tool has no business rounding off.
    println!("\nHeld in one place only");
    for (position, source) in merged.sources.iter().enumerate() {
        let only_here = count_exclusive(merged, analysis, position);
        println!(
            "  {:<20} {} file(s) that no other machine has a copy of",
            source.label, only_here
        );
    }

    let unchecked = analysis
        .groups
        .iter()
        .filter(|group| group.certainty == Certainty::Candidate)
        .count();
    if unchecked > 0 {
        println!("\n  {unchecked} group(s) could not be checked and are counted nowhere above.");
    }

    println!("\nWritten to {}", written_to.display());
    println!("  content digest {}", analysis.header.content_digest);
    println!("  This is a comparison of several machines, so it can be read");
    println!("  anywhere and applied nowhere.");
}

/// Files from one machine that no other machine holds a copy of.
///
/// Counted from the fingerprints rather than from the groups: a file in no group
/// at all matched nothing anywhere, which is exactly what makes it exclusive.
fn count_exclusive(
    merged: &scrub_core::merge::Merged,
    analysis: &Analysis,
    source: usize,
) -> usize {
    let elsewhere: std::collections::HashSet<_> = analysis
        .settled
        .iter()
        .filter(|(entry, _)| {
            merged
                .source_of(**entry)
                .is_some_and(|found| found.label != merged.sources[source].label)
        })
        .filter_map(|(_, state)| state.content())
        .collect();

    analysis
        .settled
        .iter()
        .filter(|(entry, _)| merged.sources[source].contains(**entry))
        .filter_map(|(_, state)| state.content())
        .filter(|digest| !elsewhere.contains(digest))
        .count()
}

/// Prints a plan as the difference between how things are and how they would be.
///
/// The screen a decision is made on. Everything it says is in the conditional,
/// because nothing has happened: a plan is a document until somebody applies it,
/// and reading one changes nothing at all (DR-9).
pub fn describe_plan(plan: &scrub_store::Plan, rule: &Keep, written_to: Option<&Path>) {
    let effect = plan.effect();
    let conflicts = plan.conflicts();

    println!("\nPlan");
    println!("  {}", describe_rule(rule));
    println!("  Nothing has happened. This is what would.");

    if plan.operations.is_empty() {
        println!("\n  No operations. There is nothing to do.");
        return;
    }

    if effect.directories > 0 {
        println!("\n  CREATE  {} director(ies)", effect.directories);
    }
    if effect.moved > 0 {
        println!("\n  MOVE    {} file(s)", effect.moved);
        for operation in plan.operations.iter().take(200) {
            if let scrub_core::plan::Operation::Move {
                subject,
                destination,
            } = operation
            {
                println!("    {}", subject.path.display());
                println!("      to {}", destination.display());
            }
        }
    }

    if effect.quarantined > 0 {
        println!(
            "\n  SET ASIDE  {} file(s), freeing {}",
            effect.quarantined,
            human_bytes(effect.frees)
        );
        println!("    Set aside means moved to quarantine, not deleted. Nothing leaves");
        println!("    quarantine until you empty it yourself.");
        show_quarantines(plan);
    }

    // Reported here, while the plan is still a document. The same collision
    // discovered halfway through execution is a half-finished reorganization
    // (DR-6).
    println!();
    if conflicts.is_empty() {
        println!("  No conflicts: every destination is free.");
    } else {
        println!(
            "  {} CONFLICT(S) — nothing will run until these are settled:",
            conflicts.len()
        );
        for conflict in conflicts.iter().take(20) {
            println!("    {}", conflict.destination.display());
            if let Some(entry) = conflict.occupied_by {
                println!(
                    "      already holds {}",
                    plan.body.outcome.entries[entry].path.display()
                );
            }
            if conflict.claimants.len() > 1 {
                println!("      wanted by {} operations", conflict.claimants.len());
            }
        }
        if conflicts.len() > 20 {
            println!("    … and {} more", conflicts.len() - 20);
        }
    }

    if let Some(path) = written_to {
        println!("\nWritten to {}", path.display());
        println!("  content digest {}", plan.header.content_digest);
        println!("  Nothing on disk has been touched.");
    }
}

/// The first few files a plan would set aside, and why.
///
/// A sample rather than the list: a plan can hold hundreds of thousands of
/// operations, and a wall of them is not a thing anyone reviews. The artifact
/// holds every one, queryable.
fn show_quarantines(plan: &scrub_store::Plan) {
    let mut shown = 0;
    for operation in &plan.operations {
        let scrub_core::plan::Operation::Quarantine { subject, because } = operation else {
            continue;
        };
        if shown >= 5 {
            break;
        }
        shown += 1;
        println!("    {}", subject.path.display());
        if let scrub_core::plan::Because::RedundantCopy { kept, .. } = because {
            println!("      same content as {}", kept.display());
        }
    }

    let total = plan
        .operations
        .iter()
        .filter(|operation| matches!(operation, scrub_core::plan::Operation::Quarantine { .. }))
        .count();
    if total > shown {
        println!(
            "    … and {} more, all of them in the artifact",
            total - shown
        );
    }
}

fn describe_rule(rule: &Keep) -> String {
    match rule {
        Keep::Oldest => "Keeping the copy modified longest ago.".to_owned(),
        Keep::Newest => "Keeping the copy modified most recently.".to_owned(),
        Keep::Shallowest => "Keeping the copy with the fewest directories above it.".to_owned(),
        Keep::Under(path) => format!("Keeping the copy under {}.", path.display()),
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
