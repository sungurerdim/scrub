//! What the interface is given.
//!
//! Deliberately not the artifact types. The window shows a settled summary of
//! two million entries, and handing it two million entries so it can count them
//! itself would be slow, fragile, and would put the counting rules in two
//! places. Everything here is computed once, on the side that already knows the
//! rules, and sent across small.
//!
//! The second rule is DR-21: a calm surface with depth on demand. So a group of
//! duplicates crosses as one object with a count, and the copies inside it are
//! fetched only if somebody opens it.

use std::path::Path;

use scrub_core::analysis::Certainty;
use scrub_core::cloud::{CloudMap, LinkVerdict, Residency};
use scrub_core::inventory::{EntryKind, UnreadReason};
use serde::Serialize;

/// What this machine synchronises, and what it does not.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Providers {
    /// Every provider directory found.
    pub roots: Vec<Root>,
    /// Folders inside a cloud directory that the provider is not backing up.
    ///
    /// First in the type and first on the screen. This is the single most
    /// consequential thing the tool can say, and it is invisible in a file
    /// browser: the folder looks like it is in the cloud directory because it
    /// is, and it is not being backed up.
    pub not_backed_up: Vec<Link>,
    /// Links that lead outside every known provider, whose backing up nothing
    /// on this machine can settle either way (DR-15).
    pub unsettled: Vec<Link>,
    /// Links that lead into a provider's own storage, which is ordinary.
    pub provider_owned: usize,
}

/// One provider directory.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    /// Which provider.
    pub provider: String,
    /// Which account, where the platform says.
    pub account: Option<String>,
    /// Where it is.
    pub path: String,
    /// How it came to be there, in words.
    pub origin: String,
}

/// One symbolic link that matters.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    /// The link itself, inside a cloud directory.
    pub link: String,
    /// Where it leads.
    pub target: String,
}

impl Providers {
    /// Summarises a detection for the window.
    #[must_use]
    pub fn of(map: &CloudMap) -> Self {
        Self {
            roots: map
                .roots()
                .iter()
                .map(|root| Root {
                    provider: format!("{:?}", root.provider),
                    account: root.account.clone(),
                    path: show(&root.path),
                    origin: match root.origin {
                        scrub_core::cloud::RootOrigin::ProviderMount => {
                            "the provider's own folder".to_owned()
                        }
                        scrub_core::cloud::RootOrigin::AppContainer => {
                            "an app's own cloud storage".to_owned()
                        }
                        scrub_core::cloud::RootOrigin::ProviderTrash => {
                            "the provider's deleted items".to_owned()
                        }
                        scrub_core::cloud::RootOrigin::HomeRedirect => {
                            "a home folder redirected into the cloud".to_owned()
                        }
                        scrub_core::cloud::RootOrigin::LegacyLocation => {
                            "an older location the provider still uses".to_owned()
                        }
                    },
                })
                .collect(),
            not_backed_up: map.excluded_links().map(link_of).collect(),
            unsettled: map.unsettled_links().map(link_of).collect(),
            provider_owned: map
                .links()
                .iter()
                .filter(|link| link.verdict == LinkVerdict::ProviderOwned)
                .count(),
        }
    }
}

fn link_of(link: &scrub_core::cloud::ProviderLink) -> Link {
    Link {
        link: show(&link.link),
        target: show(&link.target),
    }
}

/// What a scan found.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    /// How many things were recorded.
    pub entries: usize,
    /// How many of those are files.
    pub files: usize,
    /// How many are directories.
    pub directories: usize,
    /// How many are symbolic links, which are recorded and never followed.
    pub links: usize,
    /// How much space the files take on this disk.
    pub bytes: u64,
    /// How many files are in the cloud rather than on this disk.
    ///
    /// Only files the provider says are held remotely. A file outside every
    /// provider is not "in the cloud", it is simply not synchronised, and
    /// counting the two together would put most of the disk in this figure.
    pub in_cloud: usize,
    /// Places that could not be read, which are stated and never rounded away.
    pub unread: Vec<Unread>,
}

/// Somewhere the scan could not look.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unread {
    /// Where.
    pub path: String,
    /// Why, in words a person can act on.
    pub reason: String,
}

impl Inventory {
    /// Summarises a scan's outcome.
    #[must_use]
    pub fn of(outcome: &scrub_core::inventory::ScanOutcome) -> Self {
        let mut summary = Self {
            entries: outcome.entries.len(),
            ..Self::default()
        };

        for entry in &outcome.entries {
            match entry.kind {
                EntryKind::File => {
                    summary.files += 1;
                    summary.bytes += entry.allocated_size.unwrap_or(entry.logical_size);
                    if matches!(
                        entry.cloud.residency,
                        Residency::Remote | Residency::Partial
                    ) {
                        summary.in_cloud += 1;
                    }
                }
                EntryKind::Directory => summary.directories += 1,
                EntryKind::Symlink => summary.links += 1,
                EntryKind::Other => {}
            }
        }

        // Capped, because a permissions problem can produce thousands of these
        // and a list nobody can read is the same as no list. The count above is
        // never capped.
        summary.unread = outcome
            .unread
            .iter()
            .take(200)
            .map(|unread| Unread {
                path: show(&unread.path),
                reason: match unread.reason {
                    UnreadReason::PermissionDenied => {
                        "this account is not allowed to read it".to_owned()
                    }
                    UnreadReason::WouldRequireDownload => {
                        "reading it would have downloaded it".to_owned()
                    }
                    UnreadReason::Vanished => "it went away while the scan ran".to_owned(),
                    UnreadReason::Other(ref reason) => reason.clone(),
                },
            })
            .collect();

        summary
    }
}

/// What an analysis concluded, as one screen's worth of facts.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Findings {
    /// Groups proven identical by reading every byte.
    pub proven: usize,
    /// Redundant copies inside those groups.
    pub redundant: usize,
    /// What keeping one of each would free.
    pub reclaimable: u64,
    /// Groups that could not be checked, because their content is not here.
    ///
    /// Never folded into the figure above. What might be recoverable is not
    /// something anyone should plan around (DR-15).
    pub unchecked: usize,
    /// What settling those would have to download first.
    pub to_settle: u64,
}

/// One group of duplicates, as a single row.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupRow {
    /// Its position in the analysis, for asking about it later.
    pub index: usize,
    /// A name to show, taken from one of the copies.
    pub name: String,
    /// How many copies there are.
    pub copies: usize,
    /// How big one copy is.
    pub size: u64,
    /// What keeping one of them would free.
    pub reclaimable: u64,
    /// Whether every byte was read, or the group is only a candidate.
    pub proven: bool,
}

/// One copy inside a group, shown only when somebody opens it (DR-21).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Copy {
    /// Where it is.
    pub path: String,
    /// When it was last changed, where the platform recorded it.
    pub modified: Option<i64>,
    /// When it was created, where the platform recorded it.
    ///
    /// Shown as detail and never used to decide identity: the same bytes
    /// written twice are the same file, whatever the dates say.
    pub created: Option<i64>,
    /// Whether its content is on this machine.
    pub local: bool,
    /// Whether it is another name for a copy already listed, rather than a
    /// second copy taking its own space.
    pub same_file: bool,
}

/// One thing a plan would do.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    /// Its position in the plan.
    pub index: usize,
    /// What kind of change: `quarantine`, `move`, or `createDirectory`.
    pub kind: String,
    /// What it acts on.
    pub subject: String,
    /// Where it goes, for the ones that move something.
    pub destination: Option<String>,
    /// What it frees.
    pub frees: u64,
    /// Why it is here, in words.
    pub because: String,
    /// What preflight made of it, once preflight has run.
    pub verdict: Option<StepVerdict>,
}

/// What preflight made of one step.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepVerdict {
    /// `pass`, `hold`, or `fail`.
    pub grade: String,
    /// What stands in the way, for anything that is not a pass.
    pub impediment: Option<String>,
}

/// Renders a path for the window.
///
/// Lossy on purpose, and only here: the stored path keeps the exact bytes, and
/// every operation uses those. This is the label, not the identity.
pub fn show(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Turns a certainty into the plain word the window uses.
#[must_use]
pub fn is_proven(certainty: Certainty) -> bool {
    certainty == Certainty::Exact
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrub_core::cloud::CloudState;
    use scrub_core::inventory::{Entry, ScanOutcome};
    use std::path::PathBuf;

    fn file(path: &str, size: u64, residency: Residency) -> Entry {
        Entry {
            path: PathBuf::from(path),
            kind: EntryKind::File,
            logical_size: size,
            allocated_size: Some(size),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState {
                provider: None,
                residency,
                retention: scrub_core::cloud::Retention::Unspecified,
            },
        }
    }

    #[test]
    fn a_summary_counts_what_is_in_the_cloud_apart_from_what_is_here() {
        // The distinction is the reason someone opens this tool: a file that
        // shows in the file browser but is not on the disk is neither missing
        // nor present, and folding the two together hides that.
        let outcome = ScanOutcome {
            entries: vec![
                file("/here.txt", 1_000, Residency::Local),
                file("/away.txt", 2_000, Residency::Remote),
                // Most of a disk looks like this: outside every provider, and
                // so neither in the cloud nor missing from it.
                file("/elsewhere.txt", 4_000, Residency::NotSynced),
            ],
            unread: Vec::new(),
        };

        let summary = Inventory::of(&outcome);
        assert_eq!(summary.files, 3);
        assert_eq!(
            summary.in_cloud, 1,
            "only the file the provider holds remotely is in the cloud"
        );
        assert_eq!(summary.bytes, 7_000);
    }

    #[test]
    fn a_place_that_could_not_be_read_is_listed_with_a_reason_a_person_can_act_on() {
        // DR-23: a container we could not read is never reported as empty, and
        // "error 13" is not a reason anybody can act on.
        let outcome = ScanOutcome {
            entries: Vec::new(),
            unread: vec![scrub_core::inventory::Unread {
                path: PathBuf::from("/Library/Private"),
                reason: UnreadReason::PermissionDenied,
            }],
        };

        let summary = Inventory::of(&outcome);
        assert_eq!(summary.unread.len(), 1);
        assert!(
            summary.unread[0].reason.contains("not allowed"),
            "the reason has to be readable: {}",
            summary.unread[0].reason
        );
    }
}
