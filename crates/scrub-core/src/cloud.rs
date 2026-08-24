//! The vocabulary for describing a machine's relationship to its clouds.
//!
//! These types are the shared language between the stage that discovers cloud
//! state and every stage that later reasons about it. They live in the core
//! rather than in the platform layer for two reasons: the artifact schema is
//! built from them, and the merge stage reconstructs another machine's cloud map
//! out of an artifact, on a machine that may run a different operating system
//! entirely.
//!
//! Nothing here touches the filesystem. Deciding which provider owns a path is
//! pure path arithmetic and is tested as such; discovering the providers, and
//! reading a file's residency off its metadata, belong to `scrub-platform`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A sync provider that owns part of the filesystem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Apple iCloud Drive, including per-application containers.
    ICloud,
    /// Google Drive for desktop.
    GoogleDrive,
    /// Microsoft OneDrive, personal or work.
    OneDrive,
    /// Dropbox.
    Dropbox,
    /// A provider we recognised a mount for but do not model specifically.
    Other(String),
}

/// Where a file's bytes actually are.
///
/// This is the single most consequential fact the scanner records. A file whose
/// bytes are remote looks completely ordinary — full name, full size, full
/// timestamps — and reading it triggers a download (DR-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Residency {
    /// The content is on local storage. Reading it costs nothing.
    Local,
    /// The content lives with the provider. Reading it would download it.
    Remote,
    /// Some of the content is local. Reading all of it would download the rest.
    Partial,
    /// The path is not managed by any sync provider we detected.
    NotSynced,
    /// The path is provider-managed but its residency could not be determined.
    ///
    /// Treated as [`Residency::Remote`] wherever a decision must be made: an
    /// unnecessary caution costs the user nothing, an unnecessary download does.
    Unknown,
}

impl Residency {
    /// Whether reading this file's content may cause a download.
    ///
    /// [`Residency::Unknown`] answers `true`, deliberately.
    #[must_use]
    pub fn read_may_download(self) -> bool {
        match self {
            Self::Local | Self::NotSynced => false,
            Self::Remote | Self::Partial | Self::Unknown => true,
        }
    }
}

/// Whether the user asked for this file to stay downloaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    /// The user asked for this to be kept on the device.
    Pinned,
    /// The user allowed this to be evicted when space is needed.
    Unpinned,
    /// No preference recorded, or the platform does not expose one.
    Unspecified,
}

/// What the scanner knows about one path's relationship to the cloud.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudState {
    /// The provider that owns the path, if any.
    pub provider: Option<Provider>,
    /// Where the content is.
    pub residency: Residency,
    /// Whether the user pinned it locally.
    pub retention: Retention,
}

impl CloudState {
    /// The state of a path outside every detected provider root.
    #[must_use]
    pub fn not_synced() -> Self {
        Self {
            provider: None,
            residency: Residency::NotSynced,
            retention: Retention::Unspecified,
        }
    }
}

/// How a provider root came to be where it is.
///
/// Recorded because it changes what the path means to the user. A redirected
/// home directory is the case people are most often surprised by: their Desktop
/// is in iCloud and they never consciously put it there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootOrigin {
    /// The provider's own mount point.
    ProviderMount,
    /// A per-application storage container inside a provider mount.
    AppContainer,
    /// The provider's own deleted-items area.
    ///
    /// Kept rather than skipped: deleted files still occupy the user's quota
    /// until the provider expires them, so leaving this out would understate
    /// what is actually consuming their storage (DR-16).
    ProviderTrash,
    /// A home directory the provider redirected into itself.
    HomeRedirect,
    /// A location a previous version of the provider's client used.
    LegacyLocation,
}

/// What the provider itself says about a link out of its directory.
///
/// Read before the user is ever asked (DR-22). Both platforms leave evidence,
/// and it settles most links outright; `docs/VERIFICATION.md` records what each
/// signal is and how it was confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkVerdict {
    /// The provider explicitly excludes this link from synchronization.
    ///
    /// Conclusive: the target is **not** backed up by this provider, whatever
    /// its position in the directory tree suggests. On macOS this is the
    /// `com.apple.fileprovider.ignore` attribute that iCloud leaves on a link to
    /// a folder it has detached.
    ExcludedByProvider,
    /// The target carries the provider's own working state.
    ///
    /// The link is the provider's own, and its target genuinely holds that
    /// provider's content — Google Drive in mirror mode points out of its
    /// streaming directory exactly this way.
    ProviderOwned,
    /// Neither platform nor provider said anything. Only the user can settle it.
    Unsettled,
}

/// A symbolic link leading out of a provider directory.
///
/// The same shape means opposite things, which is why the verdict is carried
/// alongside rather than baked into a boolean: a link out of iCloud Drive to an
/// unsynchronized Desktop, and a link out of a Google Drive mount to that
/// drive's own content, look identical. Following the first would falsely report
/// unsynchronized files as backed up; ignoring the second would silently omit an
/// entire drive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderLink {
    /// The link itself, inside a provider directory.
    pub link: PathBuf,
    /// Where it points, made absolute.
    pub target: PathBuf,
    /// The provider whose directory contains the link.
    pub provider: Provider,
    /// What the provider said about it.
    pub verdict: LinkVerdict,
}

/// A directory owned by a sync provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudRoot {
    /// Where it is.
    pub path: PathBuf,
    /// Who owns it.
    pub provider: Provider,
    /// The account or container label the provider gave it, verbatim.
    ///
    /// Often carries an email address, because that is what the provider named
    /// the directory. It is recorded because it is the only way to tell two
    /// accounts of the same provider apart, and it stays local like everything
    /// else the scanner writes.
    pub account: Option<String>,
    /// How it came to be here.
    pub origin: RootOrigin,
}

/// What a platform scan found: the providers on a machine, and the links out of
/// them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Directories owned by a sync provider.
    pub roots: Vec<CloudRoot>,
    /// Links leading out of those directories.
    pub links: Vec<ProviderLink>,
}

/// Every provider root on a machine, arranged for lookup.
#[derive(Clone, Debug, Default)]
pub struct CloudMap {
    roots: Vec<CloudRoot>,
    links: Vec<ProviderLink>,
}

impl CloudMap {
    /// Builds a map from what a scan detected.
    #[must_use]
    pub fn from_detection(detection: Detection) -> Self {
        Self::from_roots(detection.roots).with_links(detection.links)
    }

    /// Builds a map from a known set of roots.
    ///
    /// Used by tests and by the merge stage, which reconstructs another
    /// machine's map out of that machine's artifact.
    #[must_use]
    pub fn from_roots(mut roots: Vec<CloudRoot>) -> Self {
        // Longest path first, so `owner_of` can return the first match and get
        // the most specific root: an application container inside iCloud Drive
        // must win over iCloud Drive itself.
        roots.sort_by(|left, right| {
            right
                .path
                .as_os_str()
                .len()
                .cmp(&left.path.as_os_str().len())
                .then_with(|| left.path.cmp(&right.path))
        });
        Self {
            roots,
            links: Vec::new(),
        }
    }

    /// Records links, keeping only those that genuinely lead outside.
    ///
    /// A link pointing from one provider directory into another is ordinary
    /// internal plumbing and settles itself — Google Drive resolves every
    /// shortcut this way, into a hidden directory inside the same drive.
    /// Traversal reaches those targets once on its own, so recording the links
    /// as questions would be noise, and following them would count the same
    /// bytes once per shortcut (DR-16).
    #[must_use]
    pub fn with_links(mut self, links: Vec<ProviderLink>) -> Self {
        self.links = links
            .into_iter()
            .filter(|link| self.owner_of(&link.target).is_none())
            .collect();
        self
    }

    /// The detected roots, most specific first.
    #[must_use]
    pub fn roots(&self) -> &[CloudRoot] {
        &self.roots
    }

    /// Every link leading out of a provider directory, with its verdict.
    #[must_use]
    pub fn links(&self) -> &[ProviderLink] {
        &self.links
    }

    /// Links the provider itself excluded from synchronization.
    ///
    /// Worth surfacing prominently: each one is a folder the user very likely
    /// believes is in the cloud, sitting inside the cloud directory, that the
    /// provider is not backing up.
    pub fn excluded_links(&self) -> impl Iterator<Item = &ProviderLink> {
        self.links
            .iter()
            .filter(|link| link.verdict == LinkVerdict::ExcludedByProvider)
    }

    /// Links no signal could settle, which only the user can answer (DR-22).
    pub fn unsettled_links(&self) -> impl Iterator<Item = &ProviderLink> {
        self.links
            .iter()
            .filter(|link| link.verdict == LinkVerdict::Unsettled)
    }

    /// The most specific root containing `path`, if any.
    #[must_use]
    pub fn owner_of(&self, path: &Path) -> Option<&CloudRoot> {
        self.roots.iter().find(|root| path.starts_with(&root.path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(path: &str, provider: Provider, origin: RootOrigin) -> CloudRoot {
        CloudRoot {
            path: PathBuf::from(path),
            provider,
            account: None,
            origin,
        }
    }

    fn sample_map() -> CloudMap {
        CloudMap::from_roots(vec![
            root(
                "/home/Library/Mobile Documents/com~apple~CloudDocs",
                Provider::ICloud,
                RootOrigin::ProviderMount,
            ),
            root(
                "/home/Library/Mobile Documents/com~apple~CloudDocs/Desktop",
                Provider::ICloud,
                RootOrigin::HomeRedirect,
            ),
            root(
                "/home/Library/CloudStorage/GoogleDrive-someone@example.com",
                Provider::GoogleDrive,
                RootOrigin::ProviderMount,
            ),
        ])
    }

    fn link(from: &str, to: &str, verdict: LinkVerdict) -> ProviderLink {
        ProviderLink {
            link: PathBuf::from(from),
            target: PathBuf::from(to),
            provider: Provider::ICloud,
            verdict,
        }
    }

    #[test]
    fn a_path_outside_every_root_is_not_synced() {
        assert!(
            sample_map()
                .owner_of(Path::new("/home/Projects/notes.txt"))
                .is_none()
        );
    }

    #[test]
    fn the_most_specific_root_wins() {
        // The failure this guards: reporting a redirected Desktop as plain
        // iCloud Drive, which loses the very fact the user most needs to know —
        // that their Desktop is being synchronized at all.
        let map = sample_map();
        let owner = map
            .owner_of(Path::new(
                "/home/Library/Mobile Documents/com~apple~CloudDocs/Desktop/budget.numbers",
            ))
            .expect("path lies inside a known root");
        assert_eq!(owner.origin, RootOrigin::HomeRedirect);
    }

    #[test]
    fn the_containing_root_is_found_for_a_deep_path() {
        let map = sample_map();
        let owner = map
            .owner_of(Path::new(
                "/home/Library/CloudStorage/GoogleDrive-someone@example.com/a/b/c/d.pdf",
            ))
            .expect("path lies inside a known root");
        assert_eq!(owner.provider, Provider::GoogleDrive);
    }

    #[test]
    fn a_sibling_with_a_shared_prefix_is_not_matched() {
        // `starts_with` on paths compares components, so a directory named
        // `CloudDocs-backup` must not be mistaken for one inside `CloudDocs`.
        assert!(
            sample_map()
                .owner_of(Path::new(
                    "/home/Library/Mobile Documents/com~apple~CloudDocs-backup/file.txt"
                ))
                .is_none()
        );
    }

    #[test]
    fn a_link_leading_outside_every_provider_is_kept() {
        // The observed case: iCloud Drive holds a link out to a Desktop that is
        // not synchronized. Following it would report those files as backed up,
        // and losing them would lose them for good.
        let map = sample_map().with_links(vec![link(
            "/home/Library/Mobile Documents/com~apple~CloudDocs/Desktop",
            "/home/Desktop",
            LinkVerdict::Unsettled,
        )]);
        assert_eq!(map.unsettled_links().count(), 1);
        assert_eq!(map.links()[0].target, PathBuf::from("/home/Desktop"));
    }

    #[test]
    fn a_link_leading_into_another_provider_directory_settles_itself() {
        // Ordinary plumbing between two mounts, and how Google Drive resolves
        // every shortcut. Asking the user about it would be noise, and noise is
        // what makes people stop reading the questions.
        let map = sample_map().with_links(vec![link(
            "/home/Library/Mobile Documents/com~apple~CloudDocs/shared",
            "/home/Library/CloudStorage/GoogleDrive-someone@example.com/shared",
            LinkVerdict::Unsettled,
        )]);
        assert!(map.links().is_empty());
    }

    #[test]
    fn a_map_with_no_links_reports_none() {
        assert!(sample_map().links().is_empty());
    }

    #[test]
    fn an_excluded_link_is_separated_from_an_unsettled_one() {
        // These two need different treatment: the first is a finding to show the
        // user ("this folder is not backed up"), the second is a question to ask
        // them. Merging them would either alarm people about ordinary plumbing
        // or bury a real gap among questions.
        let map = sample_map().with_links(vec![
            link(
                "/home/Library/Mobile Documents/com~apple~CloudDocs/Documents",
                "/home/Documents",
                LinkVerdict::ExcludedByProvider,
            ),
            link(
                "/home/Library/CloudStorage/GoogleDrive-someone@example.com/My Drive",
                "/home/My Drive",
                LinkVerdict::ProviderOwned,
            ),
            link(
                "/home/Library/Mobile Documents/com~apple~CloudDocs/mystery",
                "/home/mystery",
                LinkVerdict::Unsettled,
            ),
        ]);

        assert_eq!(map.excluded_links().count(), 1);
        assert_eq!(map.unsettled_links().count(), 1);
        assert_eq!(map.links().len(), 3);
    }

    #[test]
    fn unknown_residency_is_treated_as_downloadable() {
        // DR-15: when we cannot establish a fact, we take the cautious reading.
        // Getting this backwards means downloading someone's archive by accident.
        assert!(Residency::Unknown.read_may_download());
        assert!(Residency::Remote.read_may_download());
        assert!(Residency::Partial.read_may_download());
        assert!(!Residency::Local.read_may_download());
        assert!(!Residency::NotSynced.read_may_download());
    }

    #[test]
    fn a_detection_survives_a_json_round_trip() {
        // The merge stage rebuilds another machine's map out of its artifact, so
        // this vocabulary has to survive the trip through a file intact.
        let original = Detection {
            roots: vec![root(
                "/home/Library/CloudStorage/GoogleDrive-someone@example.com",
                Provider::GoogleDrive,
                RootOrigin::ProviderMount,
            )],
            links: vec![link(
                "/home/Library/CloudStorage/GoogleDrive-someone@example.com/My Drive",
                "/home/My Drive",
                LinkVerdict::ProviderOwned,
            )],
        };
        let encoded = serde_json::to_string(&original).expect("detection must serialize");
        let decoded: Detection =
            serde_json::from_str(&encoded).expect("detection must deserialize");
        assert_eq!(original, decoded);
    }
}
