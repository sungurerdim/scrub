//! Where the space went, and what it went on.
//!
//! The question this answers is the one somebody actually opens a tool like
//! this to ask: *my disk is full and I do not know why.* Counting files does not
//! answer it. Naming the four folders holding ninety per cent of the space does.
//!
//! Everything here is arithmetic over what the scan already recorded. No file is
//! opened, nothing is inferred from content, and no model is consulted — which
//! is also why the one uncertain thing is labelled as uncertain.
//!
//! **A file's kind comes from its name, and that is said out loud.** A `.pdf`
//! that is really a video is filed under documents, because the only thing that
//! would settle it is reading two million files, and reading them would download
//! the ones that live in the cloud. What this produces is a good enough map to
//! decide where to look, not a claim about any particular file (DR-15).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cloud::Residency;
use crate::inventory::{Entry, EntryKind};

/// The kind of thing a file appears to be, judged by its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Photographs and other images.
    Images,
    /// Films and recordings.
    Video,
    /// Music, voice notes, anything heard.
    Audio,
    /// Letters, spreadsheets, presentations, anything read.
    Documents,
    /// Things somebody wrote to be run.
    Code,
    /// Structured data: databases, exports, logs.
    Data,
    /// Things holding other things.
    Archives,
    /// Programs and the pieces they are made of.
    Applications,
    /// Files a person did not put there and should not move.
    ///
    /// Kept apart from everything else on purpose: a cleaning tool that
    /// cheerfully offers to tidy a settings folder is a cleaning tool that
    /// breaks something.
    System,
    /// Everything with a name that says nothing.
    Other,
}

impl Category {
    /// A plain name, for showing.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Images => "images",
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Documents => "documents",
            Self::Code => "code",
            Self::Data => "data",
            Self::Archives => "archives",
            Self::Applications => "applications",
            Self::System => "system files",
            Self::Other => "everything else",
        }
    }

    /// Whether this is somebody's own material, rather than the machine's.
    ///
    /// What separates "you have 40 GB of video" from "your Mac has 40 GB of
    /// libraries", which are different sentences with different answers.
    #[must_use]
    pub fn is_personal(self) -> bool {
        !matches!(self, Self::System | Self::Applications)
    }
}

/// Extensions that say what a file is, lower-cased, without the dot.
///
/// A table rather than a clever rule. Every entry here was put there because
/// somebody's disk has them on it, and a list that can be read and corrected is
/// worth more than a heuristic that cannot.
const KNOWN: &[(Category, &[&str])] = &[
    (
        Category::Images,
        &[
            "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "avif",
            "svg", "raw", "cr2", "cr3", "nef", "arw", "dng", "orf", "rw2", "psd", "ai", "eps",
            "ico", "icns",
        ],
    ),
    (
        Category::Video,
        &[
            "mp4",
            "mov",
            "avi",
            "mkv",
            "wmv",
            "flv",
            "webm",
            "m4v",
            "mpg",
            "mpeg",
            "3gp",
            "mts",
            "m2ts",
            "vob",
            "prproj",
            "fcpbundle",
        ],
    ),
    (
        Category::Audio,
        &[
            "mp3", "wav", "flac", "aac", "m4a", "ogg", "opus", "wma", "aiff", "aif", "alac",
            "logicx", "band",
        ],
    ),
    (
        Category::Documents,
        &[
            "pdf", "doc", "docx", "odt", "rtf", "txt", "md", "pages", "xls", "xlsx", "ods",
            "numbers", "ppt", "pptx", "odp", "key", "epub", "mobi", "azw3", "djvu", "tex",
        ],
    ),
    (
        Category::Code,
        &[
            "rs", "py", "js", "ts", "tsx", "jsx", "go", "java", "kt", "swift", "c", "h", "cpp",
            "hpp", "cs", "rb", "php", "sh", "zsh", "bash", "lua", "pl", "r", "scala", "dart",
            "vue", "html", "css", "scss", "sql", "ipynb",
        ],
    ),
    (
        Category::Data,
        &[
            "json",
            "xml",
            "yaml",
            "yml",
            "toml",
            "csv",
            "tsv",
            "db",
            "sqlite",
            "sqlite3",
            "parquet",
            "log",
            "plist",
            "ndjson",
            "jsonl",
            "avro",
            "arrow",
            "feather",
            "pkl",
            "pickle",
            "npy",
            "npz",
            "h5",
            "hdf5",
            "mat",
            "bin",
            "msgpack",
            // Model weights. Big, produced by a program rather than by a person,
            // and on a machine that has any of them they are usually the largest
            // thing on it — which makes leaving them unnamed the least useful
            // answer a survey could give.
            "gguf",
            "safetensors",
            "onnx",
            "pt",
            "pth",
            "ckpt",
            "pb",
            "tflite",
            "mlmodel",
            "mlpackage",
        ],
    ),
    (
        Category::Archives,
        &[
            "zip",
            "tar",
            "gz",
            "bz2",
            "xz",
            "7z",
            "rar",
            "tgz",
            "zst",
            "dmg",
            "iso",
            "pkg",
            "sparsebundle",
            "sparseimage",
        ],
    ),
    (
        Category::Applications,
        &[
            "app",
            "exe",
            "msi",
            "deb",
            "rpm",
            "appimage",
            "dll",
            "so",
            "dylib",
            "framework",
            "bundle",
            "jar",
            "wasm",
            "o",
            "a",
            "rlib",
        ],
    ),
    (
        Category::System,
        &[
            "sys",
            "tmp",
            "temp",
            "cache",
            "lock",
            "pid",
            "swp",
            "ds_store",
            "localized",
            "download",
            "part",
            "crdownload",
        ],
    ),
];

/// Directory names whose contents belong to the machine rather than to a person.
///
/// Judged by where a file lives rather than by what it is called, because a
/// `.png` inside an application's support folder is that application's business.
const MACHINE_PLACES: &[&str] = &[
    "Library",
    "System",
    "Applications",
    "node_modules",
    "target",
    ".git",
    ".cache",
    "AppData",
    "ProgramData",
    "Windows",
    "Program Files",
    "__pycache__",
    ".venv",
    "vendor",
    "DerivedData",
];

/// What a file appears to be, judged by its name and where it sits.
///
/// The location is consulted first: something inside a program's own folder is
/// that program's, whatever it is called.
#[must_use]
pub fn category_of(path: &Path) -> Category {
    if in_a_machine_place(path) {
        return Category::System;
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Category::Other;
    };

    // A name that is nothing but a dot-suffix — `.gitignore`, `.DS_Store` — is
    // configuration, not a document called "gitignore".
    if name.starts_with('.') && name.matches('.').count() == 1 {
        return Category::System;
    }

    let Some(extension) = path
        .extension()
        .and_then(|found| found.to_str())
        .map(str::to_ascii_lowercase)
    else {
        return Category::Other;
    };

    for (category, extensions) in KNOWN {
        if extensions.contains(&extension.as_str()) {
            return *category;
        }
    }
    Category::Other
}

fn in_a_machine_place(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| MACHINE_PLACES.contains(&name))
    })
}

/// How much of something there is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Weight {
    /// How many files.
    pub files: usize,
    /// How much space they take on this disk.
    pub bytes: u64,
}

impl Weight {
    fn add(&mut self, bytes: u64) {
        self.files += 1;
        self.bytes += bytes;
    }
}

/// One folder and everything below it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    /// Where it is.
    pub path: PathBuf,
    /// What it holds, counting everything nested inside.
    pub weight: Weight,
}

/// One file worth naming.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Large {
    /// Which entry of the inventory.
    pub entry: usize,
    /// Where it is.
    pub path: PathBuf,
    /// How much space it takes.
    pub bytes: u64,
    /// Whether its content is on this disk.
    pub local: bool,
    /// What it appears to be.
    pub category: Category,
}

/// The whole picture, in the terms somebody decides on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Survey {
    /// Everything, counted.
    pub everything: Weight,
    /// What is on this disk.
    pub here: Weight,
    /// What is in the cloud and not on this disk.
    ///
    /// Kept apart from the figure above, because "you have 400 GB of photos" and
    /// "400 GB of photos exist and 4 GB of them are on this machine" are
    /// different sentences, and only the second one is true (DR-16).
    pub in_the_cloud: Weight,
    /// What kind of things there are, largest first.
    pub kinds: Vec<(Category, Weight)>,
    /// The folders holding the most, largest first.
    pub folders: Vec<Folder>,
    /// The largest files, largest first.
    pub largest: Vec<Large>,
}

/// How many folders and files a survey names.
///
/// Enough to find where the space went, few enough to read in one sitting. A
/// list of a thousand is a list nobody looks at (DR-21).
const WORTH_NAMING: usize = 40;

/// Looks over everything a scan found.
///
/// Nothing is opened. This is arithmetic over what was already recorded, which
/// is why it can be run over two and a half million entries without touching a
/// disk (DR-11).
#[must_use]
pub fn survey(entries: &[Entry]) -> Survey {
    survey_naming(entries, WORTH_NAMING)
}

/// The same, with the length of the lists chosen.
#[must_use]
pub fn survey_naming(entries: &[Entry], worth_naming: usize) -> Survey {
    let mut found = Survey::default();
    let mut kinds: HashMap<Category, Weight> = HashMap::new();
    let mut folders: HashMap<&Path, Weight> = HashMap::new();
    let mut largest: Vec<Large> = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        if entry.kind != EntryKind::File {
            continue;
        }

        let category = category_of(&entry.path);
        let local = !matches!(
            entry.cloud.residency,
            Residency::Remote | Residency::Partial
        );

        // Two different questions, so two different numbers. A file that is here
        // takes up what the filesystem allocated for it. A file that is in the
        // cloud occupies no blocks at all — reporting that as its size would say
        // somebody has nothing in the cloud, when what they have is the amount it
        // would take to bring it down (DR-16).
        let bytes = if local {
            entry.allocated_size.unwrap_or(entry.logical_size)
        } else {
            entry.logical_size
        };

        found.everything.add(bytes);
        if local {
            found.here.add(bytes);
        } else {
            found.in_the_cloud.add(bytes);
        }
        kinds.entry(category).or_default().add(bytes);

        // Every folder above it holds it too. That is what makes the answer
        // useful: the folder somebody recognises is rarely the one the file is
        // directly in.
        for ancestor in entry.path.ancestors().skip(1) {
            folders.entry(ancestor).or_default().add(bytes);
        }

        largest.push(Large {
            entry: index,
            path: entry.path.clone(),
            bytes,
            local,
            category,
        });
    }

    found.kinds = kinds.into_iter().collect();
    found.kinds.sort_by(|left, right| {
        right
            .1
            .bytes
            .cmp(&left.1.bytes)
            .then_with(|| left.0.cmp(&right.0))
    });

    let mut ranked: Vec<Folder> = folders
        .into_iter()
        .map(|(path, weight)| Folder {
            path: path.to_path_buf(),
            weight,
        })
        .collect();
    ranked.sort_by(|left, right| {
        right
            .weight
            .bytes
            .cmp(&left.weight.bytes)
            // Deepest first among equals, so that a folder is considered before
            // the folder above it. The rule below drops a parent explained by a
            // child it has already kept, and it can only do that if the child
            // came first.
            .then_with(|| {
                right
                    .path
                    .components()
                    .count()
                    .cmp(&left.path.components().count())
            })
            .then_with(|| left.path.cmp(&right.path))
    });
    found.folders = worth_showing(&ranked, worth_naming);

    largest.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.path.cmp(&right.path))
    });
    largest.truncate(worth_naming);
    found.largest = largest;

    found
}

/// Drops a folder whose weight is entirely explained by one folder inside it.
///
/// Without this, the list is `/`, `/Users/me`, `/Users/me/projects`,
/// `/Users/me/projects/one`, all with nearly the same number — four rows saying
/// one thing, and the one thing is the last row. Keeping a folder only when it
/// holds meaningfully more than its largest child leaves the folders where the
/// space actually divides, which are the ones somebody would go and look at.
///
/// Judged against every folder rather than against the ones already kept. A
/// parent always weighs at least as much as its child and so always comes first
/// in the ranking; a rule that only looked at what it had kept so far would
/// therefore never see the child that explains it.
fn worth_showing(ranked: &[Folder], keep: usize) -> Vec<Folder> {
    // A folder is kept when it holds at least a seventh more than the largest
    // folder inside it. Below that, the child is the better answer to "where is
    // it".
    //
    // Integer arithmetic, and saturating, because a byte count is a byte count:
    // a figure that drifted by a rounding error would be a figure somebody
    // could not check against their file browser (DR-16).
    const MORE: u64 = 115;
    const THAN: u64 = 100;

    let mut largest_child: HashMap<&Path, u64> = HashMap::new();
    for folder in ranked {
        if let Some(parent) = folder.path.parent() {
            let seen = largest_child.entry(parent).or_default();
            *seen = (*seen).max(folder.weight.bytes);
        }
    }

    ranked
        .iter()
        .filter(|folder| {
            let inside = largest_child
                .get(folder.path.as_path())
                .copied()
                .unwrap_or(0);
            folder.weight.bytes.saturating_mul(THAN) > inside.saturating_mul(MORE)
        })
        .take(keep)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::{CloudState, Retention};

    fn file(path: &str, bytes: u64) -> Entry {
        Entry {
            path: PathBuf::from(path),
            kind: EntryKind::File,
            logical_size: bytes,
            allocated_size: Some(bytes),
            created: None,
            modified: None,
            file_id: None,
            link_count: 1,
            link_target: None,
            cloud: CloudState::not_synced(),
        }
    }

    fn in_the_cloud(path: &str, bytes: u64) -> Entry {
        let mut entry = file(path, bytes);
        entry.cloud = CloudState {
            provider: None,
            residency: Residency::Remote,
            retention: Retention::Unspecified,
        };
        entry
    }

    #[test]
    fn a_file_is_judged_by_its_name_and_by_where_it_sits() {
        assert_eq!(
            category_of(Path::new("/home/a/holiday.JPG")),
            Category::Images
        );
        assert_eq!(
            category_of(Path::new("/home/a/tax.pdf")),
            Category::Documents
        );
        assert_eq!(category_of(Path::new("/home/a/film.mkv")), Category::Video);
        assert_eq!(category_of(Path::new("/home/a/notes")), Category::Other);

        // Where it sits wins. An image inside an application's own folder is
        // that application's business, not a photograph somebody took.
        assert_eq!(
            category_of(Path::new("/Users/a/Library/Caches/thumb.png")),
            Category::System,
            "a machine place makes it the machine's, whatever it is called"
        );
        assert_eq!(
            category_of(Path::new("/home/a/project/node_modules/logo.svg")),
            Category::System
        );
        assert_eq!(
            category_of(Path::new("/home/a/.gitignore")),
            Category::System
        );
    }

    #[test]
    fn the_biggest_things_on_a_working_machine_are_not_filed_under_unknown() {
        // Model weights and data exports are what actually fills a developer's
        // disk, and a survey that files thirty gigabytes of them under
        // "everything else" has answered nothing. Found by running the survey
        // against a real machine and reading what the unnamed bucket held.
        for (name, expected) in [
            ("model.gguf", Category::Data),
            ("weights.safetensors", Category::Data),
            ("checkpoint.pt", Category::Data),
            ("frame.pkl", Category::Data),
            ("export.jsonl", Category::Data),
            ("features.npz", Category::Data),
            ("table.parquet", Category::Data),
        ] {
            assert_eq!(
                category_of(Path::new(&format!("/home/a/{name}"))),
                expected,
                "{name} should be named rather than shrugged at"
            );
        }
    }

    #[test]
    fn what_is_in_the_cloud_is_counted_apart_from_what_is_here() {
        // DR-16. Adding the two together produces a number that is true of
        // nothing: not of the disk, and not of what somebody can open today.
        let entries = vec![
            file("/home/a/here.mov", 1_000),
            in_the_cloud("/home/a/away.mov", 9_000),
        ];

        let found = survey(&entries);
        assert_eq!(found.everything.bytes, 10_000);
        assert_eq!(found.here.bytes, 1_000);
        assert_eq!(found.in_the_cloud.bytes, 9_000);
        assert_eq!(found.in_the_cloud.files, 1);
    }

    #[test]
    fn the_kinds_are_ordered_by_what_they_take_up() {
        let entries = vec![
            file("/home/a/one.pdf", 100),
            file("/home/a/two.mov", 5_000),
            file("/home/a/three.jpg", 900),
        ];

        let found = survey(&entries);
        let order: Vec<Category> = found.kinds.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(
            order,
            vec![Category::Video, Category::Images, Category::Documents],
            "largest first, because that is the order somebody would act in"
        );
    }

    #[test]
    fn a_folder_is_credited_with_everything_below_it() {
        let entries = vec![
            file("/home/a/photos/2024/one.jpg", 100),
            file("/home/a/photos/2025/two.jpg", 300),
        ];

        let found = survey(&entries);
        let photos = found
            .folders
            .iter()
            .find(|folder| folder.path == Path::new("/home/a/photos"))
            .expect("the folder holding both");
        assert_eq!(photos.weight.bytes, 400);
        assert_eq!(photos.weight.files, 2);
    }

    #[test]
    fn a_chain_of_folders_holding_the_same_thing_is_shown_once() {
        // The failure this prevents: `/`, `/home`, `/home/a`, `/home/a/films`
        // all reporting 40 GB, which is four rows saying one thing. The last one
        // is the answer; the rest are the road to it.
        let entries = vec![file("/home/a/films/big.mkv", 40_000)];

        let found = survey(&entries);
        assert_eq!(
            found.folders.len(),
            1,
            "only the folder where the space actually is: {:?}",
            found.folders.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert_eq!(found.folders[0].path, Path::new("/home/a/films"));
    }

    #[test]
    fn a_parent_barely_heavier_than_its_child_is_dropped() {
        // Found on a real machine, where the list read:
        //   108.7 GB  .../trade_strategy_comparison
        //   107.2 GB  .../trade_strategy_comparison/data
        //   107.2 GB  .../trade_strategy_comparison/data/lab
        // Three rows and one fact. The earlier rule only compared a folder with
        // the ones already kept, and a parent always outweighs its child and so
        // always comes first — so it never saw the child that explained it.
        let entries = vec![
            file("/home/a/work/data/lab/one.csv", 107_000),
            file("/home/a/work/loose.txt", 1_700),
        ];

        let found = survey(&entries);
        let named: Vec<&str> = found
            .folders
            .iter()
            .map(|folder| folder.path.to_str().expect("a path"))
            .collect();

        assert!(
            named.contains(&"/home/a/work/data/lab"),
            "the folder where the space actually is: {named:?}"
        );
        assert!(
            !named.contains(&"/home/a/work/data"),
            "and not the one that only passes it through: {named:?}"
        );
        assert!(
            !named.contains(&"/home/a/work"),
            "nor the one barely heavier than it: {named:?}"
        );
    }

    #[test]
    fn a_file_in_the_cloud_is_weighed_by_what_it_would_take_to_bring_down() {
        // Found on a real machine, where the survey said "0 bytes in the cloud,
        // across 110 files". A file that is not here occupies no blocks, so its
        // allocated size is zero; the number somebody wants is how much it
        // would take if they asked for it.
        let mut away = in_the_cloud("/home/a/holiday.mov", 8_000);
        away.allocated_size = Some(0);

        let found = survey(&[away]);
        assert_eq!(found.in_the_cloud.files, 1);
        assert_eq!(
            found.in_the_cloud.bytes, 8_000,
            "reporting nothing would say they have nothing in the cloud"
        );
        assert_eq!(found.here.bytes, 0, "and none of it is on this disk");
    }

    #[test]
    fn a_folder_holding_meaningfully_more_than_its_child_is_kept() {
        // The other half of the same rule. A folder that divides between two
        // children is where somebody would look, so it stays.
        let entries = vec![
            file("/home/a/films/one.mkv", 10_000),
            file("/home/a/music/two.flac", 10_000),
        ];

        let found = survey(&entries);
        let named: Vec<&Path> = found
            .folders
            .iter()
            .map(|folder| folder.path.as_path())
            .collect();
        assert!(
            named.contains(&Path::new("/home/a")),
            "the folder the space divides at is worth naming: {named:?}"
        );
    }

    #[test]
    fn the_largest_files_are_named_with_what_they_are_and_whether_they_are_here() {
        let entries = vec![
            file("/home/a/small.txt", 10),
            in_the_cloud("/home/a/huge.mov", 90_000),
        ];

        let found = survey_naming(&entries, 1);
        assert_eq!(found.largest.len(), 1);
        assert_eq!(found.largest[0].path, Path::new("/home/a/huge.mov"));
        assert_eq!(found.largest[0].category, Category::Video);
        assert!(
            !found.largest[0].local,
            "so nobody sets aside a file that is not on this disk expecting space back"
        );
    }

    #[test]
    fn folders_and_links_are_not_counted_as_files() {
        // A directory's own reported size is the space its listing takes, not
        // its contents; adding it would count the same bytes twice.
        let mut folder = file("/home/a/photos", 4_096);
        folder.kind = EntryKind::Directory;
        let mut link = file("/home/a/shortcut", 12);
        link.kind = EntryKind::Symlink;

        let found = survey(&[folder, link, file("/home/a/photos/one.jpg", 100)]);
        assert_eq!(found.everything.files, 1);
        assert_eq!(found.everything.bytes, 100);
    }

    #[test]
    fn a_survey_of_nothing_says_nothing_rather_than_failing() {
        let found = survey(&[]);
        assert_eq!(found.everything, Weight::default());
        assert!(found.kinds.is_empty());
        assert!(found.folders.is_empty());
        assert!(found.largest.is_empty());
    }

    #[test]
    fn what_belongs_to_a_person_is_separable_from_what_belongs_to_the_machine() {
        assert!(Category::Images.is_personal());
        assert!(Category::Documents.is_personal());
        assert!(!Category::System.is_personal());
        assert!(
            !Category::Applications.is_personal(),
            "a tool that offers to tidy a program's own files breaks the program"
        );
    }
}
