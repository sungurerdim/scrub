//! Artifact headers and the chain-integrity rules of DR-18.
//!
//! Every pipeline stage writes exactly one artifact, and every artifact records
//! where it came from. A stage refuses to run on an input whose chain does not
//! line up: a plan built from a different scan, a plan built for a different
//! machine, or a plan written by an incompatible schema. These are hard errors,
//! never warnings, because applying the right plan to the wrong machine must be
//! unreachable rather than merely discouraged.

use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The artifact schema this build reads and writes.
///
/// Bumped whenever the on-disk shape of any artifact changes in a way an older
/// build could misread. Artifacts declaring a different value are rejected
/// rather than interpreted.
pub const SCHEMA_VERSION: u32 = 1;

/// A BLAKE3-256 digest.
///
/// Used both for file content identity (DR-13) and for artifact chain identity
/// (DR-18). BLAKE3 is used everywhere rather than a provider-supplied checksum:
/// provider checksums may narrow a set of candidates but never conclude that two
/// files are the same file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest([u8; 32]);

impl Digest {
    /// Digests a byte slice.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// The digest as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Parses a lowercase hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::MalformedDigest`] if the input is not exactly 64
    /// hexadecimal characters.
    pub fn from_hex(text: &str) -> Result<Self, ChainError> {
        if text.len() != 64 {
            return Err(ChainError::MalformedDigest {
                found: text.to_owned(),
            });
        }
        let mut bytes = [0_u8; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let pair =
                text.get(index * 2..index * 2 + 2)
                    .ok_or_else(|| ChainError::MalformedDigest {
                        found: text.to_owned(),
                    })?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| ChainError::MalformedDigest {
                found: text.to_owned(),
            })?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form: enough to identify a chain link in an error message
        // without filling the terminal with hex.
        write!(formatter, "Digest({}…)", &self.to_hex()[..12])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl From<Digest> for String {
    fn from(digest: Digest) -> Self {
        digest.to_hex()
    }
}

impl TryFrom<String> for Digest {
    type Error = ChainError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::from_hex(&text)
    }
}

/// A locally generated, non-identifying machine identity.
///
/// Generated once at first run and stored in the user's configuration. It is a
/// random value: never derived from a hardware serial, a user name, a network
/// address, or anything else that identifies a person or a device to a third
/// party (DR-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(Uuid);

impl MachineId {
    /// Generates a fresh identity. Called once, at first run.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for MachineId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Which machines an artifact describes.
///
/// Most artifacts describe one machine. A merged analysis describes several,
/// and cannot be applied as a whole anywhere — each operation derived from it
/// carries its own target machine, checked separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineScope {
    /// The artifact describes exactly one machine.
    Single {
        /// The machine described.
        machine: MachineId,
    },
    /// The artifact merges observations from several machines.
    Merged {
        /// Every machine represented, in the order they were merged.
        machines: Vec<MachineId>,
    },
}

impl MachineScope {
    /// Whether this scope describes work that can execute on `local`.
    #[must_use]
    pub fn is_executable_on(&self, local: MachineId) -> bool {
        match self {
            Self::Single { machine } => *machine == local,
            // A merged scope is never executable as a whole: it necessarily
            // contains operations for machines that are not this one.
            Self::Merged { .. } => false,
        }
    }
}

/// What an artifact contains.
///
/// Distinct from [`Stage`] because two stages can produce the same kind:
/// `analyze` and `merge` both emit an [`ArtifactKind::Analysis`], and `apply`
/// and `undo` both emit an [`ArtifactKind::Journal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Filesystem metadata, collected without opening any file.
    Inventory,
    /// Identity groups, categories, and similarity, derived from an inventory.
    Analysis,
    /// Intended operations, derived from an analysis. Nothing has happened yet.
    Plan,
    /// A grade for every planned operation, produced without writing anything.
    Preflight,
    /// A record of what was executed, sufficient to reverse it.
    Journal,
}

/// A pipeline stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Walk the tree, recording metadata only.
    Scan,
    /// Establish identity, categories, and similarity.
    Analyze,
    /// Combine analyses from several machines into one view.
    Merge,
    /// Record the user's intended reorganization.
    Plan,
    /// Grade every operation without touching the filesystem.
    Preflight,
    /// Execute the operations preflight passed.
    Apply,
    /// Reverse an applied run.
    Undo,
}

impl Stage {
    /// The artifact kind this stage consumes, or `None` for the first stage.
    #[must_use]
    pub fn input_kind(self) -> Option<ArtifactKind> {
        match self {
            Self::Scan => None,
            Self::Analyze => Some(ArtifactKind::Inventory),
            Self::Merge | Self::Plan => Some(ArtifactKind::Analysis),
            Self::Preflight => Some(ArtifactKind::Plan),
            Self::Apply => Some(ArtifactKind::Preflight),
            Self::Undo => Some(ArtifactKind::Journal),
        }
    }

    /// The artifact kind this stage produces.
    #[must_use]
    pub fn output_kind(self) -> ArtifactKind {
        match self {
            Self::Scan => ArtifactKind::Inventory,
            Self::Analyze | Self::Merge => ArtifactKind::Analysis,
            Self::Plan => ArtifactKind::Plan,
            Self::Preflight => ArtifactKind::Preflight,
            Self::Apply | Self::Undo => ArtifactKind::Journal,
        }
    }

    /// Whether this stage may touch the user's filesystem.
    ///
    /// Only [`Stage::Apply`] and [`Stage::Undo`] mutate. Everything else is
    /// read-only, and [`Stage::Preflight`] is read-only by design so that
    /// verification and mutation never share a pass (DR-19).
    #[must_use]
    pub fn mutates_filesystem(self) -> bool {
        matches!(self, Self::Apply | Self::Undo)
    }

    /// How many input artifacts this stage accepts, as an inclusive range.
    ///
    /// Only [`Stage::Merge`] takes more than one; taking exactly one would make
    /// it a no-op, so its minimum is two.
    #[must_use]
    pub fn parent_arity(self) -> (usize, Option<usize>) {
        match self {
            Self::Scan => (0, Some(0)),
            Self::Merge => (2, None),
            _ => (1, Some(1)),
        }
    }
}

/// The header every artifact carries.
///
/// Written first and read before anything else, so a mismatched chain is caught
/// before a single row of the artifact body is interpreted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactHeader {
    /// The schema this artifact conforms to.
    pub schema_version: u32,
    /// The `scrub` version that produced it.
    pub tool_version: String,
    /// The stage that produced it.
    pub stage: Stage,
    /// What it contains.
    pub kind: ArtifactKind,
    /// Digests of the artifacts it was derived from.
    pub parents: Vec<Digest>,
    /// Which machines it describes.
    pub machine: MachineScope,
    /// When it was produced.
    pub created_at: Timestamp,
    /// Digest of the scan scope configuration in effect.
    pub scope_digest: Digest,
    /// Digest of this artifact's body, in canonical form.
    ///
    /// Taken over the content rather than over the file's bytes, so that two
    /// scans of an unchanged tree produce the same value on any machine and any
    /// version of the storage engine (DR-12). Children name this digest as their
    /// parent, which is what makes the chain check meaningful; it covers the body
    /// only, since a digest cannot cover the field holding it.
    pub content_digest: Digest,
}

/// An input artifact offered to a stage, paired with its own digest.
#[derive(Clone, Debug)]
pub struct ParentRef {
    /// The digest of the parent artifact file, as computed by the reader.
    pub digest: Digest,
    /// The parent's header.
    pub header: ArtifactHeader,
}

/// A refusal to run, because the chain does not line up (DR-18).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    /// The artifact was written by an incompatible schema.
    #[error(
        "artifact declares schema version {found}, this build implements {expected}. \
         Re-run the stage that produced it with this build."
    )]
    SchemaMismatch {
        /// The version this build implements.
        expected: u32,
        /// The version the artifact declares.
        found: u32,
    },

    /// The stage was handed the wrong kind of artifact.
    #[error("stage {stage:?} consumes a {expected:?} artifact, but was given a {found:?} artifact")]
    WrongInputKind {
        /// The stage that refused.
        stage: Stage,
        /// The kind it expects.
        expected: ArtifactKind,
        /// The kind it received.
        found: ArtifactKind,
    },

    /// The stage was handed the wrong number of inputs.
    #[error(
        "stage {stage:?} accepts {min} or more input artifacts{max_note}, but {found} were given"
    )]
    WrongParentCount {
        /// The stage that refused.
        stage: Stage,
        /// Minimum accepted.
        min: usize,
        /// A rendered note about the maximum, empty when unbounded.
        max_note: String,
        /// How many were given.
        found: usize,
    },

    /// The header names ancestors that are not the artifacts supplied.
    #[error(
        "this artifact was derived from {expected}, but {found} was supplied. \
         The chain is broken: re-run the intermediate stages."
    )]
    ParentDigestMismatch {
        /// The digest the header names.
        expected: Digest,
        /// The digest of the artifact actually supplied.
        found: Digest,
    },

    /// The artifact targets a machine other than this one.
    #[error(
        "this artifact was produced for machine {expected}, but this machine is {found}. \
         Run it on the machine it was made for."
    )]
    ForeignMachine {
        /// The machine the artifact targets.
        expected: MachineId,
        /// This machine.
        found: MachineId,
    },

    /// A merged artifact cannot be executed as a whole.
    #[error(
        "this artifact merges {count} machines and cannot be applied directly. \
         Produce a plan for a single machine first."
    )]
    MergedScopeNotExecutable {
        /// How many machines it merges.
        count: usize,
    },

    /// A digest field was not 64 hexadecimal characters.
    #[error("expected a 64-character hexadecimal BLAKE3 digest, got {found:?}")]
    MalformedDigest {
        /// The text that failed to parse.
        found: String,
    },
}

/// Verifies that `header` may legitimately be produced from `parents`.
///
/// This is the gate every stage passes through before reading a single row of
/// its input. It checks the schema, the input kind, the number of inputs, and
/// that the ancestors named in the header are exactly the artifacts supplied.
///
/// # Errors
///
/// Returns the specific [`ChainError`] describing why the chain was refused.
pub fn verify_chain(header: &ArtifactHeader, parents: &[ParentRef]) -> Result<(), ChainError> {
    if header.schema_version != SCHEMA_VERSION {
        return Err(ChainError::SchemaMismatch {
            expected: SCHEMA_VERSION,
            found: header.schema_version,
        });
    }

    let stage = header.stage;
    let (min, max) = stage.parent_arity();
    let count_ok = parents.len() >= min && max.is_none_or(|max| parents.len() <= max);
    if !count_ok {
        return Err(ChainError::WrongParentCount {
            stage,
            min,
            max_note: max.map_or_else(String::new, |max| format!(" and at most {max}")),
            found: parents.len(),
        });
    }

    if let Some(expected) = stage.input_kind() {
        for parent in parents {
            if parent.header.kind != expected {
                return Err(ChainError::WrongInputKind {
                    stage,
                    expected,
                    found: parent.header.kind,
                });
            }
        }
    }

    // Ancestry is compared as an ordered sequence: a merged analysis records the
    // order its inputs were combined in, and reordering them can change which
    // side wins a tie. Two merges of the same artifacts in different orders are
    // different artifacts.
    if header.parents.len() != parents.len() {
        return Err(ChainError::WrongParentCount {
            stage,
            min: header.parents.len(),
            max_note: String::new(),
            found: parents.len(),
        });
    }
    for (expected, supplied) in header.parents.iter().zip(parents) {
        if *expected != supplied.digest {
            return Err(ChainError::ParentDigestMismatch {
                expected: *expected,
                found: supplied.digest,
            });
        }
    }

    Ok(())
}

/// Verifies that an artifact may be executed on this machine.
///
/// Called by the stages that touch the filesystem, in addition to
/// [`verify_chain`]. Applying a plan built for another machine is refused here.
///
/// # Errors
///
/// Returns [`ChainError::ForeignMachine`] when the artifact targets a different
/// machine, or [`ChainError::MergedScopeNotExecutable`] when it spans several.
pub fn verify_executable_here(header: &ArtifactHeader, local: MachineId) -> Result<(), ChainError> {
    match &header.machine {
        MachineScope::Single { machine } if *machine == local => Ok(()),
        MachineScope::Single { machine } => Err(ChainError::ForeignMachine {
            expected: *machine,
            found: local,
        }),
        MachineScope::Merged { machines } => Err(ChainError::MergedScopeNotExecutable {
            count: machines.len(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: &str) -> Digest {
        Digest::of(seed.as_bytes())
    }

    fn header(stage: Stage, parents: Vec<Digest>, machine: MachineScope) -> ArtifactHeader {
        ArtifactHeader {
            schema_version: SCHEMA_VERSION,
            tool_version: "0.0.0".to_owned(),
            stage,
            kind: stage.output_kind(),
            parents,
            machine,
            created_at: Timestamp::UNIX_EPOCH,
            scope_digest: digest("scope"),
            content_digest: digest("body"),
        }
    }

    fn single(machine: MachineId) -> MachineScope {
        MachineScope::Single { machine }
    }

    fn parent_ref(stage: Stage, seed: &str, machine: MachineId) -> ParentRef {
        ParentRef {
            digest: digest(seed),
            header: header(stage, vec![], single(machine)),
        }
    }

    #[test]
    fn digest_hex_round_trips() {
        let original = digest("content");
        let parsed = Digest::from_hex(&original.to_hex()).expect("valid hex must parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn digest_rejects_wrong_length() {
        assert!(matches!(
            Digest::from_hex("abc123"),
            Err(ChainError::MalformedDigest { .. })
        ));
    }

    #[test]
    fn digest_rejects_non_hex_of_correct_length() {
        // Guards the case a length check alone would let through.
        let sixty_four_non_hex = "z".repeat(64);
        assert!(matches!(
            Digest::from_hex(&sixty_four_non_hex),
            Err(ChainError::MalformedDigest { .. })
        ));
    }

    #[test]
    fn scan_accepts_no_parents() {
        let machine = MachineId::generate();
        let scan = header(Stage::Scan, vec![], single(machine));
        assert_eq!(verify_chain(&scan, &[]), Ok(()));
    }

    #[test]
    fn analyze_accepts_its_inventory() {
        let machine = MachineId::generate();
        let inventory = parent_ref(Stage::Scan, "inventory", machine);
        let analysis = header(Stage::Analyze, vec![inventory.digest], single(machine));
        assert_eq!(verify_chain(&analysis, &[inventory]), Ok(()));
    }

    #[test]
    fn analyze_refuses_an_inventory_it_was_not_derived_from() {
        // The failure this guards: a user re-scans, then runs a stale analyze
        // against the new inventory. Silently proceeding would attribute the old
        // scan's findings to the new scan's files.
        let machine = MachineId::generate();
        let recorded = parent_ref(Stage::Scan, "inventory-monday", machine);
        let supplied = parent_ref(Stage::Scan, "inventory-tuesday", machine);
        let analysis = header(Stage::Analyze, vec![recorded.digest], single(machine));

        assert_eq!(
            verify_chain(&analysis, std::slice::from_ref(&supplied)),
            Err(ChainError::ParentDigestMismatch {
                expected: recorded.digest,
                found: supplied.digest,
            })
        );
    }

    #[test]
    fn preflight_refuses_an_analysis_where_a_plan_belongs() {
        let machine = MachineId::generate();
        let analysis = parent_ref(Stage::Analyze, "analysis", machine);
        let preflight = header(Stage::Preflight, vec![analysis.digest], single(machine));

        assert_eq!(
            verify_chain(&preflight, &[analysis]),
            Err(ChainError::WrongInputKind {
                stage: Stage::Preflight,
                expected: ArtifactKind::Plan,
                found: ArtifactKind::Analysis,
            })
        );
    }

    #[test]
    fn merge_refuses_a_single_input() {
        // Merging one analysis is a no-op that would produce a second artifact
        // claiming to be a merge, muddying every chain downstream of it.
        let machine = MachineId::generate();
        let only = parent_ref(Stage::Analyze, "analysis", machine);
        let merged = header(Stage::Merge, vec![only.digest], single(machine));

        assert!(matches!(
            verify_chain(&merged, &[only]),
            Err(ChainError::WrongParentCount {
                stage: Stage::Merge,
                min: 2,
                ..
            })
        ));
    }

    #[test]
    fn merge_accepts_two_machines() {
        let mac = MachineId::generate();
        let windows = MachineId::generate();
        let from_mac = parent_ref(Stage::Analyze, "mac", mac);
        let from_windows = parent_ref(Stage::Analyze, "windows", windows);
        let merged = header(
            Stage::Merge,
            vec![from_mac.digest, from_windows.digest],
            MachineScope::Merged {
                machines: vec![mac, windows],
            },
        );

        assert_eq!(verify_chain(&merged, &[from_mac, from_windows]), Ok(()));
    }

    #[test]
    fn merge_order_is_part_of_identity() {
        // Swapping the inputs changes which side wins a tie, so the swapped
        // chain must not validate against the recorded order.
        let mac = MachineId::generate();
        let windows = MachineId::generate();
        let from_mac = parent_ref(Stage::Analyze, "mac", mac);
        let from_windows = parent_ref(Stage::Analyze, "windows", windows);
        let merged = header(
            Stage::Merge,
            vec![from_mac.digest, from_windows.digest],
            MachineScope::Merged {
                machines: vec![mac, windows],
            },
        );

        assert!(matches!(
            verify_chain(&merged, &[from_windows, from_mac]),
            Err(ChainError::ParentDigestMismatch { .. })
        ));
    }

    #[test]
    fn schema_mismatch_is_refused_before_anything_else() {
        let machine = MachineId::generate();
        let mut scan = header(Stage::Scan, vec![], single(machine));
        scan.schema_version = SCHEMA_VERSION + 1;

        assert_eq!(
            verify_chain(&scan, &[]),
            Err(ChainError::SchemaMismatch {
                expected: SCHEMA_VERSION,
                found: SCHEMA_VERSION + 1,
            })
        );
    }

    #[test]
    fn a_plan_for_another_machine_is_refused() {
        // The headline failure this prevents: a plan prepared on a family
        // member's machine, carried over, and applied against paths that mean
        // something entirely different here.
        let theirs = MachineId::generate();
        let mine = MachineId::generate();
        let plan = header(Stage::Plan, vec![digest("analysis")], single(theirs));

        assert_eq!(
            verify_executable_here(&plan, mine),
            Err(ChainError::ForeignMachine {
                expected: theirs,
                found: mine,
            })
        );
    }

    #[test]
    fn a_plan_for_this_machine_is_accepted() {
        let mine = MachineId::generate();
        let plan = header(Stage::Plan, vec![digest("analysis")], single(mine));
        assert_eq!(verify_executable_here(&plan, mine), Ok(()));
    }

    #[test]
    fn a_merged_artifact_is_never_executable() {
        let mac = MachineId::generate();
        let windows = MachineId::generate();
        let merged = header(
            Stage::Merge,
            vec![digest("mac"), digest("windows")],
            MachineScope::Merged {
                machines: vec![mac, windows],
            },
        );

        assert_eq!(
            verify_executable_here(&merged, mac),
            Err(ChainError::MergedScopeNotExecutable { count: 2 })
        );
    }

    #[test]
    fn only_apply_and_undo_may_mutate() {
        // Guards DR-19: if preflight ever reports that it mutates, verification
        // and mutation have been allowed into the same pass.
        for stage in [
            Stage::Scan,
            Stage::Analyze,
            Stage::Merge,
            Stage::Plan,
            Stage::Preflight,
        ] {
            assert!(!stage.mutates_filesystem(), "{stage:?} must be read-only");
        }
        assert!(Stage::Apply.mutates_filesystem());
        assert!(Stage::Undo.mutates_filesystem());
    }

    #[test]
    fn every_stage_declares_a_consistent_kind_pairing() {
        // Any new stage must slot into the chain: whatever it consumes has to be
        // produced by some stage, or the pipeline has a dead end.
        let all = [
            Stage::Scan,
            Stage::Analyze,
            Stage::Merge,
            Stage::Plan,
            Stage::Preflight,
            Stage::Apply,
            Stage::Undo,
        ];
        for stage in all {
            if let Some(input) = stage.input_kind() {
                assert!(
                    all.iter().any(|other| other.output_kind() == input),
                    "{stage:?} consumes {input:?}, which no stage produces"
                );
            }
        }
    }

    #[test]
    fn header_survives_a_json_round_trip() {
        let machine = MachineId::generate();
        let original = header(Stage::Plan, vec![digest("analysis")], single(machine));
        let encoded = serde_json::to_string(&original).expect("header must serialize");
        let decoded: ArtifactHeader =
            serde_json::from_str(&encoded).expect("header must deserialize");
        assert_eq!(original, decoded);
    }
}
