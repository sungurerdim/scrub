//! The stage-independent core of `scrub`.
//!
//! This crate owns the artifact schemas and the chain-integrity rules that hold
//! the pipeline together. It performs no filesystem traversal and makes no
//! network calls; given the same input it produces the same output on any
//! machine (DR-12).
//!
//! See `docs/PIPELINE.md` for the pipeline this describes and
//! `docs/DESIGN-RULES.md` for the rules it enforces.

#![forbid(unsafe_code)]

pub mod analysis;
pub mod artifact;
pub mod cloud;
pub mod inventory;
pub mod merge;
pub mod paths;

pub use artifact::{
    ArtifactHeader, ArtifactKind, ChainError, Digest, MachineId, MachineScope, ParentRef,
    SCHEMA_VERSION, Stage,
};
