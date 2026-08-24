//! This machine's identity, and where it is kept.
//!
//! A random value generated once and stored beside the configuration. It exists
//! so a plan built for one machine cannot be applied to another (DR-18), and it
//! is deliberately not derived from a hardware serial, a user name, or a network
//! address: it identifies this installation to itself and to nobody else (DR-2).

use std::path::PathBuf;

use scrub_core::artifact::MachineId;

/// Reads this machine's identity, creating one on first run.
///
/// # Errors
///
/// Returns a message naming the path involved if the identity could not be read
/// or written.
pub fn identity() -> Result<MachineId, String> {
    let file = configuration_directory()?.join("machine-id");

    // DR-11-EXEMPT: the tool's own configuration file, never a scanned path.
    if let Ok(existing) = std::fs::read_to_string(&file)
        && let Ok(identity) = serde_json::from_str::<MachineId>(existing.trim())
    {
        return Ok(identity);
    }

    let fresh = MachineId::generate();
    let encoded = serde_json::to_string(&fresh)
        .map_err(|error| format!("could not encode an identity: {error}"))?;

    // DR-11-EXEMPT: as above.
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    // DR-11-EXEMPT: as above.
    std::fs::write(&file, encoded)
        .map_err(|error| format!("could not write {}: {error}", file.display()))?;
    Ok(fresh)
}

/// Where this machine keeps the tool's configuration.
///
/// Resolved from the environment rather than from a crate, because the rule is
/// three lines long and a dependency is a thing to keep updated forever.
fn configuration_directory() -> Result<PathBuf, String> {
    if cfg!(windows) {
        return std::env::var_os("APPDATA")
            .map(|base| PathBuf::from(base).join("scrub"))
            .ok_or_else(|| "APPDATA is not set, so there is nowhere to keep settings".to_owned());
    }

    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(base).join("scrub"));
    }

    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/scrub"))
        .ok_or_else(|| "HOME is not set, so there is nowhere to keep settings".to_owned())
}
