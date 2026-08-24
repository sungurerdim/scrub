//! Generates the glue Tauri needs before the crate is compiled.
//!
//! The command list is declared here rather than left implicit so that the
//! window's reachable surface is written down in one place and checked by the
//! permission system. Adding a command means adding it here and to the
//! capabilities file, which is a moment to ask whether the window should be
//! able to do that at all (DR-4).

/// Every command the window may call.
const COMMANDS: &[&str] = &[
    "begin",
    "scan",
    "analyze",
    "groups",
    "copies",
    "survey",
    "browse",
    "arrange",
    "take_back",
    "differences",
    "plan",
    "preflight",
    "apply",
    "undo",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("the application's glue could not be generated");
}
