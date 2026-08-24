//! The desktop application.
//!
//! It runs the same crates the command line does, through the same driver, and
//! adds nothing of its own to what the pipeline decides. What it adds is a way
//! to see two million files without reading a report: the things that are not
//! backed up, first and by themselves; duplicates as one row each rather than as
//! a list of paths; and a plan you can look at, change your mind about, and
//! throw away, because nothing happens until the last screen and nothing is
//! deleted even then.

#![forbid(unsafe_code)]

mod commands;
mod session;
mod view;
mod watch;

pub use commands::WORKSPACE_VARIABLE;

/// The session every command shares.
///
/// Handed out rather than built inside [`run`] so the tests can build an
/// application with the same state the real one has.
#[must_use]
pub fn shared() -> session::Shared {
    session::Shared::default()
}

/// Every command the window can call.
///
/// Exposed for the same reason: a test that registered its own list would be
/// testing that list, not the one the window is given.
pub fn handler<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static
{
    tauri::generate_handler![
        commands::begin,
        commands::scan,
        commands::analyze,
        commands::groups,
        commands::copies,
        commands::plan,
        commands::preflight,
        commands::apply,
        commands::undo,
    ]
}

/// Builds and runs the window.
///
/// # Panics
///
/// Panics if the application cannot be built at all, which means a broken
/// installation rather than anything a person did.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(shared())
        .invoke_handler(handler())
        .run(tauri::generate_context!())
        .expect("the application could not start");
}
