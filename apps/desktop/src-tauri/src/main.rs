//! The desktop application's entry point.

// Without this the application opens a console window behind itself on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() {
    scrub_desktop::run();
}
