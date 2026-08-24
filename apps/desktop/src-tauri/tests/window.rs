//! The window's commands, driven without a window.
//!
//! Tauri can build an application against a mock runtime, which means every
//! command the interface calls can be invoked here exactly as the interface
//! invokes it — same names, same arguments, same JSON coming back. What this
//! covers is the part that no amount of type-checking would: that the arguments
//! the interface sends are the arguments the commands expect, and that a stage
//! refused for the right reason says so in words.
//!
//! Everything runs against a tree these tests build in a temporary directory,
//! with the workspace pointed at another. Nothing here reads or writes anything
//! belonging to the person running it.

#![allow(
    unsafe_code,
    reason = "setting an environment variable is unsafe in edition 2024; the \
              lock this file takes is what makes it sound here"
)]

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use serde_json::{Value, json};
use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder};

/// Held for the length of each test.
///
/// Where the workspace goes is read from the environment, and the environment
/// belongs to the whole process. Two tests setting it at once would each scan
/// into the other's directory, so they take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// An application with the real command handler behind a mock runtime.
struct Fixture {
    window: tauri::WebviewWindow<MockRuntime>,
    /// Dropped with the fixture, letting the next test have the environment.
    _turn: MutexGuard<'static, ()>,
}

fn application(workspace: &Path) -> Fixture {
    // A test that panicked leaves the lock poisoned, and the state it was
    // guarding is a directory path that the next test overwrites anyway. Taking
    // it back is right; failing every later test because an earlier one failed
    // would hide which one actually broke.
    let turn = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // SAFETY: the lock above means no other thread in this process is reading
    // or writing the environment while this happens.
    unsafe { std::env::set_var(scrub_desktop::WORKSPACE_VARIABLE, workspace) };

    // The real context, not a mock one: it carries the capabilities file, and
    // a command the capabilities do not reach is a command the window cannot
    // call. Testing against an invented context would pass while the shipped
    // application refused.
    let app = mock_builder()
        .manage(scrub_desktop::shared())
        .invoke_handler(scrub_desktop::handler())
        .build(tauri::generate_context!())
        .expect("the application should build against the mock runtime");

    let window = tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
        .build()
        .expect("a window to call commands from");

    Fixture {
        window,
        _turn: turn,
    }
}

/// Calls one command the way the window calls it.
fn ask(fixture: &Fixture, command: &str, body: Value) -> Result<Value, Value> {
    let window = &fixture.window;
    get_ipc_response(
        window,
        tauri::webview::InvokeRequest {
            cmd: command.to_owned(),
            callback: tauri::ipc::CallbackFn(0),
            error: tauri::ipc::CallbackFn(1),
            // The scheme the shipped application serves itself over. The
            // permission system treats anything else as a remote origin and
            // refuses, which is the behaviour worth keeping.
            url: "tauri://localhost".parse().expect("a url"),
            body: tauri::ipc::InvokeBody::Json(body),
            headers: tauri::http::HeaderMap::default(),
            invoke_key: INVOKE_KEY.to_owned(),
        },
    )
    .map(|response| response.deserialize::<Value>().expect("json"))
}

#[test]
fn the_window_can_walk_the_whole_pipeline_without_touching_anything_else() {
    let tree = tempfile::tempdir().expect("a directory to scan");
    let place = tempfile::tempdir().expect("a directory for artifacts");

    // Two files with identical contents and one without. The duplicates are
    // written at different moments on purpose: a copy made later is still the
    // same file, and anything that let a date decide would fail here.
    let root = tree.path();
    std::fs::write(root.join("report.pdf"), b"the same bytes, twice over").expect("write");
    std::fs::create_dir(root.join("backup")).expect("mkdir");
    std::fs::write(
        root.join("backup/report.pdf"),
        b"the same bytes, twice over",
    )
    .expect("write");
    std::fs::write(root.join("notes.txt"), b"something else entirely").expect("write");

    let app = application(place.path());

    let beginning = ask(&app, "begin", json!({})).expect("the first screen");
    assert!(
        beginning["providers"].is_object(),
        "the first screen always says what is synchronised, even if nothing is"
    );
    assert_eq!(
        beginning["ready"],
        json!([]),
        "a fresh workspace has got nowhere yet"
    );

    let found = ask(&app, "scan", json!({ "roots": [root.to_string_lossy()] }))
        .expect("a scan of three files");
    assert_eq!(found["files"], 3);
    assert_eq!(
        found["directories"], 1,
        "the backup folder; a scan records what is inside a root, not the root"
    );

    let findings = ask(&app, "analyze", json!({ "thorough": false })).expect("an analysis");
    assert_eq!(findings["proven"], 1, "one group, proven by reading it");
    assert_eq!(findings["redundant"], 1, "one copy too many");
    assert_eq!(findings["unchecked"], 0);

    let rows = ask(&app, "groups", json!({ "offset": 0, "limit": 10 })).expect("the rows");
    let rows = rows.as_array().expect("an array");
    assert_eq!(rows.len(), 1, "one group is one row, whatever it holds");
    assert_eq!(rows[0]["copies"], 2);
    assert_eq!(rows[0]["proven"], true);

    let inside = ask(&app, "copies", json!({ "group": rows[0]["index"] })).expect("the copies");
    let inside = inside.as_array().expect("an array");
    assert_eq!(inside.len(), 2, "opening a row shows where its copies are");

    let steps = ask(&app, "plan", json!({ "keep": "oldest", "prefer": null })).expect("a plan");
    let steps = steps.as_array().expect("an array");
    assert_eq!(steps.len(), 1, "one copy is set aside, one is kept");
    assert_eq!(steps[0]["kind"], "quarantine", "set aside, never deleted");
    assert!(
        steps[0]["because"]
            .as_str()
            .expect("a reason")
            .contains("being kept"),
        "every step says why it is there: {:?}",
        steps[0]["because"]
    );
    assert!(
        steps[0]["verdict"].is_null(),
        "nothing has been checked against the disk yet"
    );

    let checked = ask(&app, "preflight", json!({ "fast": false })).expect("a check");
    let checked = checked.as_array().expect("an array");
    assert_eq!(checked[0]["verdict"]["grade"], "pass");

    // And there it stops. Carrying it out is the one thing these tests do not
    // do: it is covered where the change itself is, and a test suite that moves
    // files as a side effect of running is a test suite nobody trusts.
    assert!(
        root.join("backup/report.pdf").exists(),
        "nothing up to and including the check may change a single file"
    );
    assert!(root.join("report.pdf").exists());
    assert!(root.join("notes.txt").exists());
}

#[test]
fn everything_can_be_rearranged_with_nothing_happening() {
    let tree = tempfile::tempdir().expect("a directory to scan");
    let place = tempfile::tempdir().expect("a directory for artifacts");

    let root = tree.path();
    std::fs::create_dir(root.join("Belgeler")).expect("mkdir");
    std::fs::write(root.join("Belgeler/vergi.pdf"), b"a tax return").expect("write");
    std::fs::write(root.join("loose.txt"), b"filed nowhere in particular").expect("write");

    let app = application(place.path());
    ask(&app, "begin", json!({})).expect("the first screen");
    ask(&app, "scan", json!({ "roots": [root.to_string_lossy()] })).expect("a scan");

    // Walking into the tree shows what is there, under the names it has.
    let listing = ask(
        &app,
        "browse",
        json!({ "under": root.to_string_lossy(), "offset": 0, "limit": 50 }),
    )
    .expect("a listing");
    let names: Vec<&str> = listing["items"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        vec!["Belgeler", "loose.txt"],
        "folders first, then by name"
    );

    let folder = listing["items"][0]["entry"].as_u64().expect("an entry");
    let loose = listing["items"][1]["entry"].as_u64().expect("an entry");

    // Rename the folder, then move a file into it by the name it does not have
    // on disk yet. This is the whole point of the arrangement: the second change
    // is asked about the world the first one left.
    ask(
        &app,
        "arrange",
        json!({ "edit": { "rename": { "entry": folder, "to": "Vergi" } } }),
    )
    .expect("renaming a folder");

    let arranged = ask(
        &app,
        "arrange",
        json!({ "edit": { "relocate": {
            "entry": loose,
            "into": root.join("Vergi").to_string_lossy(),
        } } }),
    )
    .expect("moving a file into the renamed folder");
    assert_eq!(arranged["asked"], 2);
    assert_eq!(
        arranged["differences"], 3,
        "the folder, the file inside it that came along, and the file moved in"
    );

    let differences = ask(&app, "differences", json!({ "offset": 0, "limit": 50 }))
        .expect("the before and after");
    let differences = differences.as_array().expect("an array");
    let carried = differences
        .iter()
        .filter(|line| line["carried"] == json!(true))
        .count();
    assert_eq!(carried, 1, "one thing came along without being asked for");

    // A change that cannot be made is refused in words, and does not count.
    let refusal = ask(
        &app,
        "arrange",
        json!({ "edit": { "rename": { "entry": loose, "to": "../escape.txt" } } }),
    )
    .expect_err("that is a path, not a name");
    assert!(
        refusal.as_str().expect("a message").contains("separator"),
        "the refusal says what was wrong: {refusal}"
    );

    // Taking one back leaves exactly what was there before it.
    let after_taking_back = ask(&app, "take_back", json!({})).expect("taking one back");
    assert_eq!(after_taking_back["asked"], 1);
    assert_eq!(after_taking_back["differences"], 2);

    // The plan carries what was asked for, alongside anything a rule decided.
    ask(&app, "analyze", json!({ "thorough": false })).expect("an analysis");
    ask(
        &app,
        "arrange",
        json!({ "edit": { "new_directory": {
            "path": root.join("Arsiv").to_string_lossy(),
        } } }),
    )
    .expect("a folder that is not there yet");

    let steps = ask(&app, "plan", json!({ "keep": "oldest", "prefer": null })).expect("a plan");
    let steps = steps.as_array().expect("an array");
    let kinds: Vec<&str> = steps
        .iter()
        .map(|step| step["kind"].as_str().expect("a kind"))
        .collect();
    assert!(
        kinds.contains(&"createDirectory") && kinds.contains(&"move"),
        "the plan holds both the folder and the rename: {kinds:?}"
    );

    // And after all of it, the disk is exactly as it was.
    assert!(root.join("Belgeler/vergi.pdf").exists(), "nothing moved");
    assert!(root.join("loose.txt").exists());
    assert!(!root.join("Vergi").exists(), "and nothing was created");
    assert!(!root.join("Arsiv").exists());
}

#[test]
fn a_stage_asked_for_out_of_order_says_which_step_to_take() {
    let place = tempfile::tempdir().expect("a directory for artifacts");
    let app = application(place.path());

    ask(&app, "begin", json!({})).expect("the first screen");

    let refusal = ask(&app, "analyze", json!({ "thorough": false }))
        .expect_err("there is nothing to analyse");
    let said = refusal.as_str().expect("a message");
    assert!(
        said.contains("scan this machine"),
        "the refusal names the step to take: {said}"
    );

    let refusal = ask(&app, "plan", json!({ "keep": "oldest", "prefer": null }))
        .expect_err("there is nothing to plan from");
    assert!(
        refusal
            .as_str()
            .expect("a message")
            .contains("look for duplicates"),
        "and so does this one: {refusal}"
    );
}

#[test]
fn a_rule_nobody_offers_is_refused_by_name() {
    // The window only ever sends one of three, so this guards the case where a
    // later change adds a fourth to the interface and forgets the other side.
    let place = tempfile::tempdir().expect("a directory for artifacts");
    let app = application(place.path());
    ask(&app, "begin", json!({})).expect("the first screen");

    let refusal = ask(&app, "plan", json!({ "keep": "biggest", "prefer": null }))
        .expect_err("there is no such rule");
    let said = refusal.as_str().expect("a message");
    assert!(
        said.contains("oldest") && said.contains("newest") && said.contains("shallowest"),
        "the refusal lists the rules there are: {said}"
    );
}
