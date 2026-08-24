//! The command line, end to end, against a tree built for the occasion.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn scrub() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scrub"))
}

/// Somewhere to put artifacts.
///
/// Deliberately not the tree being scanned: writing an artifact into the
/// directory under examination changes what the next scan of it finds, which
/// would make a determinism test fail for a reason that has nothing to do with
/// determinism.
fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("a temporary directory")
}

/// A small tree with a duplicate, a link, and a name that is not ASCII.
fn fixture() -> tempfile::TempDir {
    let tree = tempfile::tempdir().expect("a temporary directory");
    let root = tree.path();
    fs::write(root.join("report.pdf"), vec![b'a'; 2_000]).expect("write report");
    fs::create_dir(root.join("papers")).expect("create papers");
    fs::write(root.join("papers/özet.txt"), b"ozet").expect("write unicode");
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("papers"), root.join("papers-link")).expect("link");
    tree
}

#[test]
fn a_scan_writes_an_artifact_that_reads_back() {
    let tree = fixture();
    let elsewhere = workspace();
    let out = elsewhere.path().join("scan.inventory");

    let scanned = scrub()
        .args(["scan", "--quiet", "--out"])
        .arg(&out)
        .arg(tree.path())
        .output()
        .expect("the scan must run");
    assert!(
        scanned.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&scanned.stderr)
    );
    assert!(out.exists(), "the artifact must have been written");

    let inspected = scrub()
        .arg("inspect")
        .arg(&out)
        .output()
        .expect("inspect must run");
    assert!(inspected.status.success());
    let text = String::from_utf8_lossy(&inspected.stdout);
    assert!(
        text.contains("files"),
        "the summary must report files: {text}"
    );
}

#[test]
fn two_scans_of_an_unchanged_tree_agree() {
    // The property the whole chain rests on (DR-12). If this drifts, "nothing
    // has changed since last time" becomes unanswerable and every downstream
    // stage has to re-derive everything.
    let tree = fixture();
    let elsewhere = workspace();
    let first = elsewhere.path().join("first.inventory");
    let second = elsewhere.path().join("second.inventory");

    for out in [&first, &second] {
        let status = scrub()
            .args(["scan", "--quiet", "--out"])
            .arg(out)
            .arg(tree.path())
            .status()
            .expect("the scan must run");
        assert!(status.success());
    }

    let digest_of = |path: &std::path::Path| {
        let output = scrub()
            .arg("inspect")
            .arg(path)
            .output()
            .expect("inspect must run");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.trim().strip_prefix("content      ").map(str::to_owned))
            .expect("inspect must print a content digest")
    };

    assert_eq!(
        digest_of(&first),
        digest_of(&second),
        "two scans of the same tree must produce the same content digest"
    );
}

#[test]
fn an_export_is_one_json_object_per_line() {
    let tree = fixture();
    let elsewhere = workspace();
    let out = elsewhere.path().join("scan.inventory");
    let status = scrub()
        .args(["scan", "--quiet", "--out"])
        .arg(&out)
        .arg(tree.path())
        .status()
        .expect("the scan must run");
    assert!(status.success());

    let exported = scrub()
        .arg("export")
        .arg(&out)
        .output()
        .expect("export must run");
    assert!(exported.status.success());

    let text = String::from_utf8(exported.stdout).expect("the export must be valid UTF-8");
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() > 3, "every record gets a line");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|error| panic!("every line must be a JSON object: {error} in {line}"));
    }
    assert!(
        lines[0].contains("\"record\":\"header\""),
        "the header comes first"
    );
}

#[test]
fn scanning_a_path_that_does_not_exist_reports_it_rather_than_pretending() {
    // The failure this guards: an empty result that looks like a clean scan of an
    // empty folder, when the folder was never there.
    let tree = fixture();
    let elsewhere = workspace();
    let out = elsewhere.path().join("scan.inventory");
    let missing = tree.path().join("nowhere");

    let scanned = scrub()
        .args(["scan", "--quiet", "--out"])
        .arg(&out)
        .arg(&missing)
        .output()
        .expect("the scan must run");
    assert!(
        scanned.status.success(),
        "a missing path is reported, not fatal"
    );

    let inspected = scrub()
        .arg("inspect")
        .arg(&out)
        .output()
        .expect("inspect must run");
    let text = String::from_utf8_lossy(&inspected.stdout);
    assert!(
        text.contains("could not be read"),
        "the missing path must be reported as unread, got: {text}"
    );
}

/// A tree holding a real duplicate, a near-miss, and a hard link.
fn duplicates() -> tempfile::TempDir {
    let tree = tempfile::tempdir().expect("a temporary directory");
    let root = tree.path();

    // Same content under two names: the one genuine finding.
    fs::write(root.join("invoice.pdf"), vec![b'x'; 5_000]).expect("write invoice");
    fs::write(root.join("invoice-copy.pdf"), vec![b'x'; 5_000]).expect("write copy");

    // Same size, different content: a size collision, not a duplicate.
    let mut different = vec![b'x'; 5_000];
    different[2_500] = b'y';
    fs::write(root.join("statement.pdf"), &different).expect("write statement");

    #[cfg(unix)]
    fs::hard_link(root.join("invoice.pdf"), root.join("invoice-link.pdf")).expect("hard link");

    tree
}

fn analyse(tree: &std::path::Path, workspace: &std::path::Path) -> String {
    let inventory = workspace.join("scan.inventory");
    let analysis = workspace.join("scan.analysis");

    let status = scrub()
        .args(["scan", "--quiet", "--out"])
        .arg(&inventory)
        .arg(tree)
        .status()
        .expect("the scan must run");
    assert!(status.success());

    let output = scrub()
        .args(["analyze", "--quiet"])
        .arg(&inventory)
        .args(["--out"])
        .arg(&analysis)
        .output()
        .expect("the analysis must run");
    assert!(
        output.status.success(),
        "analyze failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn an_analysis_finds_the_duplicate_and_not_the_size_collision() {
    // Both halves matter. Missing the copy makes the tool useless; reporting the
    // size collision makes it dangerous.
    let tree = duplicates();
    let elsewhere = workspace();
    let text = analyse(tree.path(), elsewhere.path());

    assert!(
        text.contains("1 group(s) proven identical"),
        "exactly one group, and not two: {text}"
    );
}

#[cfg(unix)]
#[test]
fn a_hard_link_does_not_inflate_what_an_analysis_promises() {
    // Three names, two objects, one redundant copy. A tool counting names would
    // promise twice the space that deleting can return (DR-16).
    let tree = duplicates();
    let elsewhere = workspace();
    let text = analyse(tree.path(), elsewhere.path());

    assert!(
        text.contains("holding 1 redundant cop"),
        "one redundant object, not two: {text}"
    );
}

#[test]
fn an_analysis_reads_back_and_reports_the_same_findings() {
    let tree = duplicates();
    let elsewhere = workspace();
    analyse(tree.path(), elsewhere.path());

    let inspected = scrub()
        .arg("inspect")
        .arg(elsewhere.path().join("scan.analysis"))
        .output()
        .expect("inspect must run");
    assert!(inspected.status.success());

    let text = String::from_utf8_lossy(&inspected.stdout);
    assert!(text.contains("Analyze"), "the stage is reported: {text}");
    assert!(
        text.contains("1 group(s) proven identical"),
        "the findings survive storage: {text}"
    );
}

#[test]
fn an_existing_artifact_is_not_written_over_without_being_asked() {
    // DR-6 applied to the tool's own output. The refusal also has to come
    // before the work: being told the name was taken after a two-minute scan is
    // the same information delivered uselessly late.
    let tree = fixture();
    let elsewhere = workspace();
    let out = elsewhere.path().join("scan.inventory");

    let first = scrub()
        .args(["scan", "--quiet", "--out"])
        .arg(&out)
        .arg(tree.path())
        .status()
        .expect("the first scan must run");
    assert!(first.status_ok());

    let second = scrub()
        .args(["scan", "--quiet", "--out"])
        .arg(&out)
        .arg(tree.path())
        .output()
        .expect("the second scan must run");
    assert!(!second.status.success(), "the second scan must refuse");
    let complaint = String::from_utf8_lossy(&second.stderr);
    assert!(
        complaint.contains("already exists") && complaint.contains("--replace"),
        "the refusal must say what to do about it: {complaint}"
    );

    let replaced = scrub()
        .args(["scan", "--quiet", "--replace", "--out"])
        .arg(&out)
        .arg(tree.path())
        .status()
        .expect("the replacing scan must run");
    assert!(replaced.status_ok(), "--replace is taken as the answer");
}

/// `ExitStatus::success`, named so the assertions above read as sentences.
trait StatusOk {
    fn status_ok(&self) -> bool;
}

impl StatusOk for std::process::ExitStatus {
    fn status_ok(&self) -> bool {
        self.success()
    }
}

/// Two trees standing in for two machines: one file in both, one in each alone.
fn two_machines() -> (tempfile::TempDir, tempfile::TempDir) {
    let first = tempfile::tempdir().expect("a temporary directory");
    let second = tempfile::tempdir().expect("a temporary directory");

    // The same content under different names, which is the ordinary case: a
    // document copied between machines rarely keeps its path.
    fs::write(first.path().join("tax.pdf"), b"the 2026 return").expect("write");
    fs::write(second.path().join("tax-copy.pdf"), b"the 2026 return").expect("write");

    fs::write(first.path().join("only-here.txt"), b"first machine").expect("write");
    fs::write(second.path().join("only-there.txt"), b"second machine").expect("write");

    (first, second)
}

fn analysis_of(tree: &std::path::Path, workspace: &std::path::Path, name: &str) -> PathBuf {
    let inventory = workspace.join(format!("{name}.inventory"));
    let analysis = workspace.join(format!("{name}.analysis"));

    assert!(
        scrub()
            .args(["scan", "--quiet", "--out"])
            .arg(&inventory)
            .arg(tree)
            .status()
            .expect("scan")
            .success()
    );
    assert!(
        scrub()
            .args(["analyze", "--quiet", "--thorough", "--out"])
            .arg(&analysis)
            .arg(&inventory)
            .status()
            .expect("analyze")
            .success()
    );
    analysis
}

#[test]
fn a_comparison_separates_what_is_in_both_places_from_what_is_in_one() {
    // The question the tool was built for. Both halves have to be right: a file
    // wrongly called shared invites deleting the only copy, and one wrongly
    // called exclusive sends someone looking for a backup that exists.
    let (first, second) = two_machines();
    let elsewhere = workspace();
    let one = analysis_of(first.path(), elsewhere.path(), "mac");
    let two = analysis_of(second.path(), elsewhere.path(), "windows");

    let output = scrub()
        .arg("merge")
        .arg(&one)
        .arg(&two)
        .args(["--out"])
        .arg(elsewhere.path().join("combined.analysis"))
        .output()
        .expect("merge must run");
    assert!(
        output.status.success(),
        "merge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("1 file(s), 15 bytes of content"),
        "the shared file is found despite its different name: {text}"
    );
    assert!(
        text.contains("mac                  1 file(s)")
            && text.contains("windows              1 file(s)"),
        "each machine has exactly one file the other lacks: {text}"
    );
}

#[test]
fn a_comparison_says_what_it_did_not_cover() {
    // Without --thorough a file whose size nothing on its own machine shares is
    // never read, so it cannot be recognised anywhere. Saying so is the
    // difference between a partial answer and a wrong one (DR-23).
    let (first, second) = two_machines();
    let elsewhere = workspace();

    let mut analyses = Vec::new();
    for (tree, name) in [(first.path(), "mac"), (second.path(), "windows")] {
        let inventory = elsewhere.path().join(format!("{name}.inventory"));
        let analysis = elsewhere.path().join(format!("{name}.analysis"));
        assert!(
            scrub()
                .args(["scan", "--quiet", "--out"])
                .arg(&inventory)
                .arg(tree)
                .status()
                .expect("scan")
                .success()
        );
        // Deliberately not thorough.
        assert!(
            scrub()
                .args(["analyze", "--quiet", "--out"])
                .arg(&analysis)
                .arg(&inventory)
                .status()
                .expect("analyze")
                .success()
        );
        analyses.push(analysis);
    }

    let output = scrub()
        .arg("merge")
        .args(&analyses)
        .args(["--out"])
        .arg(elsewhere.path().join("combined.analysis"))
        .output()
        .expect("merge must run");
    assert!(output.status.success());

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("--thorough"),
        "an incomplete comparison must say so and say what to do: {text}"
    );
}

#[test]
fn a_comparison_cannot_be_applied_anywhere() {
    // It describes several machines, so no single machine is the one it is
    // about (DR-18). Anything downstream must refuse it rather than pick one.
    let (first, second) = two_machines();
    let elsewhere = workspace();
    let one = analysis_of(first.path(), elsewhere.path(), "mac");
    let two = analysis_of(second.path(), elsewhere.path(), "windows");
    let combined = elsewhere.path().join("combined.analysis");

    assert!(
        scrub()
            .arg("merge")
            .arg(&one)
            .arg(&two)
            .args(["--out"])
            .arg(&combined)
            .status()
            .expect("merge")
            .success()
    );

    let again = scrub()
        .arg("merge")
        .arg(&combined)
        .arg(&one)
        .args(["--out"])
        .arg(elsewhere.path().join("twice.analysis"))
        .output()
        .expect("the second merge must run");
    assert!(
        !again.status.success(),
        "merging a comparison back in would count a machine twice"
    );
}

#[test]
fn merging_a_single_analysis_is_refused() {
    let (first, _second) = two_machines();
    let elsewhere = workspace();
    let one = analysis_of(first.path(), elsewhere.path(), "mac");

    let output = scrub()
        .arg("merge")
        .arg(&one)
        .args(["--out"])
        .arg(elsewhere.path().join("combined.analysis"))
        .output()
        .expect("merge must run");
    assert!(
        !output.status.success(),
        "one analysis is not a comparison of anything"
    );
}

/// A tree where the original and its copies are unambiguous.
fn original_and_copies() -> tempfile::TempDir {
    let tree = tempfile::tempdir().expect("a temporary directory");
    fs::create_dir_all(tree.path().join("Documents")).expect("create Documents");
    fs::create_dir_all(tree.path().join("Desktop/old")).expect("create Desktop/old");

    fs::write(tree.path().join("Documents/tax.pdf"), b"the 2026 return").expect("write");
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    fs::write(
        tree.path().join("Desktop/old/tax-copy.pdf"),
        b"the 2026 return",
    )
    .expect("write");
    fs::write(tree.path().join("Documents/notes.txt"), b"unrelated").expect("write");

    tree
}

fn plan_of(tree: &std::path::Path, workspace: &std::path::Path, keep: &str) -> String {
    let inventory = workspace.join("scan.inventory");
    let analysis = workspace.join("scan.analysis");
    let drafted = workspace.join(format!("{keep}.plan"));

    assert!(
        scrub()
            .args(["scan", "--quiet", "--replace", "--out"])
            .arg(&inventory)
            .arg(tree)
            .status()
            .expect("scan")
            .success()
    );
    assert!(
        scrub()
            .args(["analyze", "--quiet", "--replace", "--out"])
            .arg(&analysis)
            .arg(&inventory)
            .status()
            .expect("analyze")
            .success()
    );

    let output = scrub()
        .args(["plan", "--replace", "--keep", keep, "--out"])
        .arg(&drafted)
        .arg(&analysis)
        .output()
        .expect("plan must run");
    assert!(
        output.status.success(),
        "plan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A fingerprint of every file in a tree, to prove nothing moved.
fn tree_state(root: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut queue = vec![root.to_path_buf()];
    while let Some(directory) = queue.pop() {
        for entry in fs::read_dir(&directory).expect("read").flatten() {
            let path = entry.path();
            if path.is_dir() {
                queue.push(path);
            } else {
                let content = fs::read(&path).expect("read file");
                found.push((path, content));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn planning_changes_nothing_on_disk() {
    // The promise the stage is built on (DR-9). Everything a plan describes is
    // in the conditional until somebody applies it, and there is no apply yet.
    let tree = original_and_copies();
    let elsewhere = workspace();

    let before = tree_state(tree.path());
    let text = plan_of(tree.path(), elsewhere.path(), "oldest");
    let after = tree_state(tree.path());

    assert_eq!(before, after, "the tree must be untouched, byte for byte");
    assert!(text.contains("Nothing on disk has been touched"));
}

#[test]
fn a_plan_keeps_the_copy_the_rule_asks_for() {
    let tree = original_and_copies();
    let elsewhere = workspace();

    let oldest = plan_of(tree.path(), elsewhere.path(), "oldest");
    assert!(
        oldest.contains("tax-copy.pdf") && oldest.contains("same content as"),
        "the later copy is set aside and the original kept: {oldest}"
    );

    let newest = plan_of(tree.path(), elsewhere.path(), "newest");
    assert!(
        newest.contains("Documents/tax.pdf"),
        "asking for the newest keeps the copy and sets the original aside: {newest}"
    );
}

#[test]
fn a_plan_contains_no_operation_that_destroys_anything() {
    // DR-5, checked against the artifact rather than against the prose. The
    // strongest thing a plan can say about a file is that it should go to
    // quarantine; if a destroying operation ever becomes expressible, this
    // fails before anyone can generate one.
    let tree = original_and_copies();
    let elsewhere = workspace();
    let text = plan_of(tree.path(), elsewhere.path(), "oldest");

    let exported = scrub()
        .arg("export")
        .arg(elsewhere.path().join("scan.inventory"))
        .output()
        .expect("export must run");
    assert!(exported.status.success());

    let drafted = elsewhere.path().join("oldest.plan");
    let kinds = std::process::Command::new("sqlite3")
        .arg(&drafted)
        .arg("SELECT DISTINCT kind FROM operation;")
        .output();

    if let Ok(kinds) = kinds
        && kinds.status.success()
    {
        let listed = String::from_utf8_lossy(&kinds.stdout);
        for kind in listed.lines() {
            assert!(
                matches!(kind, "create_directory" | "move" | "quarantine"),
                "a plan may only create, move, or set aside — found {kind:?}"
            );
        }
        assert!(
            listed.contains("quarantine"),
            "this plan does set files aside"
        );
    }

    // And the report says so, because somebody skimming it has to come away
    // knowing their files are recoverable.
    assert!(
        text.contains("not deleted"),
        "the report says so plainly: {text}"
    );
}

#[test]
fn a_plan_reads_back_with_its_findings_intact() {
    let tree = original_and_copies();
    let elsewhere = workspace();
    plan_of(tree.path(), elsewhere.path(), "oldest");

    let inspected = scrub()
        .arg("inspect")
        .arg(elsewhere.path().join("oldest.plan"))
        .output()
        .expect("inspect must run");
    assert!(inspected.status.success());

    let text = String::from_utf8_lossy(&inspected.stdout);
    assert!(text.contains("Plan"), "the stage is reported: {text}");
    assert!(text.contains("SET ASIDE"), "the operations survive: {text}");
}

#[test]
fn a_plan_cannot_be_made_from_a_comparison() {
    // A comparison is about several machines, and a plan has to be about one
    // (DR-18).
    let (first, second) = two_machines();
    let elsewhere = workspace();
    let one = analysis_of(first.path(), elsewhere.path(), "mac");
    let two = analysis_of(second.path(), elsewhere.path(), "windows");
    let combined = elsewhere.path().join("combined.analysis");

    assert!(
        scrub()
            .arg("merge")
            .arg(&one)
            .arg(&two)
            .args(["--out"])
            .arg(&combined)
            .status()
            .expect("merge")
            .success()
    );

    let output = scrub()
        .arg("plan")
        .arg(&combined)
        .args(["--out"])
        .arg(elsewhere.path().join("impossible.plan"))
        .output()
        .expect("plan must run");
    assert!(
        !output.status.success(),
        "planning from a comparison is refused"
    );
}

/// Runs the whole pipeline over a tree and returns the artifacts it produced.
struct Pipeline {
    tree: tempfile::TempDir,
    workspace: tempfile::TempDir,
}

impl Pipeline {
    fn run(tree: tempfile::TempDir) -> Self {
        let workspace = workspace();
        let pipeline = Self { tree, workspace };

        pipeline.step(
            &["scan", "--quiet", "--out"],
            "scan.inventory",
            Some("TREE"),
        );
        pipeline.step(
            &["analyze", "--quiet", "--out"],
            "scan.analysis",
            Some("scan.inventory"),
        );
        pipeline.step(&["plan", "--out"], "scan.plan", Some("scan.analysis"));
        pipeline.step(&["preflight", "--out"], "scan.preflight", Some("scan.plan"));
        pipeline
    }

    fn at(&self, name: &str) -> PathBuf {
        self.workspace.path().join(name)
    }

    fn step(&self, args: &[&str], out: &str, input: Option<&str>) -> String {
        let mut command = scrub();
        command.args(args).arg(self.at(out));
        match input {
            Some("TREE") => {
                command.arg(self.tree.path());
            }
            Some(name) => {
                command.arg(self.at(name));
            }
            None => {}
        }
        let output = command.output().expect("the stage must run");
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        tree_state(self.tree.path())
    }
}

#[test]
fn a_run_sets_files_aside_and_undoing_puts_every_one_back() {
    // The promise the whole tool is built on, end to end: after a run and its
    // reversal the tree is byte-identical to how it started (DR-10).
    let pipeline = Pipeline::run(original_and_copies());
    let before = pipeline.files();

    let applied = pipeline.step(&["apply", "--out"], "scan.journal", Some("scan.preflight"));
    assert!(applied.contains("change(s) made"), "{applied}");

    let after_apply = pipeline.files();
    assert_ne!(before, after_apply, "the run did something");
    assert!(
        after_apply.len() < before.len(),
        "and what it did was take files out of the tree"
    );

    let reversed = pipeline.step(&["undo", "--out"], "undo.journal", Some("scan.journal"));
    assert!(reversed.contains("put back where they were"), "{reversed}");

    assert_eq!(
        before,
        pipeline.files(),
        "every file is back, with its content unchanged"
    );
}

#[test]
fn nothing_a_run_sets_aside_is_deleted() {
    // DR-5, checked by finding the files again rather than by trusting the
    // wording. Quarantine is a place, and everything is still in it.
    let pipeline = Pipeline::run(original_and_copies());
    let before = pipeline.files();

    pipeline.step(&["apply", "--out"], "scan.journal", Some("scan.preflight"));

    let quarantine = pipeline.at("scan.quarantine");
    assert!(quarantine.exists(), "the quarantine directory was made");

    let held = tree_state(&quarantine);
    assert!(!held.is_empty(), "and it holds what left the tree");

    let remaining: Vec<Vec<u8>> = pipeline
        .files()
        .into_iter()
        .map(|(_, content)| content)
        .collect();
    for (_, content) in &before {
        let still_somewhere = remaining.contains(content)
            || held.iter().any(|(_, quarantined)| quarantined == content);
        assert!(
            still_somewhere,
            "every file that existed before is still somewhere"
        );
    }
}

#[test]
fn a_journal_records_where_everything_went() {
    // What makes undo a matter of reading rather than of remembering.
    let pipeline = Pipeline::run(original_and_copies());
    pipeline.step(&["apply", "--out"], "scan.journal", Some("scan.preflight"));

    let inspected = scrub()
        .arg("inspect")
        .arg(pipeline.at("scan.journal"))
        .output()
        .expect("inspect must run");
    assert!(inspected.status.success());

    let text = String::from_utf8_lossy(&inspected.stdout);
    assert!(text.contains("Run"), "the stage is reported: {text}");
    assert!(text.contains("change(s) made"), "and what it did: {text}");
}

#[test]
fn a_file_changed_between_checking_and_running_is_left_alone() {
    // The last guard, and the one hardest to test any other way: preflight
    // passed, then somebody edited the file. Setting it aside now would set
    // aside work nobody accounted for (DR-8).
    let pipeline = Pipeline::run(original_and_copies());

    let copy = pipeline.tree.path().join("Desktop/old/tax-copy.pdf");
    fs::write(&copy, b"edited after preflight said it was fine").expect("edit");

    let applied = pipeline.step(&["apply", "--out"], "scan.journal", Some("scan.preflight"));
    assert!(
        applied.contains("left alone because something had changed"),
        "the edit is noticed and acted on: {applied}"
    );
    assert_eq!(
        fs::read(&copy).expect("read"),
        b"edited after preflight said it was fine",
        "and the edited file is exactly where it was"
    );
}
