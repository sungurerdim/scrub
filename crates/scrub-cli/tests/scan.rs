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
