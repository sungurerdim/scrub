# Architecture

## Layout

```
crates/
  scrub-core/       vocabulary · artifact schema · chain integrity · rule engine
  scrub-platform/   cloud state · dataless detection · traversal      one module per platform
  scrub-store/      artifacts as SQLite, and the canonical digest
  scrub-run/        drives each stage, so every interface runs the same one
  scrub-providers/  read-only Drive and Graph clients, user-owned credentials   [Phase 3]
  scrub-photos/     PhotoKit bridge, macOS only, feature-gated        [Phase 4]
  scrub-cli/        every stage as a command
apps/desktop/       Tauri window + web interface
  src/              the three screens
  src-tauri/        the commands the window can call, and nothing else
```

`scrub-core` holds no I/O at all and depends on nothing heavy. `scrub-platform`
is the only crate that touches a user's filesystem, and `scrub-store` is the only
one that carries a C dependency.

That last split is load-bearing rather than tidy-minded. `rusqlite` bundles
SQLite's C source, which needs a C compiler for whichever target is being built —
fine for the machine you are on, fatal for the Windows cross-check that stands in
for CI here. Keeping storage in its own crate means every line of
Windows-specific code stays in `scrub-platform`, where it can still be
type-checked for both Windows architectures from a Mac.

Given the same inventory, the core produces the same analysis on any machine
(DR-12), which is what makes golden-file testing possible.

## One driver, two interfaces

`scrub-run` exists because the command line and the window are two ways of
asking for the same work. If each drove the stages itself they would drift — one
would gain a check the other lacked — and two artifacts claiming the same stage
would stop meaning the same thing. So the driving lives in one crate, and both
callers get the identical artifact.

Nothing in `scrub-run` prints or draws. Progress goes to a `Watch`, which the
caller implements: the command line redraws a line on a terminal, the window
sends an event and moves a bar. A caller wanting neither uses `Silent`.

The command line is not a lesser surface. It exists so every stage can be driven
and checked by machine, and so the artifacts are usable by anyone who would
rather script than click.

## The window

Three screens, in the order the pipeline runs: **Discover** (what is here, and
what is not backed up), **Organize** (what is duplicated, and what to do), and
**Apply** (check it, then carry it out). Only the last one changes anything, and
only after showing every step and asking in words that name the file count and
the space involved.

The window holds no rules of its own. It does not decide what a duplicate is,
what may be moved, or what must be checked first; it asks, and shows the answer.
What it does hold is the presentation decisions: a group of duplicates crosses
the boundary as one row with a count, and its copies are fetched only if
somebody opens it (DR-21). The list is virtualised, because a real machine
produces tens of thousands of rows.

The commands the window may call are declared twice on purpose — in `build.rs`
and in `capabilities/default.json` — so the reachable surface is written down
where it can be reviewed, and adding to it is a deliberate act (DR-4).

Artifacts go to the platform's application-data directory, or to `SCRUB_WORKSPACE`
where somebody wants them on another disk. That directory is the whole of the
tool's state: deleting it loses nothing but the need to scan again, and it holds
no copy of anybody's files (DR-3).

## Platform layer

Everything platform-specific lives in one module per platform, behind one
identical set of functions. A third module covers everywhere else, and refuses
to scan rather than guessing that a placeholder is an ordinary file.

**macOS.** Cloud files are File Provider objects. A file whose content is not
present on disk is *dataless*: `st_flags` carries `SF_DATALESS`, and `st_blocks` is
zero while `st_size` reports the full logical size. `stat()` on such a file does not
materialize it, but traversing *through* a dataless directory does — so traversal
order and policy matter.

The process therefore sets
`setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_MATERIALIZE_DATALESS_FILES_OFF)`
at startup. Under this policy an accidental read of a dehydrated file returns
`EDEADLK` instead of triggering a download. DR-11 is enforced by the kernel, not by
our discipline.

**Windows.** Cloud placeholders carry `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`,
usually alongside `FILE_ATTRIBUTE_OFFLINE`, and report zero size on disk. Metadata
access uses `FILE_FLAG_OPEN_NO_RECALL`, which reads attributes without asking the
sync provider to hydrate.

Both answer the same questions: which provider owns this path, is the content
present locally, is it pinned, and what does the provider say about a link out of
its directory. The attribute rules for Windows live in their own module compiled
on every platform, so they are exercised by the ordinary test run rather than
only wherever a Windows machine happens to be.

## Traversal

Breadth-first, single-threaded, driven by an explicit queue rather than recursion
so that a deep tree cannot exhaust the stack. Every fact comes from a
symlink-preserving stat; nothing is opened.

**Measured baseline**, macOS on Apple silicon, warm cache: a home directory of
**2,459,990 entries in 131 seconds** — about 18,700 entries per second — of which
253,628 were directories and **39,978 were symbolic links**. That last figure is
the argument for DR-22 in a single number: a traversal that followed links would
be counting most of this tree many times over, and would not finish at all on the
first cycle it met.

Traversal is not parallel yet, and that is a decision rather than an omission.
The analyze stage reads file content and will dominate wall-clock time by a wide
margin, so parallelising the walk first would optimise the cheaper half. It also
has no baseline to be measured against until the whole pipeline exists. The
number above is that baseline, recorded so a future change has to prove itself.

What matters more than raw speed at this stage is that results arrive
progressively: a scan that shows nothing for two minutes is indistinguishable
from one that has hung.

## Reading content

Identity is decided by a BLAKE3 digest of a file's whole content, and by nothing
else (DR-13). Getting there cheaply matters, because reading every file to find
out which ones match would read the disk to learn what sizes already ruled out.

Three narrowings, in order:

1. **Size.** A size no other object shares cannot have a duplicate. Nothing about
   such a file is ever read.
2. **Sample.** Candidates get a digest of their first and last 64 KB plus their
   length. Two large files that merely share a size are separated for a few
   kilobytes instead of their whole length.
3. **Full read.** Only what survives the sample is read through.

Measured on this repository's own tree: 8,274 files shared a size, 1,999 survived
the sample, so **76% of the candidates were never read past their two ends**.

Measured on a home directory of 2.47 million entries: **697 seconds**, finding
221,502 proven groups holding 681,143 redundant copies and 30.8 GB that removal
would actually return, alongside 98 groups left unchecked because their content
is in the cloud.

That figure settles the question the traversal section left open. Analysis takes
seven times as long as the walk that feeds it, so it is where parallelism belongs
and the walk is not. Both numbers are recorded so that a change has something to
beat.

A sample digest is never identity. Two files can agree at both ends and differ in
the middle, which is exactly what the third pass is for — and why a file the
sample separated is recorded as *settled and distinct* rather than as unread.
Confusing those two would file a proven fact under "could not check" and bury the
handful of real questions among thousands of false ones.

Nothing whose content lives with a provider is read at any stage. Those files
become candidate-tier findings carrying the exact number of bytes that settling
them would download, which is a decision left to the person paying for the
bandwidth.

## Artifact size

Measured on the same home directory: **2,473,068 entries in a 1.09 GB
inventory**, roughly 440 bytes an entry. Most of that is the path text, which in
a tree full of dependency directories runs long.

Storing each path's raw bytes alongside its text cost 22% on top of that and
bought nothing on the machine measured, where **zero** of the 2.47 million paths
needed them. The bytes are now kept only where the text form would lose
something — see the storage module for why that case still has to be handled.

Prefix compression would cut the remainder substantially, and is deliberately not
done yet: it trades away some of how legible the file is to someone poking at it
in a database browser, which is a promise (DR-3) rather than a nicety. The figure
above is the baseline any such change has to beat by enough to be worth it.

## Stack

Every version below was verified against its registry on 2026-08-24 and is pinned
in `Cargo.toml` and `package.json`. Rows marked *later* are chosen but not yet in
use; they arrive with the stage that needs them.

| Concern | Choice | Version |
|---|---|---|
| Core language | Rust, edition 2024 | 1.98 |
| Desktop shell | Tauri · tauri-plugin-dialog | 2.11 · 2.7 |
| Interface | React · TypeScript · Vite · Tailwind | 19.2 · 7.0 · 8.2 · 4.3 |
| Virtualized lists | TanStack Virtual | 3.14 |
| Artifacts | SQLite via rusqlite, bundled | 0.40 |
| Content digest | blake3 | 1.8 |
| Perceptual image hashing | image_hasher | 3.1 · *later* |
| Content type detection | infer · file-format | 0.22 · 0.29 · *later* |
| Document text extraction | pdf-extract · docx-rs | 0.12 · 0.4 · *later* |
| Credential storage | keyring, OS keychain | 4.1 · *later* |
| macOS system bindings | objc2 · objc2-photos | 0.6 · 0.3 · *later* |
| Windows system bindings | windows | 0.62 · *later* |
| Command line | clap | 4.6 |
| Timestamps | jiff | 0.2 |

Three notes on selection. `img_hash` is the commonly recommended perceptual
hashing crate and has been unmaintained since 2021; we use the maintained fork
`image_hasher` instead. `kamadak-exif` was last released in 2024 — mature, but we
record that as a known staleness rather than discovering it later. The `trash`
crate was listed here and has been dropped: quarantine is a directory whose
contents leave it only when somebody empties it deliberately, and a system trash
that empties itself on a schedule is a worse promise than the one DR-5 makes.

**Interface stack rationale.** Tauri renders a web interface inside the operating
system's own webview. This gives us the ergonomics of web UI — rich visuals, fast
iteration, virtualized tables over hundreds of thousands of rows, side-by-side
preview — with none of the browser baggage: no listening port, no tab to lose, no
extra attack surface. It ships as an application with an icon, native file dialogs,
and drag and drop. There is one interface codebase, packaged as a desktop
application. There is no separate web build and none is planned.

**Why SQLite for artifacts.** It is queryable, durable, crash-safe, and — decisively
— readable by anything. A user can open an artifact in any SQLite client and answer
their own questions without this tool installed, which is DR-3 in practice. An
embedded key-value store would be faster to write and would fail that test.

## Cloud access

Reading the local filesystem answers most questions on its own. On macOS, iCloud
Drive, Google Drive, and OneDrive all present through File Provider, and a file
that has never been downloaded still carries its real name, real size, and full
metadata on disk. "What is backed up and what is not" is answerable with no network
access at all.

The gap is a provider whose client is not running or not installed: then the local
filesystem knows nothing about the remote side. That gap is what the optional
provider module addresses, under strict limits.

**No central OAuth application (DR-2).** We do not register one, so we never hold or
proxy anyone's credentials. The user registers their own client with their own
provider, guided step by step in the application, and supplies its identifier. The
user is the data controller. Nothing reaches us, because there is no us to reach.

This is not only a privacy position, it is the only workable one. A full Drive
inventory requires `drive.readonly` or `drive.metadata.readonly`, both *restricted*
scopes, which for a published application require annual paid third-party security
assessment. The narrow `drive.file` scope cannot enumerate a Drive at all — it sees
only files the application itself created or the user individually picked, and
selecting a folder does not grant access to its contents. A user's own client, used
by that user, sidesteps the entire question.

Apple provides no equivalent. CloudKit reaches only an application's own container,
never the user's iCloud Drive, and there is no OAuth-style iCloud API. For iCloud
the local File Provider metadata is not merely the best available source — it is the
only one.

**Provider APIs are read-only (DR-20).** Even when connected, we never write through
a cloud API. Version choices are applied through the local filesystem so the
provider's own client performs the synchronization it was built for. Writing through
both paths at once would create two writers on one dataset, which is precisely the
class of failure this tool exists to prevent.
