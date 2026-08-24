# Architecture

## Layout

```
crates/
  scrub-core/       vocabulary · artifact schema · chain integrity · rule engine
  scrub-platform/   cloud state · dataless detection · traversal      one module per platform
  scrub-store/      artifacts as SQLite, and the canonical digest
  scrub-engine/     preflight · apply · quarantine · journal · undo   [Phase 2]
  scrub-providers/  read-only Drive and Graph clients, user-owned credentials   [Phase 3]
  scrub-photos/     PhotoKit bridge, macOS only, feature-gated        [Phase 4]
  scrub-cli/        every stage as a command
apps/desktop/       Tauri shell + web interface
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

`scrub-core` holds no I/O beyond reading and writing artifacts. Given the same
inventory it produces the same analysis on any machine (DR-12), which is what makes
golden-file testing possible.

The command line exists so that every stage can be exercised by machine in CI —
not as a second product surface. The graphical interface is a thin layer over the
same crates and has no logic of its own.

## Platform layer

Everything platform-specific lives behind one trait, implemented twice.

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

Both implementations answer the same questions: which provider owns this path, is
the content present locally, is it pinned, and what does the provider believe about
it. Both are covered by the same fixture-driven tests.

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

## Stack

Every version below was verified against its registry on 2026-08-24 and is pinned
in `Cargo.toml` and `package.json`.

| Concern | Choice | Version |
|---|---|---|
| Core language | Rust, edition 2024 | 1.98 |
| Desktop shell | Tauri | 2.11 |
| Interface | React · TypeScript · Vite · Tailwind | 19.2 · 7.0 · 8.2 · 4.3 |
| Virtualized tables and trees | TanStack Virtual · Table | 3.14 · 9.1 |
| Artifacts | SQLite via rusqlite, bundled | 0.40 |
| Content digest | blake3 | 1.8 |
| Parallel traversal | jwalk · rayon | 0.9 · 1.12 |
| Perceptual image hashing | image_hasher | 3.1 |
| Content type detection | infer · file-format | 0.22 · 0.29 |
| Document text extraction | pdf-extract · docx-rs | 0.12 · 0.4 |
| System trash | trash | 5.2 |
| Credential storage | keyring, OS keychain | 4.1 |
| macOS system bindings | objc2 · objc2-photos | 0.6 · 0.3 |
| Windows system bindings | windows | 0.62 |
| Command line | clap | 4.6 |

Two notes on selection. `img_hash` is the commonly recommended perceptual hashing
crate and has been unmaintained since 2021; we use the maintained fork
`image_hasher` instead. `kamadak-exif` was last released in 2024 — mature, but we
record that as a known staleness rather than discovering it later.

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
