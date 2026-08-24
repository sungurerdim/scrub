# Pipeline

`scrub` is not one program that does everything. It is seven independent stages
connected by six durable artifacts. Each stage reads one artifact and writes one
artifact. Nothing is passed in memory, nothing is hidden in a cache, and no stage
consults the filesystem for something its input should have carried (DR-17).

This is what makes the tool auditable: every claim it makes is written down in a
file you can open, query, diff, archive, and hand to someone else.

```
                   ┌──────────────┐
   filesystem ────>│  1. scan     │───> inventory     metadata only, zero reads
                   └──────────────┘
                   ┌──────────────┐
   inventory ─────>│  2. analyze  │───> analysis      identity, categories, similarity
                   └──────────────┘
                   ┌──────────────┐
   analysis × N ──>│  3. merge    │───> analysis      cross-device unified view (optional)
                   └──────────────┘
                   ┌──────────────┐
   analysis ──────>│  4. plan     │───> plan          virtual editing, old ↔ new diff
                   └──────────────┘
                   ┌──────────────┐
   plan ──────────>│  5. preflight│───> preflight     grade every operation, write nothing
                   └──────────────┘
                   ┌──────────────┐
   preflight ─────>│  6. apply    │───> journal       execute passing operations only
                   └──────────────┘
                   ┌──────────────┐
   journal ───────>│  7. undo     │───> journal       reverse an applied run
                   └──────────────┘
```

The graphical interface presents this as three steps — **Discover**, **Organize**,
**Apply**. The seven stages live underneath, in the command line and in the
artifacts on disk. Ease of use and auditability are not in tension here; they are
different views of the same chain.

---

## Chain integrity

Every artifact carries a header:

| Field | Meaning |
|---|---|
| `schema_version` | The artifact schema this file conforms to |
| `tool_version` | The `scrub` version that produced it |
| `stage` | Which stage produced it |
| `parent_digest` | BLAKE3-256 of the input artifact, or null for `scan` |
| `machine_id` | Stable, non-identifying, locally generated machine identity |
| `created_at` | RFC 3339 timestamp, with timezone offset |
| `scope_digest` | Digest of the scan scope configuration |

A stage **refuses to run** when the header does not line up (DR-18):

- a plan whose `parent_digest` does not match the analysis being supplied
- a plan produced on a different `machine_id` than the machine applying it
- an artifact whose `schema_version` this build does not implement

These are hard failures with an explanatory message, never a warning the user can
click past and never something the tool silently adapts to. Applying the right
plan to the wrong machine is not a mistake we guard against with care; it is a
state the format makes unreachable.

`machine_id` is generated locally at first run and is a random identifier. It is
never derived from hardware serials, user names, network addresses, or anything
else that identifies a person or a device to a third party.

---

## Artifacts

All artifacts are SQLite databases with a documented schema (DR-3), each
accompanied by a stable NDJSON export for diffing and for tools that would rather
not open a database. They are self-contained files. You can copy one to another
machine, open it with any SQLite client, and query it without `scrub` installed.

### 1. `inventory`

Produced by **scan**. Pure filesystem metadata, collected without opening a single
file (DR-11).

Per entry: absolute path, entry type, logical size, allocated size, timestamps
(created / modified / accessed as the platform reports them), permissions, inode
or file id, link count, and the platform's cloud-state facts — which sync provider
owns the path, whether the object is materialized or dehydrated, whether it is
pinned to the device.

Also recorded, once per run: the sync topology. Which directories are synchronized
to which provider, including redirected home directories, application containers,
provider trash areas, and any directory that turns out to be synchronized to
nothing at all.

Alongside it, the **unresolved links** (DR-22): symbolic links leading out of a
provider directory to somewhere outside every provider directory. These are
recorded rather than resolved, because the same shape means opposite things — a
link out of iCloud Drive to an unsynchronized Desktop, and a link out of a Google
Drive mount to that drive's main folder, look identical from the filesystem. Each
one becomes a question the interface puts to the user before anything downstream
treats its target as backed up or as missing.

**Cost:** minutes on a large tree. **Risk:** none. No file is opened.

### 2. `analysis`

Produced by **analyze**, consuming an `inventory`. This is where the expensive work
happens, and it is separate precisely because it is expensive: you can re-run it
with different settings — turning on document similarity, widening the perceptual
threshold — without walking the tree again.

Adds: content digests where they could be taken, exact-duplicate groups,
perceptual-similarity groups for images, text-similarity groups for documents,
category assignments, and for every group a **certainty tier** (DR-14) and, where
identity could not be established, the reason plus the available secondary
evidence (DR-15).

Digest strategy, in order: entries of differing size can never match and are never
read. Same-size candidates get a head-and-tail quick digest. Survivors get a full
BLAKE3-256. Dehydrated files are never read (DR-11) and become candidate-tier
entries carrying whatever provider checksum and metadata is available.

**Cost:** minutes to hours, proportional to how much genuinely needs reading.
**Risk:** none. Reads are non-mutating and no download is triggered.

### 3. `merge` (optional)

Consumes two or more `analysis` artifacts from different machines and produces one
unified `analysis`. This is how a Mac and a Windows machine are compared: each runs
scan and analyze locally, and the resulting artifacts are brought together
anywhere — including on a third machine that holds neither set of files.

Cross-device identity uses the same rule as everything else: content, and only
content (DR-13).

### 4. `plan`

Produced by **plan**, consuming an `analysis`. This is the draft layer (DR-9). Every
folder creation, move, rename, merge, and duplicate resolution the user expressed,
recorded as intent — never as a completed action.

The plan stores the desired end state and the operations that reach it. Operations
are normalized before they are written: a file dragged through three folders
becomes one move, a rename never degrades into a copy-and-delete, and operations
are ordered so that no intermediate state collides.

Every operation records its source identity — path *and* digest *and* size *and*
modification time — so the later stages can prove they are acting on the file the
user actually chose.

Because `plan` reads only an `analysis`, planning does not require the files. A
plan can be produced on a machine that has never seen them, reviewed by someone
else, and carried back.

### 5. `preflight`

Produced by **preflight**, consuming a `plan`. **Writes nothing** (DR-19).

Every operation is independently graded:

| Grade | Meaning |
|---|---|
| **pass** | Source is present and matches its recorded identity; destination is free; space, permissions, and sync state are all satisfactory |
| **hold** | Something changed or is unresolved — the source moved, was edited, the destination is now occupied, sync is mid-flight — stated precisely, with what would resolve it |
| **fail** | The operation cannot proceed as written and needs replanning |

The result is a complete account of what will happen and what will not, produced
before anything at all has been touched. `hold` and `fail` items can be exported
back into a new planning session.

### 6. `journal`

Produced by **apply**, consuming a `preflight`. Only `pass` operations execute.

Each operation is written to the journal before it begins and again after it
completes, with enough recorded to reverse it. If the source drifted between
preflight and execution — someone edited the file in the intervening seconds — that
single operation stops, is journaled as skipped with the reason, and the run
continues with the rest (DR-8). The final report lists every skipped item.

Apply is idempotent and crash-safe. Re-running it against the same journal
recognizes completed work and resumes from the interruption.

### 7. `undo`

Consumes a `journal` and reverses it, producing a journal of its own (DR-10). Undo
is an ordinary stage with ordinary guarantees, not a special recovery mode.

---

## Development order

Stages are built one at a time, in order, each locked by its tests before the next
begins. The artifact schemas are designed **together, first** — otherwise stage
four discovers that stage one never recorded a field it needs, and the whole point
of sequential development is lost.

```
Step 0   artifact schemas · chain integrity · synthetic test fixtures
1  scan       ┐
2  analyze    │  Phase 1 — read-only. The first release.
3  merge      │  Nothing on disk is ever modified.
4  plan       ┘
5  preflight  ┐
6  apply      │  Phase 2 — writes, quarantine, reversal.
7  undo       ┘
```

Every stage ships the same way: schema, core implementation, command-line command,
golden-file tests against the synthetic fixture tree, then its panel in the
interface.

Phase 1 delivers the complete editing experience with no write capability at all.
You can scan, compare across machines, group duplicates, and design the entire
reorganization — and the tool still has no code path that modifies a file.
