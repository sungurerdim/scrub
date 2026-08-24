# Design Rules

These rules are binding. They are not aspirations, style preferences, or things we
try to do when convenient. Every pull request is reviewed against this document,
and a change that violates a rule is wrong even if it works, even if it is faster,
and even if a user asked for it.

Where a rule and a feature conflict, the rule wins and the feature is redesigned.

Rules are numbered permanently. A rule is never renumbered or reused; a retired
rule keeps its number and is marked retired, with the reason and the date.

---

## A. Sovereignty

The user owns their data, their machine, and their decisions. We are a tool they
run, not a service they depend on.

### DR-1 — Local first

The core path works entirely on the local machine and requires no network
connection. Scanning, analysis, comparison, and planning never contact a server.
Any feature that cannot work offline is an optional module, not part of the core.

### DR-2 — Vendor independence

There is no central server, no hosted component, no account, no registration, and
no telemetry. We do not operate an OAuth application, so we never hold, proxy, or
see a user's cloud credentials. Where cloud API access is used at all, the user
registers their own OAuth client with their own provider and remains the sole data
controller. The project can be abandoned tomorrow and every installed copy keeps
working.

### DR-3 — Data belongs to the user

Every artifact this tool produces is stored in an open, documented, queryable
format (SQLite, with a documented schema and a plain-text export). A user must be
able to read, query, back up, and move their data without this tool installed. No
proprietary container, no opaque blob, no format that only we can parse.

### DR-4 — Permission class is a cost

The core path runs with the lowest privilege that gets the job done. Any capability
that raises the permission class — photo library access, cloud API tokens, full
disk access — is an optional module. If the user does not enable that module, the
permission is never requested, not at install, not at first run, not ever.

---

## B. Non-destruction

The user's fear of losing a file is the reason this tool exists. Every rule in this
section exists to make that loss structurally impossible rather than unlikely.

### DR-5 — There is no delete

The tool has no operation that destroys data. Files are moved to quarantine, never
removed. Quarantine is emptied only by a separate, explicit, deliberately
inconvenient action that the user initiates and confirms. No code path, no flag, no
configuration setting turns an ordinary operation into a destructive one.

### DR-6 — There is no overwrite

Writing to a path that already holds different content is not an operation this
tool can perform. When a destination is occupied, the content is hashed and
compared. Identical content means the operation is already satisfied and is
skipped. Different content is a **decision point**: the operation halts, both
versions are presented side by side with size, timestamps, digest, and preview, and
the user chooses. A conflict is never resolved by a default, a heuristic, or a
timestamp comparison.

### DR-7 — Every mutation is atomic and journaled

Writes go to a temporary file, are verified by digest, and only then are moved into
place by an atomic rename. A partially written file never occupies the destination
name. Every step is journaled before and after it executes, so an interrupted run
is detected on the next start and either completed or rolled back.

### DR-8 — Plan, approve, and apply are separate

No write happens except as the execution of a plan the user has seen and approved.
The plan states every operation in full before any of them run. If the filesystem
changed between planning and applying, the affected operation halts and is
reported; it is never silently adapted.

### DR-9 — Editing is virtual

Everything the user does in the interface — creating folders, moving, renaming,
merging, marking duplicates — accumulates in a draft layer and touches nothing on
disk. The draft can be explored, undone, abandoned, saved, exported, and reviewed
on another machine. Only an explicit apply step, preceded by an old-versus-new
diff of the entire draft, turns it into filesystem changes.

### DR-10 — No unrecoverable state

Every write operation has a single-step reversal. The undo path is a first-class
stage of the pipeline with the same testing, the same journaling, and the same
guarantees as the forward path — not an afterthought or a recovery mode.

---

## C. Truth

The tool's claims must be true. A tool that is confidently wrong about which files
are duplicates, or how much space the user will reclaim, is worse than no tool.

### DR-11 — Reads have no side effects

Scanning never modifies anything: not content, not access times, not modification
times, not extended attributes. Cloud placeholder files are never materialized.
This is enforced at the operating-system level — the process sets a policy under
which an accidental read of a dehydrated file *fails* rather than silently
triggering a multi-gigabyte download. Hydration happens only when the user
explicitly asks for it, having been told what will be downloaded and how large it
is.

### DR-12 — Determinism, no inference

There is no AI, no model, no statistical guess anywhere in the decision path. Every
classification, grouping, and recommendation follows a written rule, and the
interface can answer "why is this here?" with that rule. Identical input produces
identical output, on any machine, in any version that declares the same schema.

### DR-13 — Identity comes only from content

Two files are the same file if and only if their content is identical. Name, path,
timestamps, permissions, and provider metadata never participate in that decision.
A copy created on a different date is still the same file. Identity is established
by a cryptographic digest (BLAKE3-256); provider-supplied checksums may be used to
*narrow candidates* but never to *conclude identity*.

### DR-14 — Certainty tiers are never mixed

Exact matches and similarity matches are separate categories, separately labeled,
separately colored, and separately counted. Similarity — perceptual image hashing,
document text overlap — never triggers an automatic action and never enters a
batch operation by default. The user sees which tier each group belongs to without
having to ask.

### DR-15 — Uncertainty is stated, with alternatives

When identity cannot be established — the file is a cloud placeholder we refuse to
download, the file is locked, permission is denied — the group is labeled
**candidate**, not confirmed. The interface then presents the secondary evidence it
does have (exact byte size, provider checksum, embedded metadata) and offers the
concrete path to certainty: what would need to be downloaded, and how much. A
candidate group never triggers an automatic action.

### DR-16 — Capacity claims reflect physical reality

Space that would be reclaimed is computed from what the filesystem actually
allocates. Hard links, copy-on-write clones, sparse files, and dehydrated
placeholders are detected and labeled, and never counted as reclaimable space they
would not actually free. The tool would rather report a smaller number than a
number the user cannot verify.

---

### DR-22 — Symbolic links are recorded, never followed

Whether a file is backed up is decided by where it physically lives, never by
whether some path can reach it. Traversal does not follow symbolic links, and a
file is attributed to a provider only when its own path lies inside that
provider's directory.

This rule was written after observing both of its failure modes on one machine.
A user's iCloud Drive contained links pointing outward to a Desktop and Documents
that were *not* synchronized; following them would have reported those folders as
backed up when losing them would have lost them for good. The same machine's
Google Drive reached its main folder through a link pointing outward; refusing to
look would have silently omitted the entire drive from the inventory.

The two are indistinguishable from the filesystem, so the tool does not guess. A
link at the top of a provider directory whose target lies outside every known
provider directory is recorded as an **unresolved link** and put to the user:
this is here, it points there, does it belong to this provider? Until answered,
its target is neither scanned as cloud content nor silently dropped.

## D. Pipeline

The tool is a chain of independent stages connected by durable artifacts. This is
what makes every claim above auditable rather than merely asserted.

### DR-17 — Stages are independent

Each stage reads exactly one input artifact and writes exactly one output artifact.
A stage never consults the filesystem for information that should have come from
its input, and never carries hidden state between runs. Any stage can be run,
re-run, inspected, and tested in isolation.

### DR-18 — The chain is verified, not assumed

Every artifact records the digest of the artifact it was derived from, along with
the tool version, the schema version, and the machine identity. A stage refuses to
run on an input whose chain does not match: a plan built from a different scan, a
plan built for a different machine, or a plan built by an incompatible version is
rejected rather than adapted.

### DR-19 — Verification and mutation never share a pass

Checking whether an operation is safe and performing that operation are separate
stages producing separate artifacts. The preflight stage writes nothing to the
filesystem and grades every operation independently. The apply stage executes only
the operations preflight passed. The user learns about every problem before
anything is touched, not at operation forty-seven of two hundred.

---

## E. Restraint

### DR-20 — Minimal intervention

Touch only what must be touched, only where it must be touched. We do not
reimplement, replace, or work around the platform's own sync clients — they own
synchronization and they are better at it than we would be. Cloud APIs are used
for reading only; writes go through the local filesystem so the provider's client
performs the sync it was designed to perform. We do not manage libraries that
maintain their own databases (photo libraries) from the outside; we use their
sanctioned API or we leave them alone.

### DR-21 — Calm surface, depth on demand

The default view carries the minimum information needed to make the next decision.
A duplicate group is one row, one object — not five rows. Detail expands only when
requested. Complexity is not removed from the tool; it is kept out of the way until
the user reaches for it.

---

## Applying these rules

A reviewer asking "does this change comply?" should be able to point at a rule
number. A contributor who believes a rule is wrong should open an issue proposing
its amendment rather than working around it — these rules are versioned and can
change, but only deliberately and in the open.
