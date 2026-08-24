# scrub

**See every file you own — across iCloud, Google Drive, and OneDrive — and
reorganize it without ever losing one.**

`scrub` maps what is on your machine and in your clouds, tells you what is backed
up and what is not, groups the duplicates, shows you what is actually taking up
space, and lets you design a complete reorganization before a single file moves.

It has no delete operation. It cannot overwrite a file. It never downloads a cloud
file without asking. Every change it makes is reversible in one step.

> **Status: early development.** All seven stages work end to end — scan,
> analyze, merge, plan, preflight, apply, undo — and a run followed by its
> reversal leaves the tree byte-identical. There is no interface yet beyond the
> command line, and it has been exercised on macOS only. See
> [`docs/PIPELINE.md`](docs/PIPELINE.md) for what each stage does.

---

## The problem

You have files in iCloud. You have files in Google Drive. You have no reliable way
to know which directories are actually synchronized, which files exist in both
places, or which files are backed up nowhere at all. One cloud is full while
another has room, and moving between them by hand means trusting yourself not to
make a single irreversible mistake across thousands of files.

Existing tools solve pieces of this. They tend to solve them by asking you to trust
a cloud service with your file index, or by offering a "clean up" button whose
behavior you cannot audit.

## The approach

**Nothing is deleted.** Files go to quarantine, which is emptied only by a separate
deliberate action. There is no code path that destroys data.

**Nothing is overwritten.** A destination that already holds different content is a
decision you make, with both versions shown side by side — not a conflict resolved
by a timestamp rule while you look away.

**Nothing is downloaded behind your back.** Cloud files that are not on your disk
stay that way. The scanner runs under an operating-system policy where accidentally
reading a cloud-only file *fails* rather than quietly pulling gigabytes down. If
certainty about a file requires downloading it, you are told exactly which files
and how many megabytes, and you decide.

**Nothing happens until you say so.** You rearrange, rename, create folders, and
resolve duplicates in a draft that touches nothing. When you are satisfied, you see
a complete before-and-after of everything that will change, and approve it.

**No AI, no guessing.** Every grouping and recommendation follows a written rule the
interface can show you. Two files are the same file only when their contents are
identical — never because their names or dates line up.

**No servers, no accounts, no telemetry.** Everything runs on your machine. There is
no hosted component to trust and nothing to sign up for. If cloud API access is
ever used, you register your own client with your own provider and remain the only
party holding your credentials.

## How it works

Seven independent stages, connected by files you can open and inspect:

```
scan → analyze → merge → plan → preflight → apply → undo
```

The interface shows three steps — **Discover**, **Organize**, **Apply**. The stages
underneath produce durable artifacts: standard SQLite databases you can query,
archive, diff, and hand to someone else. Every artifact records which artifact it
came from, and a stage refuses to run on a mismatched chain — applying the right
plan to the wrong machine is unreachable by design, not merely discouraged.

One consequence worth calling out: planning needs only the analysis artifact, not
the files. Someone can scan their own machine, send you the result, and you can
design their reorganization on yours and send back a plan for them to apply.

Full detail: [`docs/PIPELINE.md`](docs/PIPELINE.md).

## Trying it

There are two ways in, and they run the same code. The window is the one to
start with; the command line does everything the window does and is what you
want if you would rather script than click.

### The window

```bash
cd apps/desktop
pnpm install
pnpm tauri dev        # or `pnpm tauri build` for an application you can keep
```

Four steps, in order. **Discover** says what this machine synchronises and,
before any other number, which folders sit inside a cloud directory without
being backed up. **Organize** finds what is duplicated, shows each set as one
row, and lets you choose which copy to keep. **Arrange** is a file browser where
you make folders, rename things and move them about — and none of it touches a
disk, so you can change your mind as many times as you like, or take the last
change back. **Apply** shows the before and after, checks every step against the
disk, asks once in plain words, and only then moves anything — into a quarantine
folder, never to a wastebasket, with a record that puts it all back.

Artifacts are kept in the platform's application-data directory, or wherever you
point `SCRUB_WORKSPACE`.

### The command line

```bash
cargo build --release -p scrub-cli

./target/release/scrub scan                       # your home directory
./target/release/scrub analyze scan.inventory     # what is the same as what
./target/release/scrub plan scan.analysis         # what should happen about it
./target/release/scrub preflight scan.plan        # check it, changing nothing
./target/release/scrub apply scan.preflight       # carry it out
./target/release/scrub undo scan.journal          # put it all back

./target/release/scrub inspect scan.journal       # summarise any artifact
./target/release/scrub export scan.inventory      # newline-delimited JSON
```

To compare two machines, each one scans and analyses itself, then the two
artifacts are brought together anywhere — on either machine, or on a third that
holds neither set of files:

```bash
# on each machine
scrub scan && scrub analyze scan.inventory --thorough -o mac.analysis

# anywhere, with both files to hand
scrub merge mac.analysis windows.analysis
```

```
Comparing 2 machines
  mac                  2 of 2 files carry a fingerprint
  windows              2 of 2 files carry a fingerprint

Held in more than one place
  1 file(s), 15 bytes of content

Held in one place only
  mac                  1 file(s) that no other machine has a copy of
  windows              1 file(s) that no other machine has a copy of
```

A scan opens no files at all. An analysis opens only files already on your disk,
and reads most of them just at both ends — enough to separate almost everything
that merely shares a size, without reading it through. On macOS both run under a
kernel policy that makes an accidental download fail rather than happen, and they
say so if the system refuses to grant it.

Anything held only in the cloud is reported as unchecked, never guessed at, with
the exact cost of settling it:

```
4 group(s) could not be checked, because their content is not on
this machine. They are not counted above.
Settling them would download 5.4 kB.
```

The artifact is an ordinary SQLite database, so you never have to take the
summary's word for anything:

```bash
sqlite3 scan.inventory "SELECT path_text, logical_size FROM entry
                        WHERE cloud LIKE '%remote%' ORDER BY logical_size DESC LIMIT 20;"
```

Planning changes nothing. It produces a document you can read, keep, hand to
somebody else, and throw away:

```
Plan
  Keeping the copy modified longest ago.
  Nothing has happened. This is what would.

  SET ASIDE  2 file(s), freeing 8.1 kB
    Set aside means moved to quarantine, not deleted. Nothing leaves
    quarantine until you empty it yourself.
    Desktop/old/tax-kopya.pdf
      same content as Documents/tax.pdf

  No conflicts: every destination is free.
```

Conflicts — two files wanting the same destination, or a destination already
occupied — are found here, while the plan is still a document. Not at operation
four hundred with three hundred and ninety-nine already done.

Then preflight checks the plan against the disk, reading every file again and
writing nothing, and grades each operation on its own. Only what passed is
carried out, each change recorded before it is attempted:

```
Run
  Finished.

  2 change(s) made, freeing 8.1 kB

  Everything set aside is in:
    scan.quarantine
  Nothing has been deleted. It stays there until you empty it.

  To put it all back:  scrub undo scan.journal
```

`scrub undo` uses the same machinery in reverse, so undo is ordinary rather than
a recovery mode with its own bugs. It refuses to put a file back on top of
something that has taken its name since, and it leaves alone any folder somebody
has used in the meantime.

## Platforms

macOS and Windows. Linux is not in the first release — iCloud does not exist there
and neither Google nor Microsoft ships an official client, so it needs a detection
layer of its own.

## Documentation

| | |
|---|---|
| [`docs/DESIGN-RULES.md`](docs/DESIGN-RULES.md) | The binding rules. Every change is reviewed against them. |
| [`docs/PIPELINE.md`](docs/PIPELINE.md) | The seven stages, their artifacts, and the build order. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Crate layout, platform layer, dependency choices. |
| [`docs/VERIFICATION.md`](docs/VERIFICATION.md) | Every platform behaviour the design relies on, with where it was verified. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute. |
| [`SECURITY.md`](SECURITY.md) | Threat model and reporting. |

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
