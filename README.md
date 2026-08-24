# scrub

**See every file you own — across iCloud, Google Drive, and OneDrive — and
reorganize it without ever losing one.**

`scrub` maps what is on your machine and in your clouds, tells you what is backed
up and what is not, groups the duplicates, shows you what is actually taking up
space, and lets you design a complete reorganization before a single file moves.

It has no delete operation. It cannot overwrite a file. It never downloads a cloud
file without asking. Every change it makes is reversible in one step.

> **Status: early development.** Step 0 — artifact schemas and test fixtures.
> Nothing is releasable yet. See [`docs/PIPELINE.md`](docs/PIPELINE.md) for the
> build order.

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
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute. |
| [`SECURITY.md`](SECURITY.md) | Threat model and reporting. |

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
