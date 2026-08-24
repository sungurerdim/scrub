# Verification ledger

This tool makes claims about a person's files: this one is backed up, that one is
not, these two are the same, removing this frees that much space. A claim that is
confidently wrong is worse than no claim at all, so every platform behaviour the
design depends on is recorded here with where it was verified and how.

Entries are ordered by how much damage a wrong answer would do.

**Evidence grades.** *Specified* — stated in vendor documentation or a system
header on the machine. *Observed* — measured directly, reproducibly, on a real
machine. *Reported* — consistent community accounts, no vendor statement found.
Nothing is graded on memory.

---

## Cloud placeholders

### A file that is not downloaded looks completely ordinary

**Grade: specified.** `chflags(2)`, macOS SDK: "SF_DATALESS — The file is a
dataless placeholder. The system will attempt to materialize it when accessed
according to the dataless file materialization policy of the accessing thread or
process." The flag is `0x40000000` in `sys/stat.h`. The same page states the flag
is internal and cannot be set from user space, so it is a trustworthy signal
rather than something an application can fake.

**Consequence:** name, size, timestamps and extended attributes are all present on
a file whose bytes are not. Nothing short of checking this flag distinguishes it
from a real file.

### Reading such a file can be made to fail instead of downloading

**Grade: specified.** `read(2)`: "[EDEADLK] The file is a 'dataless' file that
requires materialization and the I/O policy of the current thread or process
disallows dataless file materialization." `getiopolicy_np(3)` documents
`IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES` with the value
`IOPOL_MATERIALIZE_DATALESS_FILES_OFF`, and `setiopolicy_np(3)`'s signature is
`setiopolicy_np(int iotype, int scope, int policy)`.

**Consequence:** DR-11 is enforced by the kernel. The process asks once at start-up
and an accidental read afterwards fails rather than costing the user bandwidth.

**Also specified:** the same man page notes that at process scope the *system
default* is already `_OFF`, and that children inherit the parent's policy. We set
it explicitly regardless, because relying on a default we do not control is not a
guarantee.

### Directories can be dataless too, and that is the sharper edge

**Grade: specified.** `open(2)` and `openat(2)`: "[EDEADLK] A component of the
pathname refers to a 'dataless' directory that requires materialization and the
I/O policy of the current thread or process disallows dataless directory
materialization." `read(2)` additionally documents `[ETIMEDOUT]` for a
materialization that "timed out or encountered some other temporary failure".

Notably, `stat(2)`, `lstat(2)`, `getdirentries(2)` and `opendir(3)` do **not**
document dataless errors, which is consistent with Apple's advice to check the
flag with `stat` before touching anything.

**Consequence:** enumerating a directory can fail with `EDEADLK`, and a scanner
that treats that as "empty" would report every file inside it as missing. That is
a false claim a user could act on, which is why DR-23 exists.

### Windows marks placeholders with attributes, and with reparse tags

**Grade: specified.** Microsoft's file attribute reference gives
`FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x00400000, "not fully present locally"),
`FILE_ATTRIBUTE_RECALL_ON_OPEN` (0x00040000, "no physical representation on the
local system; the item is virtual"), `FILE_ATTRIBUTE_OFFLINE` (0x00001000),
`FILE_ATTRIBUTE_PINNED` (0x00080000) and `FILE_ATTRIBUTE_UNPINNED` (0x00100000).

Microsoft's reparse point tag reference lists `IO_REPARSE_TAG_CLOUD` through
`IO_REPARSE_TAG_CLOUD_F` with `IO_REPARSE_TAG_CLOUD_MASK`, plus
`IO_REPARSE_TAG_ONEDRIVE`, `IO_REPARSE_TAG_FILE_PLACEHOLDER` and
`IO_REPARSE_TAG_STORAGE_SYNC` — all distinct from `IO_REPARSE_TAG_SYMLINK` and
`IO_REPARSE_TAG_MOUNT_POINT`. The same page documents the **name surrogate bit**,
set only when "the file or directory represents another named entity in the
system", and states the tag can be read from `FindFirstFile`'s `dwReserved0`
during enumeration — with no file handle, and therefore no hydration.

**Consequence:** on Windows a cloud placeholder *is* a reparse point, so asking
"is this a symlink?" the ordinary way answers yes for every online-only file. The
correct question is the reparse tag and its name-surrogate bit. This is recorded
as a known gap in the Windows implementation rather than guessed at, because it
cannot be verified from a macOS machine.

---

## Symbolic links

The most dangerous ambiguity in the whole tool. The same filesystem shape — a link
inside a provider directory pointing outside it — occurs in two situations with
opposite meanings.

### Providers do not sync what a link points to

**Grade: reported, consistently.** No vendor documents syncing the *contents* of a
linked-in folder, and both vendors document the opposite in effect. Microsoft
states OneDrive does not support syncing through symbolic links or junction
points, describes it as intentional, and offers no workaround; reported failure
modes include indefinite "processing changes", one-way sync, silent months-long
failure and data duplication. For iCloud Drive, the consistent account is that the
link object itself is copied while its target is not, and Apple's developer forum
position is that symbolic links have never been supported for folders with special
meaning to the system.

**Consequence:** a link inside a provider directory is *not* a backup of its
target. Reporting it as one is the failure mode that loses files.

### macOS records its own verdict, in extended attributes

**Grade: observed**, on a machine where Desktop & Documents syncing had been turned
off. Read without following the link (`ls -@`, or `xattr -s`; plain `xattr`
follows the link and reads the target instead — an easy mistake that inverts the
answer):

On the link, inside iCloud Drive:

| Attribute | Value |
|---|---|
| `com.apple.fileprovider.detached-link#P` | `1` |
| `com.apple.fileprovider.ignore#P` | the iCloud Drive file provider domain id |

On the target, in the home directory:

| Attribute | Value |
|---|---|
| `com.apple.file-provider-domain-id` | the same domain id |
| `com.apple.fileprovider.detached#B` | `{name: "Documents", parentBookmark: …/com~apple~CloudDocs}` |

Read together, macOS states plainly: this folder used to live inside iCloud Drive,
it was detached, a link was left behind, and that link is excluded from sync. It
is the filesystem representation of Apple's documented "turn off Desktop &
Documents Folders" flow, where files stay in iCloud Drive and new empty folders
are created locally.

Corroborating the same reading of the attribute: `com.apple.fileprovider.ignore#P`
is the attribute third-party tools set to exclude a directory from File Provider
sync, the counterpart of `com.dropbox.ignored`.

**Caveat, and it matters:** Apple does not document this attribute. So the
inference runs one way only. Its presence is treated as a definitive *no*; its
absence is never treated as a *yes*.

### Google Drive links outward on purpose, in mirror mode

**Grade: observed.** On the same machine, `~/Library/CloudStorage/GoogleDrive-…/`
contained `Drive'ım` (the localised "My Drive") as a symbolic link to
`~/Drive'ım`, while `Diğer bilgisayarlar` ("Other computers") was a real streamed
directory beside it.

The target contains `.tmp.drivedownload`, Drive for desktop's own staging
directory. Google documents two sync modes, streaming and mirroring; streaming
content lives under `~/Library/CloudStorage` and mirrored content lives in a local
folder, with the staging directory appearing in the mirrored folder in mirror mode
and in the `DriveFS` cache in streaming mode.

**Consequence:** here the link is the provider's own, and its target genuinely is
that drive's content. Refusing to look would omit an entire Google Drive from the
inventory — the mirror image of the iCloud mistake, and just as wrong.

### Drive shortcuts are symbolic links into a hidden directory

**Grade: reported.** Drive for desktop materialises each shortcut target once
under `.shortcut-targets-by-id/<targetId>/` and points the visible shortcut at it
with a symbolic link, so a shared folder appearing in several places is stored
once. Confirmed present in the Drive root on the machine examined.

**Consequence:** following these links counts the same bytes once per shortcut.
Since the targets sit inside the same provider directory, traversal reaches them
exactly once on its own, and the shortcuts are recorded as links rather than
descended into. Anything else inflates both the duplicate groups and the amount of
space the tool promises to recover, in violation of DR-16.

---

## Cloud APIs

### A full Drive inventory needs a restricted scope

**Grade: specified.** Google's restricted scope verification documentation
requires annual security assessment by an approved third party for a published
application using restricted scopes. `drive.file`, the non-sensitive alternative,
grants per-file access only — to files the application created or the user
individually picked — and selecting a folder does not extend access to its
contents, so it cannot enumerate a drive at all.

**Consequence:** DR-2 is not only a privacy preference here, it is the only
workable design. A user's own OAuth client, used by that user, needs no assessment
because there is no third party.

### iCloud Drive has no equivalent API at all

**Grade: specified.** CloudKit reaches an application's own container, not the
user's iCloud Drive; there is no OAuth-style API for a user's iCloud files.

**Consequence:** for iCloud, the local File Provider metadata is not the best
available source, it is the only one — which is also why the local-first design
loses nothing.

---

## Re-verifying

Everything above was checked on 2026-08-24 against macOS SDK headers and manual
pages present on the machine, vendor documentation, and direct measurement.
Platform behaviour changes. An entry that a change would invalidate should be
re-checked before that release, and the finding recorded here rather than in a
commit message where it will not be found again.
