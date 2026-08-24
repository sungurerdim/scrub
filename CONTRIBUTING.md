# Contributing

Thank you for considering a contribution.

## Read this first

[`docs/DESIGN-RULES.md`](docs/DESIGN-RULES.md) is binding. Every pull request is
reviewed against it, and a change that violates a rule is rejected even if it works
and even if it is an improvement in every other respect. Reviewers cite rule
numbers; contributors are welcome to do the same in the other direction.

If you believe a rule is wrong, open an issue proposing an amendment. The rules are
versioned and can change — deliberately, in the open, and never by working around
them in a pull request.

Claims about platform behaviour belong in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md), with the source they came from and
the grade of that evidence. If a change relies on how a provider behaves, verify
it against vendor documentation or measure it, and add the entry in the same pull
request. "I remember that it works this way" is not a source.

## The rules that trip people up

Three come up more than the rest.

**DR-11, reads have no side effects.** It is very easy to write code that opens a
file and, on someone's machine, triggers a multi-gigabyte download from a cloud
provider. Any code that touches a path must go through the platform layer, which
checks cloud state before deciding whether reading is permissible. Never call
`std::fs::read` on a user path directly.

**DR-13, identity comes only from content.** Timestamps and filenames are shown to
users to help them choose which copy to keep. They never participate in deciding
whether two files are the same file.

**DR-17, stages are independent.** If you find yourself wanting a stage to look at
the filesystem for something its input artifact does not carry, the answer is
almost always to add the field to the artifact schema, not to reach past the
boundary.

## Development

One command runs everything, on your machine, with no network and no CI:

```bash
scripts/check.sh            # format · lint · test · design-rule guards · Windows cross-check
scripts/check.sh --fast     # same, without the Windows cross-check
```

Enable the hook once per clone and the gate runs itself before every commit:

```bash
git config core.hooksPath .githooks
```

The gate is deliberately local. A check that only runs in CI is a check you find
out about twenty minutes late, on someone else's machine, after you have moved
on. Continuous integration is reserved here for the one thing a laptop genuinely
cannot do — running the Windows test suite on Windows.

**Windows without Windows.** Windows code paths are type-checked locally for both
`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`. `cargo check` compiles
without linking, so no MSVC toolchain is required. Install the targets once:

```bash
rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc
```

This catches every Windows compile error before it is committed. It cannot catch
Windows *runtime* behaviour — placeholder attributes, path semantics, filesystem
quirks — and that is exactly where CI earns its place.

### Design-rule guards

Two rules are enforced mechanically by `scripts/guards.py`, because remembering
them is not a strategy:

- **DR-11** — direct filesystem calls (`fs::read`, `File::open`, `OpenOptions`,
  and friends) are rejected outside `scrub-platform`. Reading a user path without
  checking cloud state first can silently pull gigabytes down from a provider. If
  the path is one the tool itself owns — an artifact, a config file — annotate the
  line above it with `// DR-11-EXEMPT: <why this is not user data>`.
- **Rule citations** — every `DR-nn` referenced in code or documentation must
  exist in `docs/DESIGN-RULES.md`, so a renumbered rule cannot leave stale
  pointers behind.

Both guards are verified against a deliberate violation before being relied on. A
guard that has never failed has never been shown to work.

Tests run against a synthetic fixture tree that is generated, not committed — a
directory containing known duplicates, simulated cloud placeholders, hard links,
copy-on-write clones, Unicode names, and long paths. Tests never run against real
user data and never require a cloud account.

Every stage ships with golden-file tests: a fixture tree in, a known artifact out,
byte-comparable across runs and across machines. If a change makes output
non-deterministic, that is a bug in the change (DR-12).

## Pull requests

- One concern per pull request.
- A bug fix comes with a regression test that fails before it and passes after.
- Interface or behaviour changes update the documentation in the same pull request.
- Anything touching the write path — quarantine, journal, apply, undo — needs tests
  covering interruption and reversal, not just the successful case.

## Licensing of contributions

Contributions are accepted under Apache-2.0, per section 5 of the licence:
contributions you submit for inclusion are licensed under the same terms, without
any additional agreement. There is no CLA to sign.
