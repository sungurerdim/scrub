# Security

## Reporting a vulnerability

Report privately through GitHub's **Security → Report a vulnerability** on this
repository. Please do not open a public issue for a security problem.

Include what you did, what happened, and what you expected. If the issue can cause
data loss, say so first — those are triaged ahead of everything else.

## What we consider a vulnerability

This project's threat model is unusual: the most serious failures are not remote
compromise but **silent data loss** and **unintended disclosure**. All of the
following are treated as security issues:

- Any path that deletes or overwrites user data without the confirmation the design
  rules require (DR-5, DR-6)
- Any path that materializes a cloud placeholder without explicit consent (DR-11) —
  this can cost a user money and disk space without their knowledge
- Any path that leaves the filesystem in a state the journal cannot reverse (DR-10)
- Any operation applied to a file other than the one the plan identified (DR-13,
  DR-18)
- Any outbound network request the user did not initiate (DR-1, DR-2)
- Any credential written outside the operating system keychain, or any credential
  or file path appearing in logs or crash reports
- Any artifact containing data beyond what its documented schema declares

## Design commitments

These are guarantees, not intentions. A build that breaks one is broken.

**No network in the core path.** Scan, analyze, merge, and plan make no outbound
connections. Update checks are opt-in and off by default.

**No telemetry, ever.** No usage reporting, no crash reporting to us, no
analytics — not opt-out, not anonymized, not present in the code at all.

**No credentials held by the project.** We operate no OAuth application and no
server. Where a user connects a cloud account, they register their own client with
their provider; tokens live in the operating system keychain on their machine and
never leave it.

**Artifacts contain file metadata.** An inventory or analysis artifact records
paths, sizes, timestamps, and digests for the scanned scope. That is sensitive: a
file listing describes a person. Artifacts are local files under the user's
control, and the tool never transmits one. Treat them as you would a backup index —
if you share one, you are sharing a map of your storage.

## Supported versions

The project is in early development. Until the first release, only the `main`
branch is supported.
