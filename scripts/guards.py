#!/usr/bin/env python3
"""Mechanical guards for design rules that a compiler cannot enforce.

Each guard turns a rule from `docs/DESIGN-RULES.md` into a check that fails a
build rather than a paragraph someone is expected to remember. Run by
`scripts/check.sh`; exits non-zero on the first rule violated.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "docs" / "DESIGN-RULES.md"

# Direct filesystem access on a user path can materialize a cloud placeholder and
# trigger a silent multi-gigabyte download (DR-11). Every such call must go
# through the platform layer, which checks cloud state first.
UNGUARDED_FS = re.compile(
    r"\b(?:std::)?fs::(?:read|read_to_string|read_dir|write|copy|rename|remove_file|remove_dir\w*)\b"
    r"|\bFile::(?:open|create)\b"
    r"|\bOpenOptions::new\b"
)

# Crates permitted to reach the filesystem directly. Everything else must ask the
# platform layer.
FS_ALLOWED_CRATES = {"scrub-platform"}

# Integration tests build the trees they run against, which is direct filesystem
# work by definition. Annotating every fixture line would be noise, and noise
# teaches people to add the annotation reflexively, which is exactly how a guard
# stops guarding. Tests are separately forbidden from touching real user data
# (see CONTRIBUTING.md).
def is_test_file(path: Path) -> bool:
    return "tests" in path.relative_to(ROOT).parts

# Escape hatch for lines that provably touch a path the tool itself owns — an
# artifact file, a config file — rather than user data.
EXEMPT = "DR-11-EXEMPT:"

DR_REFERENCE = re.compile(r"\bDR-(\d+)\b")


def fail(message: str) -> None:
    print(f"guard failed: {message}", file=sys.stderr)
    sys.exit(1)


def rust_sources() -> list[Path]:
    return sorted(p for p in (ROOT / "crates").rglob("*.rs") if "/target/" not in str(p))


def crate_of(path: Path) -> str:
    relative = path.relative_to(ROOT / "crates")
    return relative.parts[0]


def guard_filesystem_access() -> None:
    """DR-11: reads have no side effects, enforced by routing all access."""
    offences: list[str] = []
    for source in rust_sources():
        if crate_of(source) in FS_ALLOWED_CRATES or is_test_file(source):
            continue
        lines = source.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            if not UNGUARDED_FS.search(line):
                continue
            if EXEMPT in line or exempted_by_comment_above(lines, number):
                continue
            relative = source.relative_to(ROOT)
            offences.append(f"  {relative}:{number}: {line.strip()}")

    if offences:
        fail(
            "DR-11 — direct filesystem access outside the platform layer.\n"
            "Reading a user path without checking cloud state first can trigger a\n"
            "silent download. Route it through scrub-platform, or if the path is one\n"
            "the tool itself owns, annotate the line above with:\n"
            f"    // {EXEMPT} <why this path is not user data>\n\n"
            + "\n".join(offences)
        )


def exempted_by_comment_above(lines: list[str], number: int) -> bool:
    """Whether the run of comment lines directly above carries the exemption.

    Looks back through the whole comment block rather than at a single line: an
    exemption worth granting usually needs a sentence to justify it, and a
    sentence wraps.
    """
    index = number - 2
    while index >= 0:
        stripped = lines[index].strip()
        if not stripped.startswith("//"):
            return False
        if EXEMPT in stripped:
            return True
        index -= 1
    return False


def guard_rule_references() -> None:
    """Every DR-nn cited anywhere must exist as a rule, so citations cannot rot."""
    defined = {
        int(match)
        for match in re.findall(r"^### DR-(\d+) —", RULES.read_text(encoding="utf-8"), re.M)
    }
    if not defined:
        fail(f"no rules found in {RULES.relative_to(ROOT)} — is the heading format still `### DR-n —`?")

    searched = rust_sources() + sorted((ROOT / "docs").glob("*.md")) + [
        ROOT / "README.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "SECURITY.md",
    ]

    dangling: list[str] = []
    for source in searched:
        if source == RULES or not source.exists():
            continue
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            for cited in DR_REFERENCE.findall(line):
                if int(cited) not in defined:
                    relative = source.relative_to(ROOT)
                    dangling.append(f"  {relative}:{number}: cites DR-{cited}, which does not exist")

    if dangling:
        fail(
            "dangling design-rule citations. A rule was renumbered or removed and\n"
            "something still points at it:\n\n" + "\n".join(dangling)
        )


def main() -> None:
    guard_filesystem_access()
    guard_rule_references()
    print("guards: ok")


if __name__ == "__main__":
    main()
