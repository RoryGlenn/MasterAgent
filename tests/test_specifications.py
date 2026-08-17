"""Tests for the repository-native behavioral specification lifecycle."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts import specs


class SpecificationTests(unittest.TestCase):
    """Exercise validation, path safety, and archival behavior."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for path in (
            "scripts/specs.py",
            "tests/test_specifications.py",
            "docs/specifications.md",
            "AGENTS.md",
        ):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"placeholder for {path}\n", encoding="utf-8")
        for path in (
            "specs/current/development",
            "specs/changes",
            "specs/archive",
            "specs/templates",
        ):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        (self.root / "specs/README.md").write_text(
            "# Specifications\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_archived_pilot_passes(self) -> None:
        current = self._write_current("MA-SPEC-001")
        change = self._write_change(
            "0075-native-specification-lifecycle",
            status="archived",
            requirement_id="MA-SPEC-001",
            source_content=current.read_text(encoding="utf-8"),
            destination="development/MA-SPEC-001.md",
            location="archive",
        )
        self.assertTrue(change.is_dir())

        report = specs.validate_repository(self.root)

        self.assertTrue(report.ok, report.errors)
        self.assertIn("validated 1 current behavioral requirements", report.checks)

    def test_duplicate_current_requirement_is_rejected(self) -> None:
        self._write_current("MA-SPEC-001", filename="first.md")
        self._write_current("MA-SPEC-001", filename="second.md")

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                "duplicate current requirement ID MA-SPEC-001" in error
                for error in report.errors
            )
        )

    def test_broken_verification_reference_is_rejected(self) -> None:
        self._write_current(
            "MA-SPEC-001",
            verification="- `tests/does-not-exist.py`",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(any("does-not-exist.py" in error for error in report.errors))

    def test_symlink_in_specification_tree_is_rejected(self) -> None:
        target = self.root / "outside.md"
        target.write_text("outside\n", encoding="utf-8")
        link = self.root / "specs/current/development/link.md"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlinks are unavailable: {error}")

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(any("contains a symlink" in error for error in report.errors))

    def test_path_traversal_delta_is_rejected(self) -> None:
        current = self._requirement_text("MA-SPEC-001")
        change = self._write_change(
            "0075-native-specification-lifecycle",
            status="verifying",
            requirement_id="MA-SPEC-001",
            source_content=current,
            destination="development/MA-SPEC-001.md",
        )
        metadata = change / "change.toml"
        metadata.write_text(
            metadata.read_text(encoding="utf-8").replace(
                'destination = "development/MA-SPEC-001.md"',
                'destination = "../escape.md"',
            ),
            encoding="utf-8",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any("normalized relative path" in error for error in report.errors)
        )

    def test_archived_snapshot_must_match_current_requirement(self) -> None:
        current = self._write_current("MA-SPEC-001")
        changed = current.read_text(encoding="utf-8").replace(
            "The repository MUST maintain",
            "The repository SHOULD maintain",
        )
        self._write_change(
            "0075-native-specification-lifecycle",
            status="archived",
            requirement_id="MA-SPEC-001",
            source_content=changed,
            destination="development/MA-SPEC-001.md",
            location="archive",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                "differs from the latest archived snapshot" in error
                for error in report.errors
            )
        )

    def test_archive_applies_add_delta_and_moves_change(self) -> None:
        content = self._requirement_text("MA-SPEC-001")
        self._write_change(
            "0075-native-specification-lifecycle",
            status="verifying",
            requirement_id="MA-SPEC-001",
            source_content=content,
            destination="development/MA-SPEC-001.md",
        )

        archived = specs.archive_change(
            self.root,
            "0075-native-specification-lifecycle",
        )

        self.assertEqual(
            archived,
            self.root / "specs/archive/0075-native-specification-lifecycle",
        )
        self.assertFalse(
            (self.root / "specs/changes/0075-native-specification-lifecycle").exists()
        )
        current = self.root / "specs/current/development/MA-SPEC-001.md"
        self.assertEqual(current.read_text(encoding="utf-8"), content)
        self.assertIn(
            'status = "archived"',
            (archived / "change.toml").read_text(encoding="utf-8"),
        )
        report = specs.validate_repository(self.root)
        self.assertTrue(report.ok, report.errors)

    def test_archive_refuses_incomplete_tasks(self) -> None:
        content = self._requirement_text("MA-SPEC-001")
        change = self._write_change(
            "0075-native-specification-lifecycle",
            status="verifying",
            requirement_id="MA-SPEC-001",
            source_content=content,
            destination="development/MA-SPEC-001.md",
        )
        (change / "tasks.md").write_text(
            "# Tasks\n\n- [x] Implement validator\n- [ ] Run verification\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(specs.SpecificationError, "incomplete tasks"):
            specs.archive_change(self.root, "0075-native-specification-lifecycle")

    def test_active_changes_cannot_modify_the_same_requirement(self) -> None:
        content = self._requirement_text("MA-SPEC-001")
        self._write_change(
            "0075-native-specification-lifecycle",
            status="proposed",
            requirement_id="MA-SPEC-001",
            source_content=content,
            destination="development/MA-SPEC-001.md",
        )
        self._write_change(
            "0076-conflicting-specification-change",
            status="proposed",
            requirement_id="MA-SPEC-001",
            source_content=content,
            destination="development/MA-SPEC-001.md",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any("both modify MA-SPEC-001" in error for error in report.errors)
        )
        self.assertTrue(
            any(
                "both target development/MA-SPEC-001.md" in error
                for error in report.errors
            )
        )

    def test_archive_applies_modify_delta(self) -> None:
        current = self._write_current("MA-SPEC-001")
        updated = current.read_text(encoding="utf-8").replace(
            "The repository MUST maintain current behavioral requirements",
            "The repository MUST preserve current behavioral requirements",
        )
        self._write_change(
            "0075-native-specification-lifecycle",
            status="verifying",
            requirement_id="MA-SPEC-001",
            source_content=updated,
            destination="development/MA-SPEC-001.md",
            operation="modify",
        )

        specs.archive_change(self.root, "0075-native-specification-lifecycle")

        self.assertEqual(current.read_text(encoding="utf-8"), updated)
        self.assertTrue(specs.validate_repository(self.root).ok)

    def test_archive_applies_remove_delta(self) -> None:
        current = self._write_current("MA-SPEC-001")
        self._write_change(
            "0075-native-specification-lifecycle",
            status="verifying",
            requirement_id="MA-SPEC-001",
            source_content=None,
            destination="development/MA-SPEC-001.md",
            operation="remove",
        )

        specs.archive_change(self.root, "0075-native-specification-lifecycle")

        self.assertFalse(current.exists())
        self.assertTrue(specs.validate_repository(self.root).ok)

    def test_status_is_deterministic(self) -> None:
        current = self._write_current("MA-SPEC-001")
        self._write_change(
            "0075-native-specification-lifecycle",
            status="archived",
            requirement_id="MA-SPEC-001",
            source_content=current.read_text(encoding="utf-8"),
            destination="development/MA-SPEC-001.md",
            location="archive",
        )

        first = specs._format_status(self.root)
        second = specs._format_status(self.root)

        self.assertEqual(first, second)
        self.assertIn("ARCHIVE 0075-native-specification-lifecycle archived", first)

    def test_older_archived_snapshot_may_differ_after_later_modify(self) -> None:
        original = self._requirement_text("MA-SPEC-001")
        current = self._write_current("MA-SPEC-001")
        self._write_change(
            "0075-native-specification-lifecycle",
            status="archived",
            requirement_id="MA-SPEC-001",
            source_content=original,
            destination="development/MA-SPEC-001.md",
            location="archive",
        )
        updated = original.replace(
            "The repository MUST maintain current behavioral requirements",
            "The repository MUST preserve current behavioral requirements",
        )
        current.write_text(updated, encoding="utf-8")
        self._write_change(
            "0076-update-specification-requirement",
            status="archived",
            requirement_id="MA-SPEC-001",
            source_content=updated,
            destination="development/MA-SPEC-001.md",
            location="archive",
            operation="modify",
        )

        report = specs.validate_repository(self.root)

        self.assertTrue(report.ok, report.errors)

    def test_change_id_prefix_must_match_github_issue(self) -> None:
        content = self._requirement_text("MA-SPEC-001")
        self._write_change(
            "0075-native-specification-lifecycle",
            status="proposed",
            requirement_id="MA-SPEC-001",
            source_content=content,
            destination="development/MA-SPEC-001.md",
            github_issue=76,
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                "prefix does not match GitHub issue #76" in error
                for error in report.errors
            )
        )

    def test_undeclared_requirement_heading_is_rejected(self) -> None:
        content = self._requirement_text("MA-SPEC-001")
        change = self._write_change(
            "0075-native-specification-lifecycle",
            status="proposed",
            requirement_id="MA-SPEC-001",
            source_content=content,
            destination="development/MA-SPEC-001.md",
        )
        requirements = change / "requirements.md"
        requirements.write_text(
            requirements.read_text(encoding="utf-8").replace(
                "## MODIFIED\n\nNone.",
                "## MODIFIED\n\n"
                "### MA-SPEC-002 — Undeclared behavior\n\nUnexpected delta.",
            ),
            encoding="utf-8",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(any("undeclared deltas" in error for error in report.errors))

    def test_verifying_change_requires_complete_tasks(self) -> None:
        content = self._requirement_text("MA-SPEC-001")
        change = self._write_change(
            "0075-native-specification-lifecycle",
            status="verifying",
            requirement_id="MA-SPEC-001",
            source_content=content,
            destination="development/MA-SPEC-001.md",
        )
        (change / "tasks.md").write_text(
            "# Tasks\n\n- [x] Implement validator\n- [ ] Run verification\n",
            encoding="utf-8",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any("incomplete tasks for verifying" in error for error in report.errors)
        )

    def test_status_command_fails_for_invalid_repository(self) -> None:
        with redirect_stdout(io.StringIO()):
            result = specs.main(["--root", str(self.root), "status"])

        self.assertEqual(result, 0)
        (self.root / "specs/README.md").unlink()

        with redirect_stdout(io.StringIO()):
            result = specs.main(["--root", str(self.root), "status"])

        self.assertEqual(result, 1)

    def test_change_directory_symlink_is_rejected(self) -> None:
        outside = self.root / "outside-change"
        outside.mkdir()
        (outside / "change.toml").write_text("untrusted = true\n", encoding="utf-8")
        link = self.root / "specs/changes/0075-linked-change"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlinks are unavailable: {error}")

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                "change directory contains a symlink" in error
                for error in report.errors
            )
        )
        self.assertFalse(
            any("unsupported metadata fields" in error for error in report.errors)
        )

    def test_current_requirement_filename_must_match_id(self) -> None:
        self._write_current("MA-SPEC-001", filename="renamed.md")

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any("must use filename MA-SPEC-001.md" in error for error in report.errors)
        )

    def test_duplicate_required_section_is_rejected(self) -> None:
        current = self._write_current("MA-SPEC-001")
        text = current.read_text(encoding="utf-8")
        current.write_text(
            text.replace(
                "## Rationale",
                "## Requirement\n\nDuplicate.\n\n## Rationale",
            ),
            encoding="utf-8",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any("repeats sections: ## Requirement" in error for error in report.errors)
        )

    def test_two_changes_cannot_link_the_same_github_issue(self) -> None:
        first = self._requirement_text("MA-SPEC-001")
        second = self._requirement_text("MA-SPEC-002")
        self._write_change(
            "0075-first-change",
            status="proposed",
            requirement_id="MA-SPEC-001",
            source_content=first,
            destination="development/MA-SPEC-001.md",
        )
        self._write_change(
            "0075-second-change",
            status="proposed",
            requirement_id="MA-SPEC-002",
            source_content=second,
            destination="development/MA-SPEC-002.md",
        )

        report = specs.validate_repository(self.root)

        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                "GitHub issue #75 is linked by changes" in error
                for error in report.errors
            )
        )

    def _write_current(
        self,
        requirement_id: str,
        *,
        filename: str | None = None,
        verification: str = "- `tests/test_specifications.py`",
    ) -> Path:
        target = (
            self.root
            / "specs/current/development"
            / (filename or f"{requirement_id}.md")
        )
        target.write_text(
            self._requirement_text(requirement_id, verification=verification),
            encoding="utf-8",
        )
        return target

    def _requirement_text(
        self,
        requirement_id: str,
        *,
        verification: str = "- `tests/test_specifications.py`",
    ) -> str:
        return f"""# {requirement_id} — Native specification lifecycle

## Status

Active

## Requirement

The repository MUST maintain current behavioral requirements separately from
active changes.

## Rationale

Future agents need durable intent without reconstructing it from old conversations.

## Scenarios

### Current behavior remains discoverable

- GIVEN an archived behavioral change
- WHEN a developer inspects current requirements
- THEN the accepted behavior is available without reading the original issue

## Implementation

- `scripts/specs.py`
- `docs/specifications.md`

## Verification

{verification}

## History

- Introduced by GitHub issue #75.
"""

    def _write_change(
        self,
        change_id: str,
        *,
        status: str,
        requirement_id: str,
        source_content: str | None,
        destination: str,
        location: str = "changes",
        operation: str = "add",
        github_issue: int | None = None,
    ) -> Path:
        change = self.root / "specs" / location / change_id
        issue = github_issue or int(change_id.split("-", 1)[0])
        (change / "current").mkdir(parents=True)
        source_line = ""
        if source_content is not None:
            source = change / "current" / f"{requirement_id}.md"
            source.write_text(source_content, encoding="utf-8")
            source_line = f'source = "current/{requirement_id}.md"\n'
        change.joinpath("change.toml").write_text(
            f"""schema = "master-agent/change@1"
id = "{change_id}"
title = "Native specification lifecycle"
status = "{status}"
github_issue = {issue}
created = "2026-08-17"
updated = "2026-08-17"
design_required = true

[[deltas]]
operation = "{operation}"
requirement_id = "{requirement_id}"
destination = "{destination}"
{source_line}""",
            encoding="utf-8",
        )
        change.joinpath("proposal.md").write_text(
            """# Proposal

## Problem

Current behavior is fragmented.

## Desired outcome

Maintain current requirements.

## Scope

Development workflow only.

## Rationale

Reduce ambiguity.

## Alternatives considered

External frameworks.

## Non-goals

Runtime authorization.

## Risks

Documentation drift.
""",
            encoding="utf-8",
        )
        added = (
            f"### {requirement_id} — Native specification lifecycle\n\n"
            "Add the maintained behavior."
            if operation == "add"
            else "None."
        )
        modified = (
            f"### {requirement_id} — Native specification lifecycle\n\n"
            "Modify the maintained behavior."
            if operation == "modify"
            else "None."
        )
        removed = (
            f"### {requirement_id} — Native specification lifecycle\n\n"
            "Remove the maintained behavior."
            if operation == "remove"
            else "None."
        )
        change.joinpath("requirements.md").write_text(
            f"""# Requirement deltas

## ADDED

{added}

## MODIFIED

{modified}

## REMOVED

{removed}
""",
            encoding="utf-8",
        )
        change.joinpath("design.md").write_text(
            """# Design

## Approach

Use repository-owned Markdown and TOML.

## Affected components

Development scripts and documentation.

## Data flow

Change to current requirement.

## Compatibility

No runtime dependency.

## Security

Confine paths to the repository.

## Rejected alternatives

External specification tooling.
""",
            encoding="utf-8",
        )
        change.joinpath("tasks.md").write_text(
            """# Tasks

- [x] Implement validator
- [x] Add verification
""",
            encoding="utf-8",
        )
        return change


class RepositorySpecificationIntegrationTests(unittest.TestCase):
    """Verify the checked-in pilot and source-distribution wiring."""

    def test_checked_in_specifications_validate(self) -> None:
        root = Path(__file__).resolve().parents[1]

        report = specs.validate_repository(root)

        self.assertTrue(report.ok, report.errors)
        self.assertIn("validated 8 current behavioral requirements", report.checks)

    def test_source_manifest_includes_specification_tree(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = (root / "MANIFEST.in").read_text(encoding="utf-8")

        self.assertIn("recursive-include specs *", manifest)

    def test_ci_validates_source_and_extracted_specifications(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertGreaterEqual(workflow.count("scripts/specs.py validate"), 2)


if __name__ == "__main__":
    unittest.main()
