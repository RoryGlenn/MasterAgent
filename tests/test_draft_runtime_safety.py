"""Adversarial tests for descriptor-backed create-only draft publication."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from master_agent.connectors import drafts as drafts_module
from master_agent.connectors.drafts import JiraDraftConnector
from master_agent.errors import ConnectorError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import RunReport
from master_agent.workflows import draft_package as package_module
from master_agent.workflows.draft_package import render_draft_package


class DraftRuntimeSafetyTests(unittest.TestCase):
    """Prove concurrent destination creation cannot be overwritten."""

    def test_destination_creation_race_preserves_peer_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connector = JiraDraftConnector(root)
            action = _jira_draft_action()
            real_open = os.open
            injected = False

            def create_peer_then_open(
                name: str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal injected
                if not injected and name == "jira-draft.json" and flags & os.O_EXCL:
                    injected = True
                    peer = real_open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=dir_fd,
                    )
                    try:
                        os.write(peer, b"peer-owned-bytes")
                        os.fsync(peer)
                    finally:
                        os.close(peer)
                return real_open(name, flags, mode, dir_fd=dir_fd)

            try:
                with (
                    patch.object(
                        drafts_module.os,
                        "open",
                        side_effect=create_peer_then_open,
                    ),
                    self.assertRaisesRegex(ConnectorError, "fresh output"),
                ):
                    connector.execute(action)

                self.assertEqual(
                    (root / "jira-draft.json").read_bytes(),
                    b"peer-owned-bytes",
                )
                self.assertFalse((root / "jira-draft.md").exists())
            finally:
                connector.close()

    def test_companion_collision_removes_only_transaction_owned_primary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            companion = root / "jira-draft.md"
            companion.write_bytes(b"peer-companion")
            companion.chmod(0o600)
            connector = JiraDraftConnector(root)
            try:
                with self.assertRaisesRegex(ConnectorError, "fresh output"):
                    connector.execute(_jira_draft_action())

                self.assertFalse((root / "jira-draft.json").exists())
                self.assertEqual(companion.read_bytes(), b"peer-companion")
            finally:
                connector.close()

    def test_manifest_symlink_is_rejected_without_touching_victim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim.json"
            victim.write_bytes(b"victim-owned")
            victim.chmod(0o600)
            (root / "manifest.json").symlink_to(victim)

            with self.assertRaisesRegex(ConnectorError, "fresh output"):
                render_draft_package(_empty_report(), output_dir=root)

            self.assertEqual(victim.read_bytes(), b"victim-owned")
            self.assertFalse((root / "README.md").exists())

    def test_summary_collision_rolls_back_owned_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "README.md"
            summary.write_bytes(b"peer-summary")
            summary.chmod(0o600)

            with self.assertRaisesRegex(ConnectorError, "fresh output"):
                render_draft_package(_empty_report(), output_dir=root)

            self.assertFalse((root / "manifest.json").exists())
            self.assertEqual(summary.read_bytes(), b"peer-summary")

    def test_output_alias_swap_fails_closed_before_summary_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "drafts"
            displaced = parent / "approved-displaced"
            attacker = parent / "attacker"
            root.mkdir(mode=0o700)
            attacker.mkdir(mode=0o700)
            real_write = package_module.write_artifact_bundle

            def swap_then_write(*args: object, **kwargs: object) -> object:
                root.rename(displaced)
                root.symlink_to(attacker, target_is_directory=True)
                return real_write(*args, **kwargs)

            with (
                patch.object(
                    package_module,
                    "write_artifact_bundle",
                    side_effect=swap_then_write,
                ),
                self.assertRaisesRegex(Exception, "runtime directory"),
            ):
                render_draft_package(_empty_report(), output_dir=root)

            self.assertEqual(tuple(attacker.iterdir()), ())
            self.assertEqual(tuple(displaced.iterdir()), ())


def _jira_draft_action() -> AgentAction:
    return AgentAction(
        capability="jira.issue.update.draft",
        target=ResourceRef("jira", "issue", "ENG-1"),
        parameters={
            "before": {"summary": "Before"},
            "fields": {"summary": "After"},
            "output_name": "jira-draft.json",
        },
        risk=RiskLevel.LOCAL_GENERATION,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="draft-create-race",
        justification="prove create-only draft publication",
    )


def _empty_report() -> RunReport:
    return RunReport(
        run_id=uuid4(),
        plan_id=uuid4(),
        plan_fingerprint="0" * 64,
        dry_run=False,
        actions=(),
    )


if __name__ == "__main__":
    unittest.main()
