"""Phase 3 draft connector and workflow tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.connectors.drafts import (
    ConfluenceDraftConnector,
    JiraDraftConnector,
    OutlookDraftConnector,
    PowerPointDraftConnector,
    RepositoryDraftConnector,
    TeamsDraftConnector,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.registry import ConnectorRegistry
from master_agent.workflows.draft_package import (
    DraftPackageSettings,
    build_draft_package_plan,
    render_draft_package,
)
from tests.windows_adversarial_evidence import adversarial_reasons

ROOT = Path(__file__).resolve().parents[1]


class DraftPackageTests(unittest.TestCase):
    """Verify that Phase 3 generates artifacts and never publishes."""

    def test_full_draft_package_generates_six_local_artifacts(self) -> None:
        settings = DraftPackageSettings.from_toml(ROOT / "config/draft-package.toml")
        plan = build_draft_package_plan(settings)
        self.assertEqual(len(plan.actions), 6)
        self.assertTrue(
            all(str(item.risk) == "local_generation" for item in plan.actions)
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            registry = ConnectorRegistry()
            with ExitStack() as connector_stack:
                for connector in (
                    JiraDraftConnector(root),
                    ConfluenceDraftConnector(root),
                    OutlookDraftConnector(root),
                    TeamsDraftConnector(root),
                    PowerPointDraftConnector(root),
                    RepositoryDraftConnector(root),
                ):
                    connector_stack.callback(connector.close)
                    registry.register(connector)
                runtime = WorkflowOrchestrator(
                    policy=PolicyEngine(
                        PolicyConfig.from_toml(ROOT / "config/policy.toml")
                    ),
                    sources=SourceOfTruthRegistry.from_toml(
                        ROOT / "config/sources_of_truth.toml"
                    ),
                    connectors=registry,
                    audit=AuditLog(root / "audit.sqlite3"),
                )
                report = runtime.run(plan, dry_run=False)
                self.assertTrue(report.successful)
                artifacts = render_draft_package(report, output_dir=root)
                self.assertTrue(artifacts.manifest_json.is_file())
                self.assertTrue((root / "change-package.pptx").is_file())
                self.assertTrue((root / "stakeholder-email.eml").is_file())
                self.assertTrue((root / "source-change.patch").is_file())
                self.assertIn(
                    "No external system was modified",
                    artifacts.summary_markdown.read_text(encoding="utf-8"),
                )

    def test_repository_patch_rejects_parent_path(self) -> None:
        settings = DraftPackageSettings.from_toml(ROOT / "config/draft-package.toml")
        plan = build_draft_package_plan(settings)
        patch = plan.actions[-1]
        unsafe = replace(
            patch,
            parameters={**patch.parameters, "relative_path": "../secret.txt"},
        )
        with tempfile.TemporaryDirectory() as directory:
            connector = RepositoryDraftConnector(Path(os.path.realpath(directory)))
            try:
                with self.assertRaisesRegex(Exception, "inside the repository"):
                    connector.execute(unsafe)
            finally:
                connector.close()

    @adversarial_reasons("deterministic_lf")
    def test_repository_patch_normalizes_crlf_to_deterministic_lf(self) -> None:
        settings = DraftPackageSettings.from_toml(ROOT / "config/draft-package.toml")
        action = build_draft_package_plan(settings).actions[-1]
        crlf = replace(
            action,
            parameters={
                **action.parameters,
                "before_text": "first\r\nsecond\r\n",
                "after_text": "first\r\nchanged\r\n",
                "output_name": "crlf.patch",
            },
        )
        lf = replace(
            crlf,
            parameters={
                **crlf.parameters,
                "before_text": "first\nsecond\n",
                "after_text": "first\nchanged\n",
                "output_name": "lf.patch",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            connector = RepositoryDraftConnector(root)
            try:
                connector.execute(crlf)
                connector.execute(lf)
            finally:
                connector.close()
            crlf_bytes = (root / "crlf.patch").read_bytes()
            lf_bytes = (root / "lf.patch").read_bytes()

        self.assertEqual(crlf_bytes, lf_bytes)
        self.assertNotIn(b"\r", crlf_bytes)


if __name__ == "__main__":
    unittest.main()
