"""Exact Tier-1 Engineering Work Item Review workflow tests."""

from __future__ import annotations

import hashlib
import json
import stat
import unittest
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from master_agent.capabilities import CapabilityCatalog
from master_agent.citations import make_resource_citation
from master_agent.config import IntegrationConfig
from master_agent.config_sources import ConfigSnapshot, resolve_config_source
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError, ConnectorError, ValidationError
from master_agent.execution_context import build_runtime_execution_binding
from master_agent.governance import GovernanceProfile
from master_agent.models import (
    ActionState,
    AgentAction,
    ChangePlan,
    ConnectorExecutionBinding,
    ExecutionContext,
    ExecutionResult,
    RiskLevel,
)
from master_agent.orchestrator import ActionReport, RunReport
from master_agent.provider_egress import (
    ProviderDataRoute,
    bind_provider_data_egress,
)
from master_agent.workflows.engineering_work_item_review import (
    WORKFLOW_FINGERPRINT,
    WORKFLOW_ID,
    EngineeringReviewOutcome,
    EngineeringWorkItemReviewSettings,
    build_engineering_work_item_review_plan,
    render_engineering_work_item_review,
    validate_engineering_work_item_review_plan,
)
from tests.helpers import private_temporary_directory


class EngineeringWorkItemReviewPlanTests(unittest.TestCase):
    """Verify the protected case is exact before runtime access."""

    def test_plan_is_fixed_read_only_and_configuration_bound(self) -> None:
        settings = _settings(page_ids=("11",), include_diffstat=True)
        plan = build_engineering_work_item_review_plan("ENG-123", settings)

        self.assertEqual(plan.workflow_id, WORKFLOW_ID)
        self.assertEqual(plan.workflow_fingerprint, WORKFLOW_FINGERPRINT)
        self.assertTrue(
            all(action.risk is RiskLevel.READ_ONLY for action in plan.actions)
        )
        self.assertEqual(
            [action.capability for action in plan.actions],
            [
                "jira.issue.review_context.read",
                "bitbucket.repository.read",
                "bitbucket.pull_request.read",
                "bitbucket.build_status.read",
                "bitbucket.pull_request.diffstat",
                "confluence.page.read",
            ],
        )
        jira = plan.actions[0]
        self.assertEqual(
            jira.parameters["workflow_configuration_sha256"],
            settings.configuration_sha256,
        )
        self.assertEqual(
            plan.actions[-1].parameters,
            {"space_id": "space-1", "space_key": "ENG"},
        )
        self.assertEqual(plan.actions[4].parameters["limit"], 50)
        validate_engineering_work_item_review_plan(plan, settings)

    def test_malformed_or_overbroad_scope_fails(self) -> None:
        settings = _settings()
        with self.assertRaisesRegex(ConfigurationError, "canonical Jira issue key"):
            build_engineering_work_item_review_plan("eng-0", settings)
        with self.assertRaisesRegex(ConfigurationError, "at most three"):
            _settings(page_ids=("1", "2", "3", "4"))


class EngineeringWorkItemReviewRendererTests(unittest.TestCase):
    """Verify fail-closed evidence handling and private publication."""

    def test_complete_bundle_is_exact_cited_private_and_create_only(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            report = _report(plan, settings)

            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )
                original = {
                    path.name: path.read_bytes()
                    for path in (
                        artifacts.review_json,
                        artifacts.review_markdown,
                        artifacts.manifest_json,
                    )
                }
                with self.assertRaises(ConnectorError):
                    render_engineering_work_item_review(
                        report,
                        plan,
                        settings,
                        output_root=pinned,
                    )

            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.COMPLETE)
            self.assertEqual(
                {path.name for path in artifact_root.iterdir()},
                {
                    "engineering-work-item-review.json",
                    "engineering-work-item-review.md",
                    "manifest.json",
                },
            )
            for path in artifact_root.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.read_bytes(), original[path.name])
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertTrue(review["complete"])
            self.assertEqual(review["outcome"], "complete")
            self.assertEqual(len(review["citations"]), len(plan.actions))
            self.assertNotEqual(
                _citation_for(review, "pull_request")["citation_id"],
                _citation_for(review, "build_status")["citation_id"],
            )
            markdown = artifacts.review_markdown.read_text(encoding="utf-8")
            for text in (
                "ENG-123: Implement exact review",
                "Repository: **widget**",
                "PR **7: ENG-123 implement exact review**",
                "Build statuses for commit",
                "Requirement 11",
            ):
                line = next(item for item in markdown.splitlines() if text in item)
                self.assertIn("[CIT-", line)
            manifest = json.loads(artifacts.manifest_json.read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["artifacts"]), 2)
            for item in manifest["artifacts"]:
                payload = (artifact_root / item["filename"]).read_bytes()
                self.assertEqual(item["bytes"], len(payload))
                self.assertEqual(item["sha256"], hashlib.sha256(payload).hexdigest())

    def test_matching_commit_pinned_diffstat_is_complete(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(
                root,
                include_diffstat=True,
            )
            report = _report(plan, settings)
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.COMPLETE)
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            diffstat = review["evidence"]["bitbucket_diffstat"]
            self.assertEqual(diffstat["source_commit"], "abc123")
            self.assertEqual(diffstat["destination_commit"], "def456")
            self.assertIn(
                "pull_request_diffstat",
                {citation["resource_type"] for citation in review["citations"]},
            )

    def test_foreign_or_missing_diffstat_identity_is_quarantined(self) -> None:
        cases = {
            "foreign pull request": ("pull_request_id", "8"),
            "foreign source": ("source_commit", "other-source"),
            "foreign destination": ("destination_commit", "other-destination"),
            "missing source": ("source_commit", ""),
        }
        for name, (field, value) in cases.items():
            with self.subTest(name=name), private_temporary_directory() as directory:
                canary = f"SECRET-DIFFSTAT-{name}"

                def mutate_diffstat(
                    action: AgentAction,
                    payload: dict[str, object],
                    field: str = field,
                    value: str = value,
                    canary: str = canary,
                ) -> None:
                    if action.capability != "bitbucket.pull_request.diffstat":
                        return
                    payload[field] = value
                    payload["changes"] = [{"new_path": canary}]

                root = Path(directory)
                settings, plan, artifact_root = _bound_plan(
                    root,
                    include_diffstat=True,
                )
                report = _report(plan, settings, payload_mutator=mutate_diffstat)
                with PinnedDirectory.open(artifact_root) as pinned:
                    artifacts = render_engineering_work_item_review(
                        report,
                        plan,
                        settings,
                        output_root=pinned,
                    )

                combined = artifacts.review_json.read_text(
                    encoding="utf-8"
                ) + artifacts.review_markdown.read_text(encoding="utf-8")
                self.assertNotIn(canary, combined)
                self.assertIs(artifacts.outcome, EngineeringReviewOutcome.STALE)
                review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
                self.assertIsNone(review["evidence"]["bitbucket_diffstat"])
                self.assertNotIn(
                    "pull_request_diffstat",
                    {citation["resource_type"] for citation in review["citations"]},
                )
                self.assertIn(
                    {
                        "capability": "bitbucket.pull_request.diffstat",
                        "state": "quarantined",
                    },
                    [
                        {
                            "capability": failure["capability"],
                            "state": failure["state"],
                        }
                        for failure in review["failures"]
                    ],
                )

    def test_non_string_commit_identities_are_stale_and_quarantined(self) -> None:
        build_canary = "SECRET-NUMERIC-BUILD-CANARY"
        diffstat_canary = "SECRET-NUMERIC-DIFFSTAT-CANARY"

        def numeric_commits(
            action: AgentAction,
            payload: dict[str, object],
        ) -> None:
            if action.capability == "bitbucket.pull_request.read":
                pull_request = payload["pull_request"]
                assert isinstance(pull_request, dict)
                pull_request["source_commit"] = 123
                pull_request["destination_commit"] = 456
            elif action.capability == "bitbucket.build_status.read":
                payload["commit"] = 123
                payload["statuses"] = [{"key": build_canary, "state": "SUCCESSFUL"}]
            elif action.capability == "bitbucket.pull_request.diffstat":
                payload["source_commit"] = 123
                payload["destination_commit"] = 456
                payload["changes"] = [{"new_path": diffstat_canary}]

        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(
                root,
                include_diffstat=True,
            )
            report = _report(plan, settings, payload_mutator=numeric_commits)
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            combined = artifacts.review_json.read_text(
                encoding="utf-8"
            ) + artifacts.review_markdown.read_text(encoding="utf-8")
            self.assertNotIn(build_canary, combined)
            self.assertNotIn(diffstat_canary, combined)
            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.STALE)
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertFalse(review["complete"])
            self.assertIsNone(review["evidence"]["bitbucket_build_status"])
            self.assertIsNone(review["evidence"]["bitbucket_diffstat"])
            self.assertCountEqual(
                [item["kind"] for item in review["stale_evidence"]],
                ["pull_request_build_head", "pull_request_diffstat_commits"],
            )

    def test_diffstat_is_quarantined_without_exact_pull_request_evidence(self) -> None:
        def foreign_pull_request(
            action: AgentAction,
            payload: dict[str, object],
        ) -> None:
            if action.capability == "bitbucket.pull_request.read":
                pull_request = payload["pull_request"]
                assert isinstance(pull_request, dict)
                pull_request["id"] = 8
            elif action.capability == "bitbucket.pull_request.diffstat":
                payload["changes"] = [{"new_path": "SECRET-UNBOUND-DIFFSTAT"}]

        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(
                root,
                include_diffstat=True,
            )
            report = _report(plan, settings, payload_mutator=foreign_pull_request)
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            combined = artifacts.review_json.read_text(
                encoding="utf-8"
            ) + artifacts.review_markdown.read_text(encoding="utf-8")
            self.assertNotIn("SECRET-UNBOUND-DIFFSTAT", combined)
            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.STALE)
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertIsNone(review["evidence"]["bitbucket_pull_request"])
            self.assertIsNone(review["evidence"]["bitbucket_diffstat"])

    def test_report_binding_rejects_untrusted_success_shapes(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            valid = _report(plan, settings)
            first = valid.actions[0]
            assert first.result is not None
            invalid_result = ExecutionResult(
                action_id=first.action_id,
                state=ActionState.FAILED,
                before=first.result.before,
                after=first.result.after,
                connector_reference=first.result.connector_reference,
                message="failed",
            )
            cases = {
                "dry": replace(valid, dry_run=True),
                "foreign": replace(valid, plan_id=uuid4()),
                "missing": replace(valid, actions=valid.actions[:-1]),
                "duplicate": replace(valid, actions=(*valid.actions, first)),
                "capability": replace(
                    valid,
                    actions=(
                        replace(first, capability="jira.issue.read"),
                        *valid.actions[1:],
                    ),
                ),
                "missing egress": replace(
                    valid,
                    actions=(replace(first, egress=None), *valid.actions[1:]),
                ),
                "failed result": replace(
                    valid,
                    actions=(replace(first, result=invalid_result), *valid.actions[1:]),
                ),
                "reused read": replace(
                    valid,
                    actions=(
                        replace(first, state=ActionState.REUSED),
                        *valid.actions[1:],
                    ),
                ),
            }
            with PinnedDirectory.open(artifact_root) as pinned:
                for name, report in cases.items():
                    with self.subTest(name=name), self.assertRaises(ValidationError):
                        render_engineering_work_item_review(
                            report,
                            plan,
                            settings,
                            output_root=pinned,
                        )
            self.assertEqual(list(artifact_root.iterdir()), [])

    def test_report_binding_rejects_mismatched_connector_deployment(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            assert plan.execution_context is not None
            connectors = tuple(
                replace(connector, deployment="data_center")
                if connector.system == "bitbucket"
                else connector
                for connector in plan.execution_context.connectors
            )
            plan = replace(
                plan,
                execution_context=replace(
                    plan.execution_context,
                    connectors=connectors,
                ),
            )
            report = _report(
                plan,
                settings,
                payload_mutator=lambda action, payload: (
                    payload.__setitem__("deployment", "data_center")
                    if action.target.system == "bitbucket"
                    else None
                ),
            )

            with (
                PinnedDirectory.open(artifact_root) as pinned,
                self.assertRaisesRegex(ValidationError, "Bitbucket deployment"),
            ):
                render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )
            self.assertEqual(list(artifact_root.iterdir()), [])

    def test_post_verification_mutation_is_rejected(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            report = _report(plan, settings)
            result = report.actions[0].result
            assert result is not None and result.after is not None
            issue = result.after["issue"]
            assert isinstance(issue, dict)
            issue["summary"] = "MUTATED-AFTER-VERIFICATION"

            with (
                PinnedDirectory.open(artifact_root) as pinned,
                self.assertRaisesRegex(ValidationError, "changed after return"),
            ):
                render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )
            self.assertEqual(list(artifact_root.iterdir()), [])

    def test_stale_and_ambiguous_evidence_cannot_be_complete(self) -> None:
        cases = {
            "head drift": (
                lambda action, payload: (
                    payload.__setitem__("commit", "different")
                    if action.capability == "bitbucket.build_status.read"
                    else None
                ),
                EngineeringReviewOutcome.STALE,
            ),
            "page scope drift": (
                lambda action, payload: (
                    payload["page"].__setitem__("space_id", "other-space")
                    if action.capability == "confluence.page.read"
                    else None
                ),
                EngineeringReviewOutcome.STALE,
            ),
            "relation conflict": (
                _set_conflicting_relation,
                EngineeringReviewOutcome.AMBIGUOUS,
            ),
            "confluence relation conflict": (
                _set_conflicting_confluence_relation,
                EngineeringReviewOutcome.AMBIGUOUS,
            ),
        }
        for name, (mutator, expected) in cases.items():
            with self.subTest(name=name), private_temporary_directory() as directory:
                root = Path(directory)
                settings, plan, artifact_root = _bound_plan(root)
                report = _report(plan, settings, payload_mutator=mutator)
                with PinnedDirectory.open(artifact_root) as pinned:
                    artifacts = render_engineering_work_item_review(
                        report,
                        plan,
                        settings,
                        output_root=pinned,
                    )
                self.assertIs(artifacts.outcome, expected)
                review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
                self.assertFalse(review["complete"])
                if name == "relation conflict":
                    self.assertIn(
                        {
                            "owner_or_project": "acme",
                            "repository": "foreign",
                            "pull_request_id": "7",
                        },
                        review["ambiguities"][0]["observed"],
                    )

    def test_foreign_target_payloads_are_quarantined_from_artifacts(self) -> None:
        def foreign_jira(action: AgentAction, payload: dict[str, object]) -> None:
            if action.capability == "jira.issue.review_context.read":
                issue = payload["issue"]
                assert isinstance(issue, dict)
                issue.update({"key": "OTHER-9", "summary": "JIRA-SECRET-CANARY"})

        def foreign_repository(action: AgentAction, payload: dict[str, object]) -> None:
            if action.capability == "bitbucket.repository.read":
                repository = payload["repository"]
                assert isinstance(repository, dict)
                repository.update({"slug": "foreign", "name": "REPO-SECRET-CANARY"})

        def foreign_pull_request(
            action: AgentAction, payload: dict[str, object]
        ) -> None:
            if action.capability == "bitbucket.pull_request.read":
                pull_request = payload["pull_request"]
                assert isinstance(pull_request, dict)
                pull_request.update({"id": 8, "title": "PR-SECRET-CANARY"})

        def foreign_page(action: AgentAction, payload: dict[str, object]) -> None:
            if action.capability == "confluence.page.read":
                page = payload["page"]
                assert isinstance(page, dict)
                page.update({"id": "999", "title": "PAGE-SECRET-CANARY"})

        cases = {
            "jira": (foreign_jira, "JIRA-SECRET-CANARY", "jira"),
            "repository": (
                foreign_repository,
                "REPO-SECRET-CANARY",
                "bitbucket_repository",
            ),
            "pull request": (
                foreign_pull_request,
                "PR-SECRET-CANARY",
                "bitbucket_pull_request",
            ),
            "page": (foreign_page, "PAGE-SECRET-CANARY", "confluence_pages"),
        }
        for name, (mutator, canary, evidence_key) in cases.items():
            with self.subTest(name=name), private_temporary_directory() as directory:
                root = Path(directory)
                settings, plan, artifact_root = _bound_plan(root)
                report = _report(plan, settings, payload_mutator=mutator)
                with PinnedDirectory.open(artifact_root) as pinned:
                    artifacts = render_engineering_work_item_review(
                        report,
                        plan,
                        settings,
                        output_root=pinned,
                    )
                combined = artifacts.review_json.read_text(
                    encoding="utf-8"
                ) + artifacts.review_markdown.read_text(encoding="utf-8")
                self.assertNotIn(canary, combined)
                self.assertIs(artifacts.outcome, EngineeringReviewOutcome.STALE)
                review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
                expected = [] if evidence_key == "confluence_pages" else None
                self.assertEqual(review["evidence"][evidence_key], expected)

    def test_stale_build_payload_is_quarantined_from_artifacts(self) -> None:
        canary = "SECRET-STALE-BUILD-CANARY"

        def stale_build(action: AgentAction, payload: dict[str, object]) -> None:
            if action.capability != "bitbucket.build_status.read":
                return
            payload["commit"] = "different"
            payload["statuses"] = [{"key": canary, "name": canary, "state": "FAILED"}]
            payload["summary"] = {
                "total": 1,
                "successful": 0,
                "failed": 1,
                "in_progress": 0,
                "other": 0,
            }

        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            report = _report(plan, settings, payload_mutator=stale_build)
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            combined = artifacts.review_json.read_text(
                encoding="utf-8"
            ) + artifacts.review_markdown.read_text(encoding="utf-8")
            self.assertNotIn(canary, combined)
            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.STALE)
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertIsNone(review["evidence"]["bitbucket_build_status"])
            self.assertIn(
                {
                    "capability": "bitbucket.build_status.read",
                    "state": "quarantined",
                },
                [
                    {
                        "capability": failure["capability"],
                        "state": failure["state"],
                    }
                    for failure in review["failures"]
                ],
            )
            markdown = artifacts.review_markdown.read_text(encoding="utf-8")
            self.assertIn("`bitbucket.build\\_status.read`: quarantined", markdown)
            self.assertIn("No reportable build evidence is available.", markdown)
            self.assertNotIn("None in the configured scope.", markdown)
            head_findings = [
                finding
                for finding in review["findings"]
                if finding["kind"] == "stale_pull_request_build_head"
            ]
            self.assertEqual(head_findings[0]["citation_ids"], [])

    def test_foreign_build_pull_request_is_quarantined_from_artifacts(self) -> None:
        canary = "SECRET-FOREIGN-BUILD-CANARY"

        def foreign_build(action: AgentAction, payload: dict[str, object]) -> None:
            if action.capability != "bitbucket.build_status.read":
                return
            payload["pull_request_id"] = "8"
            payload["statuses"] = [
                {"key": canary, "name": canary, "state": "SUCCESSFUL"}
            ]

        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            report = _report(plan, settings, payload_mutator=foreign_build)
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            combined = artifacts.review_json.read_text(
                encoding="utf-8"
            ) + artifacts.review_markdown.read_text(encoding="utf-8")
            self.assertNotIn(canary, combined)
            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.STALE)
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertIsNone(review["evidence"]["bitbucket_build_status"])
            self.assertNotIn(
                "build_status",
                {citation["resource_type"] for citation in review["citations"]},
            )

    def test_partial_bundle_names_exact_failed_page_without_raw_error(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(
                root,
                page_ids=("11", "12"),
            )
            report = _report(
                plan,
                settings,
                failed_resource_ids={"12"},
                failure_message="SECRET-CANARY /private/operator/path",
            )
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.PARTIAL)
            combined = artifacts.review_json.read_text(
                encoding="utf-8"
            ) + artifacts.review_markdown.read_text(encoding="utf-8")
            self.assertNotIn("SECRET-CANARY", combined)
            self.assertNotIn("/private/operator/path", combined)
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertEqual(review["failures"][0]["resource_id"], "12")
            self.assertEqual(
                review["failures"][0]["stage"],
                "provider_read_and_independent_verification",
            )
            self.assertIn(
                "No evidence-backed consistency conclusion is available.",
                artifacts.review_markdown.read_text(encoding="utf-8"),
            )

    def test_all_failed_core_reads_are_failed_not_stale(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root, page_ids=())
            report = _report(
                plan,
                settings,
                failed_resource_ids={"ENG-123", "acme/widget", "7"},
            )
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            self.assertIs(artifacts.outcome, EngineeringReviewOutcome.FAILED)
            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertEqual(review["stale_evidence"], [])
            self.assertIn(
                "No evidence-backed consistency conclusion is available.",
                artifacts.review_markdown.read_text(encoding="utf-8"),
            )

    def test_empty_acceptance_statement_is_cited(self) -> None:
        def clear_acceptance(action: AgentAction, payload: dict[str, object]) -> None:
            if action.capability == "jira.issue.review_context.read":
                issue = payload["issue"]
                assert isinstance(issue, dict)
                issue["acceptance_criteria"] = []

        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            report = _report(plan, settings, payload_mutator=clear_acceptance)
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )
            line = next(
                item
                for item in artifacts.review_markdown.read_text(
                    encoding="utf-8"
                ).splitlines()
                if "No reportable configured acceptance criteria" in item
            )
            self.assertIn("[CIT-", line)

    def test_non_success_provider_build_state_is_visible_and_flagged(self) -> None:
        def stop_build(action: AgentAction, payload: dict[str, object]) -> None:
            if action.capability != "bitbucket.build_status.read":
                return
            payload["statuses"] = [{"key": "tests", "state": "STOPPED"}]
            payload["summary"] = {
                "total": 1,
                "successful": 0,
                "failed": 0,
                "in_progress": 0,
                "other": 1,
            }

        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            report = _report(plan, settings, payload_mutator=stop_build)
            with PinnedDirectory.open(artifact_root) as pinned:
                artifacts = render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )

            review = json.loads(artifacts.review_json.read_text(encoding="utf-8"))
            self.assertIn(
                "non_success_build_state",
                {finding["kind"] for finding in review["findings"]},
            )
            build_line = next(
                line
                for line in artifacts.review_markdown.read_text(
                    encoding="utf-8"
                ).splitlines()
                if "Build statuses for commit" in line
            )
            self.assertIn("1 total", build_line)
            self.assertIn("1 other", build_line)
            self.assertIn("[CIT-", build_line)

    def test_renderer_rejects_a_different_private_output_root(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            settings, plan, artifact_root = _bound_plan(root)
            report = _report(plan, settings)
            other = root / "other-artifacts"
            other.mkdir(mode=0o700)
            with (
                PinnedDirectory.open(other) as pinned,
                self.assertRaisesRegex(ValidationError, "bound artifact root"),
            ):
                render_engineering_work_item_review(
                    report,
                    plan,
                    settings,
                    output_root=pinned,
                )
            self.assertEqual(list(other.iterdir()), [])
            self.assertEqual(list(artifact_root.iterdir()), [])


def _settings(
    *,
    page_ids: tuple[str, ...] = ("11",),
    include_diffstat: bool = False,
) -> EngineeringWorkItemReviewSettings:
    pages = ", ".join(f'"{item}"' for item in page_ids)
    payload = f"""
[case]
id = "T1-EWIR-001"
data_classification = "internal"

[bitbucket]
deployment = "cloud"
origin = "https://api.bitbucket.org"
workspace = "acme"
repository = "widget"
pull_request_id = "7"
build_status_limit = 50
diffstat_limit = 50
include_diffstat = {str(include_diffstat).lower()}

[confluence]
origin = "https://acme.atlassian.net"
space_id = "space-1"
space_key = "ENG"
page_ids = [{pages}]
""".lstrip().encode("utf-8")
    return EngineeringWorkItemReviewSettings.from_toml(
        ConfigSnapshot(Path("/private/test/engineering-review.toml"), payload)
    )


def _bound_plan(
    root: Path,
    *,
    page_ids: tuple[str, ...] = ("11",),
    include_diffstat: bool = False,
) -> tuple[EngineeringWorkItemReviewSettings, ChangePlan, Path]:
    settings = _settings(
        page_ids=page_ids,
        include_diffstat=include_diffstat,
    )
    plan = build_engineering_work_item_review_plan("ENG-123", settings)
    state_root = root / "state"
    artifact_root = root / "artifacts"
    state_root.mkdir(mode=0o700)
    artifact_root.mkdir(mode=0o700)
    runtime = build_runtime_execution_binding(
        IntegrationConfig({}),
        connector_mode="live",
        include_writes=False,
        include_communications=False,
        audit_database=state_root / "audit.sqlite3",
        artifact_root=artifact_root,
        workspace_root=None,
        result_json=None,
        evidence_type="run-result/full",
        configuration_sources={},
    )
    systems = sorted({action.target.system for action in plan.actions})
    connectors = tuple(
        ConnectorExecutionBinding(
            system=system,
            deployment="cloud",
            config_identity_sha256=hashlib.sha256(system.encode("utf-8")).hexdigest(),
            resolved_base_url=f"https://{system}.example/api",
            resolved_origin=f"https://{system}.example",
        )
        for system in systems
    )
    bound = replace(
        plan,
        execution_context=ExecutionContext(
            integrations_sha256="a" * 64,
            connectors=connectors,
            runtime=runtime,
        ),
    )
    return settings, bound, artifact_root


def _report(
    plan: ChangePlan,
    settings: EngineeringWorkItemReviewSettings,
    *,
    payload_mutator: object | None = None,
    failed_resource_ids: set[str] | None = None,
    failure_message: str = "provider failure",
) -> RunReport:
    failed = failed_resource_ids or set()
    actions: list[ActionReport] = []
    for action in plan.actions:
        if action.target.resource_id in failed:
            actions.append(
                ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.FAILED,
                    message=failure_message,
                )
            )
            continue
        payload = _payload(action, settings)
        if callable(payload_mutator):
            payload_mutator(action, payload)
        result = ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=payload,
            after=payload,
            connector_reference=(
                f"https://{action.target.system}.example/{action.target.resource_id}"
            ),
            message="read",
        )
        actions.append(
            ActionReport(
                action_id=action.action_id,
                capability=action.capability,
                state=ActionState.VERIFIED,
                message="verified",
                result=result,
                egress=_egress(plan, action),
            )
        )
    return RunReport(
        run_id=uuid4(),
        plan_id=plan.plan_id,
        plan_fingerprint=plan.fingerprint,
        dry_run=False,
        actions=tuple(actions),
    )


def _payload(
    action: AgentAction,
    settings: EngineeringWorkItemReviewSettings,
) -> dict[str, object]:
    common = {"system": action.target.system, "deployment": "cloud"}
    if action.capability == "jira.issue.review_context.read":
        return {
            "schema": "master-agent/jira-issue-review-context@1",
            **common,
            "issue": {
                "id": "10001",
                "key": "ENG-123",
                "summary": "Implement exact review",
                "status": "In Progress",
                "priority": "High",
                "assignee": "Rory",
                "description": "Bounded engineering review.",
                "acceptance_criteria": [
                    {"field_id": "customfield_10001", "text": "Ship exact evidence."}
                ],
                "external_relations": [
                    {
                        "provider": "bitbucket",
                        "resource_type": "pull_request",
                        "owner_or_project": "acme",
                        "repository": "widget",
                        "pull_request_id": "7",
                    },
                    {
                        "provider": "confluence",
                        "resource_type": "page",
                        "space": "ENG",
                        "page_id": "11",
                    },
                ],
            },
            "source_urls": ["https://jira.example/ENG-123"],
        }
    if action.capability == "bitbucket.repository.read":
        citation = make_resource_citation(
            system="bitbucket",
            resource_type="repository",
            resource_id="widget",
            title="widget",
            url="https://bitbucket.example/acme/widget",
        )
        return {
            "schema": "master-agent/bitbucket-repository@1",
            **common,
            "repository": {
                "id": "repo-1",
                "name": "Widget",
                "slug": "widget",
                "owner_or_project": "acme",
            },
            "citations": [citation],
            "source_urls": ["https://bitbucket.example/acme/widget"],
        }
    if action.capability == "bitbucket.pull_request.read":
        citation = make_resource_citation(
            system="bitbucket",
            resource_type="pull_request",
            resource_id="7",
            title="ENG-123 implement exact review",
            url="https://bitbucket.example/acme/widget/pull-requests/7",
        )
        return {
            "schema": "master-agent/bitbucket-pull-request@1",
            **common,
            "pull_request": {
                "id": 7,
                "title": "ENG-123 implement exact review",
                "description": "Implements ENG-123.",
                "state": "OPEN",
                "source_branch": "feature/eng-123",
                "destination_branch": "main",
                "source_commit": "abc123",
                "destination_commit": "def456",
            },
            "citations": [citation],
            "source_urls": ["https://bitbucket.example/acme/widget/pull-requests/7"],
        }
    if action.capability == "bitbucket.build_status.read":
        return {
            "schema": "master-agent/bitbucket-build-status@1",
            **common,
            "commit": "abc123",
            "pull_request_id": "7",
            "returned": 1,
            "statuses": [{"key": "tests", "state": "SUCCESSFUL"}],
            "summary": {"successful": 1, "failed": 0, "in_progress": 0, "other": 0},
            "source_urls": ["https://bitbucket.example/statuses/abc123"],
        }
    if action.capability == "bitbucket.pull_request.diffstat":
        return {
            "schema": "master-agent/bitbucket-diffstat@1",
            **common,
            "pull_request_id": "7",
            "source_commit": "abc123",
            "destination_commit": "def456",
            "returned": 1,
            "changes": [{"new_path": "src/review.py", "lines_added": 10}],
            "summary": {"files": 1, "lines_added": 10, "lines_removed": 0},
            "source_urls": ["https://bitbucket.example/diffstat/7"],
        }
    if action.capability == "confluence.page.read":
        citation = make_resource_citation(
            system="confluence",
            resource_type="page",
            resource_id=action.target.resource_id,
            title=f"Requirement {action.target.resource_id}",
            url=f"https://confluence.example/pages/{action.target.resource_id}",
            version="3",
        )
        return {
            "schema": "master-agent/confluence-page@1",
            **common,
            "page": {
                "id": action.target.resource_id,
                "title": f"Requirement {action.target.resource_id}",
                "version": 3,
                "space_id": settings.confluence_space_id,
                "space_key": settings.confluence_space_key,
                "body_excerpt": "The exact review must fail closed.",
            },
            "citations": [citation],
            "source_urls": [
                f"https://confluence.example/pages/{action.target.resource_id}"
            ],
        }
    raise AssertionError(action.capability)


def _egress(plan: ChangePlan, action: AgentAction):
    catalog = CapabilityCatalog.from_toml(
        resolve_config_source(None, "capabilities.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(None, "governance.toml")
    )
    connector = next(
        item
        for item in plan.execution_context.connectors
        if item.system == action.target.system
    )
    return bind_provider_data_egress(
        policy=governance.model_context,
        action=action,
        definition=catalog.definition(action.capability),
        connector_binding=connector,
        route=ProviderDataRoute.AUDITED,
        audit_available=True,
    )


def _set_conflicting_relation(
    action: AgentAction,
    payload: dict[str, object],
) -> None:
    if action.capability != "jira.issue.review_context.read":
        return
    issue = payload["issue"]
    assert isinstance(issue, dict)
    relations = issue["external_relations"]
    assert isinstance(relations, list)
    conflicting = dict(relations[0])
    conflicting["repository"] = "foreign"
    relations.append(conflicting)


def _set_conflicting_confluence_relation(
    action: AgentAction,
    payload: dict[str, object],
) -> None:
    if action.capability != "jira.issue.review_context.read":
        return
    issue = payload["issue"]
    assert isinstance(issue, dict)
    relations = issue["external_relations"]
    assert isinstance(relations, list)
    relations[1]["space"] = "OTHER"


def _citation_for(review: dict[str, object], resource_type: str) -> dict[str, object]:
    citations = review["citations"]
    assert isinstance(citations, list)
    return next(item for item in citations if item["resource_type"] == resource_type)


if __name__ == "__main__":
    unittest.main()
