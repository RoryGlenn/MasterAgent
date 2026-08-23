"""Fail-closed type validation for security-sensitive booleans."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.governance import GovernanceProfile
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)
from master_agent.oauth_config import OAuthProfiles
from master_agent.orchestrator import RunReport
from master_agent.planners.base import (
    ComplexityItem,
    ComplexityKind,
    GovernedPlanner,
    SystemsAssessment,
    SystemsGateRoute,
    SystemsGovernanceGate,
    bind_systems_governance,
)
from master_agent.planners.static import build_weekly_status_plan
from master_agent.provider_egress import ProviderDataEgressPolicy


class StrictBooleanTests(unittest.TestCase):
    """Reject string/int substitutions for policy-sensitive booleans."""

    def test_plan_requires_real_boolean_values(self) -> None:
        payload = build_weekly_status_plan().to_dict()
        payload["actions"][0]["requires_approval"] = "false"
        with self.assertRaises(ValidationError):
            ChangePlan.from_dict(payload)

        payload = build_weekly_status_plan().to_dict()
        payload["compensate_on_failure"] = "false"
        with self.assertRaises(ValidationError):
            ChangePlan.from_dict(payload)

    def test_serialized_provider_read_requires_explicit_classification(self) -> None:
        payload = build_weekly_status_plan().to_dict()
        del payload["actions"][0]["data_classification"]

        with self.assertRaisesRegex(ValidationError, "explicit data_classification"):
            ChangePlan.from_dict(payload)

    def test_model_context_policy_rejects_type_confusion_and_unknown_keys(self) -> None:
        base = _model_context_mapping()
        for mutation in (
            lambda value: value.update(destination=7),
            lambda value: value["rules"][0].update(audit_required="false"),
            lambda value: value["rules"][0].update(audit_requred=True),
            lambda value: value["rules"][0].update(handling=7),
            lambda value: value["rules"][0].update(providers="jira"),
        ):
            candidate = __import__("copy").deepcopy(base)
            mutation(candidate)
            with self.assertRaises(ConfigurationError):
                ProviderDataEgressPolicy.from_mapping(candidate)

    def test_model_context_policy_rejects_duplicate_rules(self) -> None:
        candidate = _model_context_mapping()
        candidate["rules"].append(dict(candidate["rules"][0]))
        with self.assertRaisesRegex(ConfigurationError, "names must be unique"):
            ProviderDataEgressPolicy.from_mapping(candidate)

    def test_report_requires_real_dry_run_boolean(self) -> None:
        plan = build_weekly_status_plan()
        payload = {
            "run_id": "00000000-0000-0000-0000-000000000001",
            "plan_id": str(plan.plan_id),
            "plan_fingerprint": plan.fingerprint,
            "dry_run": "false",
            "actions": [],
        }
        with self.assertRaises(ValueError):
            RunReport.from_dict(payload)

    def test_toml_enablement_flags_are_not_coerced(self) -> None:
        cases = (
            (
                "integrations.toml",
                '[connectors.jira]\nenabled = "false"\ndeployment = "cloud"\nbase_url = "https://example.test"\nauth_mode = "none"\n',
                IntegrationConfig.from_toml,
            ),
            (
                "capabilities.toml",
                '[capabilities."jira.issue.read"]\nenabled = "false"\nauthentication = "none"\nrisk = "read_only"\n',
                CapabilityCatalog.from_toml,
            ),
            (
                "governance.toml",
                '[organization]\nname="x"\nenvironment="development"\nsecret_manager="x"\naudit_sink="x"\nexternal_model_policy="x"\n\n[[rules]]\npattern="*"\nowner="x"\nauthentication="provider_specific"\ndata_classifications=["internal"]\napproval_tier="single"\nenvironments=["development"]\nenabled="false"\n',
                GovernanceProfile.from_toml,
            ),
            (
                "oauth.toml",
                '[profiles.x]\nenabled="false"\nprovider="microsoft_graph"\nflow="environment"\naccess_token_env="TOKEN"\nscopes=["User.Read"]\nidentity_mode="delegated"\n',
                OAuthProfiles.from_toml,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, content, loader in cases:
                path = root / filename
                path.write_text(content, encoding="utf-8")
                with (
                    self.subTest(filename=filename),
                    self.assertRaises(ConfigurationError),
                ):
                    loader(path)


class SystemsGovernanceGateTests(unittest.TestCase):
    """Require systems diagnosis before non-trivial planning."""

    def test_explicit_fast_path_accepts_only_safe_reversible_work(self) -> None:
        decision = SystemsGovernanceGate().evaluate(
            _systems_plan(RiskLevel.READ_ONLY),
            _systems_assessment(),
        )

        self.assertTrue(decision.permitted, decision.reasons)
        self.assertEqual(decision.route, SystemsGateRoute.FAST_PATH)
        self.assertEqual(decision.complexity_score, 0)

    def test_fast_path_rejects_a_write_plan(self) -> None:
        gate = SystemsGovernanceGate()
        plan = _systems_plan(RiskLevel.REVERSIBLE_WRITE)
        assessment = _systems_assessment()

        decision = gate.evaluate(plan, assessment)

        self.assertFalse(decision.permitted)
        self.assertIn("read-only", " ".join(decision.reasons))
        with self.assertRaisesRegex(ValidationError, "systems governance denied"):
            gate.enforce(plan, assessment)

    def test_complete_gated_assessment_scores_added_complexity(self) -> None:
        assessment = _systems_assessment(
            low_risk=False,
            stocks=("open work",),
            flows=("new work arrives",),
            feedback_loops=("more work creates more coordination",),
            delays=("benefits appear after adoption",),
            unintended_consequences=("temporary migration cost",),
            alternatives_considered=("extend the existing planner",),
            added_complexity=(
                ComplexityItem(
                    ComplexityKind.AGENT,
                    "one independently governed planning component",
                ),
            ),
            existing_mechanisms_insufficient_because=(
                "existing planners do not receive a systems assessment"
            ),
            reversibility_strategy="remove the wrapper and restore the prior planner",
        )

        decision = SystemsGovernanceGate().evaluate(
            _systems_plan(RiskLevel.REVERSIBLE_WRITE),
            assessment,
        )

        self.assertTrue(decision.permitted, decision.reasons)
        self.assertEqual(decision.route, SystemsGateRoute.GATED)
        self.assertEqual(decision.complexity_score, 2)

    def test_added_complexity_requires_justification_and_removal_plan(self) -> None:
        assessment = _systems_assessment(
            low_risk=False,
            stocks=("open work",),
            flows=("new work arrives",),
            feedback_loops=("more work creates more coordination",),
            delays=("none identified",),
            unintended_consequences=("configuration drift",),
            added_complexity=(
                ComplexityItem(
                    ComplexityKind.CONFIGURATION_SURFACE,
                    "systems-governance configuration",
                ),
            ),
        )

        decision = SystemsGovernanceGate().evaluate(
            _systems_plan(RiskLevel.LOCAL_GENERATION),
            assessment,
        )

        self.assertFalse(decision.permitted)
        combined = " ".join(decision.reasons)
        self.assertIn("alternatives", combined)
        self.assertIn("existing mechanisms", combined)
        self.assertIn("reversibility", combined)

    def test_complexity_above_budget_requires_human_review(self) -> None:
        assessment = _systems_assessment(
            low_risk=False,
            stocks=("open work",),
            flows=("new work arrives",),
            feedback_loops=("more work creates more coordination",),
            delays=("benefits appear after adoption",),
            unintended_consequences=("operational burden",),
            alternatives_considered=("extend current components",),
            added_complexity=(
                ComplexityItem(ComplexityKind.AGENT, "planning agent"),
                ComplexityItem(ComplexityKind.STATE_STORE, "assessment store"),
                ComplexityItem(ComplexityKind.PERSISTENT_SERVICE, "review service"),
            ),
            existing_mechanisms_insufficient_because="no current durable boundary",
            reversibility_strategy="remove all three components and restore prior flow",
        )

        decision = SystemsGovernanceGate().evaluate(
            _systems_plan(RiskLevel.REVERSIBLE_WRITE),
            assessment,
        )

        self.assertTrue(decision.permitted)
        self.assertTrue(decision.requires_human_review)
        self.assertIn("exceeds automatic budget", " ".join(decision.reasons))
        with self.assertRaisesRegex(ValidationError, "authenticated human review"):
            SystemsGovernanceGate().enforce(
                _systems_plan(RiskLevel.REVERSIBLE_WRITE),
                assessment,
            )

    def test_governed_planner_assesses_before_building_the_plan(self) -> None:
        events: list[str] = []
        assessment = _systems_assessment()
        expected_plan = _systems_plan(RiskLevel.LOCAL_GENERATION)

        class Assessor:
            def assess(self, goal: str) -> SystemsAssessment:
                events.append(f"assess:{goal}")
                return assessment

        class PlanBuilder:
            def plan(
                self,
                goal: str,
                *,
                systems_assessment: SystemsAssessment,
            ) -> ChangePlan:
                self.assert_assessment(systems_assessment)
                events.append(f"plan:{goal}")
                return expected_plan

            @staticmethod
            def assert_assessment(value: SystemsAssessment) -> None:
                if value is not assessment:
                    raise AssertionError("planner did not receive the assessed object")

        result = GovernedPlanner(
            assessor=Assessor(),
            planner=PlanBuilder(),
        ).plan("prepare a local summary")

        self.assertEqual(
            events,
            ["assess:prepare a local summary", "plan:prepare a local summary"],
        )
        self.assertEqual(result.plan.plan_id, expected_plan.plan_id)
        self.assertIs(result.plan.systems_assessment, assessment)
        self.assertEqual(result.plan.systems_decision, result.decision)
        self.assertEqual(
            result.decision.assessment_fingerprint,
            assessment.fingerprint,
        )

    def test_plan_round_trip_binds_assessment_decision_and_fingerprint(self) -> None:
        unbound = _systems_plan(RiskLevel.LOCAL_GENERATION)
        governed = bind_systems_governance(unbound, _systems_assessment())

        restored = ChangePlan.from_dict(governed.to_dict())

        self.assertNotEqual(unbound.fingerprint, governed.fingerprint)
        self.assertEqual(restored, governed)
        self.assertEqual(restored.fingerprint, governed.fingerprint)

    def test_plan_rejects_tampered_systems_decision(self) -> None:
        governed = bind_systems_governance(
            _systems_plan(RiskLevel.LOCAL_GENERATION),
            _systems_assessment(),
        )
        payload = governed.to_dict()
        payload["systems_decision"]["complexity_score"] = 1

        with self.assertRaisesRegex(ValidationError, "complexity"):
            ChangePlan.from_dict(payload)

    def test_plan_rejects_boolean_complexity_weight(self) -> None:
        assessment = _systems_assessment(
            low_risk=False,
            stocks=("work",),
            flows=("work arrives",),
            feedback_loops=("verification feeds the next run",),
            delays=("provider latency",),
            unintended_consequences=("fixture drift",),
            alternatives_considered=("reuse the current component",),
            added_complexity=(
                ComplexityItem(ComplexityKind.DEPENDENCY, "one dependency"),
            ),
            existing_mechanisms_insufficient_because="the fixture needs this dependency",
            reversibility_strategy="remove the dependency",
        )
        governed = bind_systems_governance(
            _systems_plan(RiskLevel.REVERSIBLE_WRITE),
            assessment,
        )
        payload = governed.to_dict()
        payload["systems_assessment"]["added_complexity"][0]["weight"] = True

        with self.assertRaisesRegex(ValidationError, "weight"):
            ChangePlan.from_dict(payload)


def _systems_plan(risk: RiskLevel) -> ChangePlan:
    action = AgentAction(
        capability="example.summary.generate",
        target=ResourceRef("example", "summary", "systems-gate"),
        parameters={},
        risk=risk,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"systems-gate:{risk}",
        justification="Exercise the systems-governance planning boundary.",
    )
    return ChangePlan(
        goal="prepare a local summary",
        actions=(action,),
        created_by="test",
    )


def _systems_assessment(
    *,
    low_risk: bool = True,
    reversible: bool = True,
    well_understood: bool = True,
    stocks: tuple[str, ...] = (),
    flows: tuple[str, ...] = (),
    feedback_loops: tuple[str, ...] = (),
    delays: tuple[str, ...] = (),
    unintended_consequences: tuple[str, ...] = (),
    alternatives_considered: tuple[str, ...] = (),
    added_complexity: tuple[ComplexityItem, ...] = (),
    existing_mechanisms_insufficient_because: str = "",
    reversibility_strategy: str = "",
) -> SystemsAssessment:
    return SystemsAssessment(
        desired_outcome="produce an accurate local summary",
        current_behavior="the summary is prepared manually",
        constraint="manual preparation time",
        leverage_point="information flow",
        simplest_intervention="generate one local draft",
        success_metric="draft is produced without an external side effect",
        failure_condition="draft is inaccurate or cannot be discarded",
        low_risk=low_risk,
        reversible=reversible,
        well_understood=well_understood,
        stocks=stocks,
        flows=flows,
        feedback_loops=feedback_loops,
        delays=delays,
        unintended_consequences=unintended_consequences,
        alternatives_considered=alternatives_considered,
        added_complexity=added_complexity,
        existing_mechanisms_insufficient_because=(
            existing_mechanisms_insufficient_because
        ),
        reversibility_strategy=reversibility_strategy,
    )


def _model_context_mapping() -> dict[str, object]:
    return {
        "destination": "approved-agent",
        "model_tenancy": "tenant-a",
        "source_data_environment": "nonproduction",
        "dlp_adapter": "none",
        "development_default_classification": "internal",
        "rules": [
            {
                "name": "internal",
                "providers": ["jira"],
                "capabilities": ["jira.*"],
                "data_classifications": ["internal"],
                "destinations": ["approved-agent"],
                "model_tenancies": ["tenant-a"],
                "routes": ["ephemeral"],
                "handling": "allow",
                "audit_required": False,
                "dlp_required": False,
                "redacted_fields": [],
                "allowed_fields": ["*"],
                "max_items": 100,
                "max_output_bytes": 4096,
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
