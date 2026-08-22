"""Fail-closed type validation for security-sensitive booleans."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.governance import GovernanceProfile
from master_agent.models import ChangePlan
from master_agent.oauth_config import OAuthProfiles
from master_agent.orchestrator import RunReport
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
