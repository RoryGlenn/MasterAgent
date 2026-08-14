"""Fail-closed type validation for security-sensitive booleans."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.governance import GovernanceProfile
from master_agent.models import ChangePlan
from master_agent.oauth_config import OAuthProfiles
from master_agent.planners.static import build_weekly_status_plan
from master_agent.orchestrator import RunReport


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
                with self.subTest(filename=filename):
                    with self.assertRaises(ConfigurationError):
                        loader(path)


if __name__ == "__main__":
    unittest.main()
