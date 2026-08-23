"""Registered governed workflows."""

from master_agent.workflows.weekly_operating_review import (
    WeeklyOperatingReviewArtifacts,
    WeeklyOperatingReviewSettings,
    build_weekly_operating_review_plan,
    render_weekly_operating_review,
)
from master_agent.workflows.weekly_status import (
    WeeklyStatusArtifacts,
    WeeklyStatusSettings,
    build_weekly_status_read_plan,
    render_weekly_status_package,
)

__all__ = [
    "WeeklyOperatingReviewArtifacts",
    "WeeklyOperatingReviewSettings",
    "WeeklyStatusArtifacts",
    "WeeklyStatusSettings",
    "build_weekly_operating_review_plan",
    "build_weekly_status_read_plan",
    "render_weekly_operating_review",
    "render_weekly_status_package",
]
