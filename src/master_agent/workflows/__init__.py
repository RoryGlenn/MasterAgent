"""Registered governed workflows."""

from master_agent.workflows.weekly_status import (
    WeeklyStatusArtifacts,
    WeeklyStatusSettings,
    build_weekly_status_read_plan,
    render_weekly_status_package,
)

__all__ = [
    "WeeklyStatusArtifacts",
    "WeeklyStatusSettings",
    "build_weekly_status_read_plan",
    "render_weekly_status_package",
]
