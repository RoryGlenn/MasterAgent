"""Planner protocol for model-independent plan generation."""

from __future__ import annotations

from typing import Protocol

from master_agent.models import ChangePlan


class Planner(Protocol):
    """Convert a user goal into a typed, non-authoritative plan."""

    def plan(self, goal: str) -> ChangePlan:
        """Return a validated plan for a goal."""
