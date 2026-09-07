"""Compatibility adapter for the pre-M2 planner API.

The adapter deliberately downgrades legacy ``Action`` objects into proposal
objects. They must still pass the M2 validator before execution.
"""
from __future__ import annotations

from typing import Protocol

from ..model import Plan
from .model import PlanningRequest, PlanningResponse, ProposedAction


class LegacyPlanner(Protocol):
    def propose(self, task: str) -> Plan: ...


class LegacyPlannerAdapter:
    def __init__(self, planner: LegacyPlanner, repository_id: str):
        self.planner = planner
        self.repository_id = repository_id

    def plan(self, request: PlanningRequest) -> PlanningResponse:
        legacy = self.planner.propose(request.objective)
        if legacy.task != request.objective:
            raise ValueError("legacy planner returned a plan for another task")
        proposals = tuple(
            ProposedAction(
                action_id=action.id,
                kind=action.kind.value,
                skill=action.skill,
                target=action.arguments.get("path"),
                arguments=dict(action.arguments),
                expected_effect=action.rationale,
            )
            for action in legacy.actions
        )
        return PlanningResponse(
            request_id=request.request_id,
            run_id=request.run_id,
            repository_id=self.repository_id,
            generation=request.generation,
            mutation_epoch=request.mutation_epoch,
            objective=request.objective,
            actions=proposals,
        )
