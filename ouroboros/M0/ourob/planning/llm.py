"""Model-backed planner adapter (M2.2).

The adapter converts provider text into proposal data only. It does not have
access to policy, skills, filesystem, verification, or promotion authority.
"""
from __future__ import annotations

import json
from typing import Any

from .context import PlanningContext
from .model import PlanningRequest, PlanningResponse, ProposedAction
from .prompt import build_prompt
from .provider import PlannerProvider


class LLMPlanner:
    def __init__(self, provider: PlannerProvider, *, max_output_chars: int = 64_000):
        self.provider = provider
        self.max_output_chars = max_output_chars

    def plan(self, request: PlanningRequest, context: PlanningContext) -> PlanningResponse:
        if context.run_id != request.run_id:
            raise ValueError("planning context belongs to another run")
        if context.repository_id != request.repository_id:
            raise ValueError("planning context belongs to another repository")
        if context.generation != request.generation or context.mutation_epoch != request.mutation_epoch:
            raise ValueError("planning context is stale")

        raw = self.provider.generate(build_prompt(context, request.objective))
        if len(raw) > self.max_output_chars:
            raise ValueError("planner output exceeds configured limit")
        try:
            payload: Any = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("planner returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("planner response must be a JSON object")

        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            raise ValueError("planner actions must be a list")
        proposals = tuple(self._proposal(item) for item in actions)
        return PlanningResponse(
            request_id=request.request_id,
            run_id=request.run_id,
            repository_id=request.repository_id,
            generation=request.generation,
            mutation_epoch=request.mutation_epoch,
            objective=request.objective,
            actions=proposals,
        )

    @staticmethod
    def _proposal(item: Any) -> ProposedAction:
        if not isinstance(item, dict):
            raise ValueError("each planner action must be an object")
        required = ("action_id", "kind", "skill", "arguments", "expected_effect")
        if any(key not in item for key in required):
            raise ValueError("planner action is missing required fields")
        arguments = item["arguments"]
        if not isinstance(arguments, dict):
            raise ValueError("planner action arguments must be an object")
        return ProposedAction(
            action_id=str(item["action_id"]),
            kind=str(item["kind"]),
            skill=str(item["skill"]),
            target=None if item.get("target") is None else str(item["target"]),
            arguments=dict(arguments),
            expected_effect=str(item["expected_effect"]),
        )
