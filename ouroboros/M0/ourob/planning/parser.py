"""Strict parser for untrusted planner responses."""
from __future__ import annotations

from typing import Any

from .model import PlanningResponse, ProposedAction


SCHEMA = "ourob.planning.v1"


def parse_response(raw: Any) -> PlanningResponse:
    if not isinstance(raw, dict):
        raise ValueError("planning response must be an object")
    if raw.get("schema", SCHEMA) != SCHEMA:
        raise ValueError(f"unsupported planning schema: {raw.get('schema')!r}")

    def req(name: str) -> str:
        value = raw.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty string")
        return value

    epoch = raw.get("mutation_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ValueError("mutation_epoch must be a non-negative integer")
    actions_raw = raw.get("actions", [])
    if not isinstance(actions_raw, list):
        raise ValueError("actions must be a list")
    actions: list[ProposedAction] = []
    for item in actions_raw:
        if not isinstance(item, dict):
            raise ValueError("each action must be an object")
        action_id, kind, skill = item.get("action_id"), item.get("kind"), item.get("skill")
        if not all(isinstance(x, str) and x for x in (action_id, kind, skill)):
            raise ValueError("action_id, kind, and skill are required strings")
        arguments = item.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ValueError("action arguments must be an object")
        target = item.get("target")
        if target is not None and not isinstance(target, str):
            raise ValueError("action target must be a string or null")
        expected = item.get("expected_effect", "")
        if not isinstance(expected, str):
            raise ValueError("expected_effect must be a string")
        actions.append(ProposedAction(action_id, kind, skill, target, dict(arguments), expected))

    def strings(name: str) -> tuple[str, ...]:
        value = raw.get(name, [])
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ValueError(f"{name} must be a list of strings")
        return tuple(value)

    return PlanningResponse(
        req("request_id"), req("run_id"), req("repository_id"), req("generation"), epoch,
        req("objective"), strings("assumptions"), tuple(actions), strings("verification_gates"),
        raw.get("rollback_strategy", "") if isinstance(raw.get("rollback_strategy", ""), str) else "",
    )
