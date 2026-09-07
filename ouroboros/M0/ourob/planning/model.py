"""M2 planning objects: planner output is proposal data, never authority."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class PlanningRequest:
    request_id: str
    run_id: str
    repository_id: str
    generation: str
    mutation_epoch: int
    objective: str
    constraints: tuple[str, ...] = ()
    allowed_action_kinds: tuple[str, ...] = ()
    required_gates: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProposedAction:
    action_id: str
    kind: str
    skill: str
    target: str | None = None
    arguments: Mapping[str, Any] = field(default_factory=dict)
    expected_effect: str = ""


@dataclass(frozen=True)
class PlanningResponse:
    request_id: str
    run_id: str
    repository_id: str
    generation: str
    mutation_epoch: int
    objective: str
    assumptions: tuple[str, ...] = ()
    actions: tuple[ProposedAction, ...] = ()
    verification_gates: tuple[str, ...] = ()
    rollback_strategy: str = ""


@dataclass(frozen=True)
class PlanViolation:
    code: str
    message: str
    action_id: str | None = None


@dataclass(frozen=True)
class PlanValidation:
    accepted: bool
    violations: tuple[PlanViolation, ...] = ()
    normalized_actions: tuple[Any, ...] = ()
