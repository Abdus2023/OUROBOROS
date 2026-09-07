"""Immutable, provenance-aware planning context (M2.2)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ContextFact:
    """A fact exposed to a planner with explicit provenance."""

    value: str
    source: str


@dataclass(frozen=True)
class PlanningContext:
    """Immutable snapshot from which one planning response may be produced."""

    repository_id: str
    generation: str
    mutation_epoch: int
    run_id: str
    facts: tuple[ContextFact, ...] = ()
    constraints: tuple[str, ...] = ()
    allowed_action_kinds: tuple[str, ...] = ()
    required_gates: tuple[str, ...] = ()

    @classmethod
    def build(
        cls,
        *,
        repository_id: str,
        generation: str,
        mutation_epoch: int,
        run_id: str,
        facts: Iterable[ContextFact] = (),
        constraints: Iterable[str] = (),
        allowed_action_kinds: Iterable[str] = (),
        required_gates: Iterable[str] = (),
    ) -> "PlanningContext":
        return cls(
            repository_id=repository_id,
            generation=generation,
            mutation_epoch=mutation_epoch,
            run_id=run_id,
            facts=tuple(facts),
            constraints=tuple(constraints),
            allowed_action_kinds=tuple(allowed_action_kinds),
            required_gates=tuple(required_gates),
        )
